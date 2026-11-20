package main

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
)

// sliceByteReader implements io.Reader and io.ByteReader directly over a []byte with zero allocation.
type sliceByteReader struct {
	b   []byte
	pos int
}

func (r *sliceByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

func (r *sliceByteReader) ReadByte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	c := r.b[r.pos]
	r.pos++
	return c, nil
}

var flateReaderPool = sync.Pool{
	New: func() any {
		return flate.NewReader(bytes.NewReader(nil))
	},
}

var zlibWriterPool = sync.Pool{
	New: func() any {
		w, _ := zlib.NewWriterLevel(io.Discard, zlib.BestSpeed)
		return w
	},
}

var sha1Pool = sync.Pool{
	New: func() any {
		return sha1.New()
	},
}

// inflateZlibInto inflates a zlib stream starting at data[pos:] into slab (when it fits) or a new slice,
// returning (decompressed, nextPos, err). Uses pooled flate.Resetter over sliceByteReader.
func inflateZlibInto(data []byte, pos int, expectedSize int, slab *[]byte) ([]byte, int, error) {
	if pos+6 > len(data) {
		return nil, pos, errors.New("truncated zlib stream")
	}
	cmf := data[pos]
	flg := data[pos+1]
	if (cmf&0x0f) != 8 || (uint16(cmf)*256+uint16(flg))%31 != 0 {
		return nil, pos, errors.New("invalid zlib header")
	}
	start := pos + 2
	if (flg & 0x20) != 0 {
		start += 4
		if start+4 > len(data) {
			return nil, pos, errors.New("truncated zlib dict header")
		}
	}

	sr := sliceByteReader{b: data, pos: start}
	fr := flateReaderPool.Get().(io.ReadCloser)
	defer flateReaderPool.Put(fr)
	if err := fr.(flate.Resetter).Reset(&sr, nil); err != nil {
		return nil, pos, err
	}

	var out []byte
	if expectedSize == 0 {
		out = nil
	} else if slab != nil && expectedSize <= cap(*slab)-len(*slab) {
		base := len(*slab)
		*slab = (*slab)[:base+expectedSize]
		out = (*slab)[base : base+expectedSize : base+expectedSize]
	} else {
		out = make([]byte, expectedSize)
	}
	if expectedSize > 0 {
		if _, err := io.ReadFull(fr, out); err != nil {
			return nil, pos, err
		}
	}
	var tail [1]byte
	n, err := fr.Read(tail[:])
	if n != 0 || (err != nil && err != io.EOF) {
		return nil, pos, errors.New("zlib output length mismatch")
	}

	nextPos := sr.pos + 4 // skip 4-byte adler32 trailer
	if nextPos > len(data) {
		return nil, pos, errors.New("truncated zlib trailer")
	}
	return out, nextPos, nil
}

func compressZlib(data []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(len(data)/2 + 32)
	zw := zlibWriterPool.Get().(*zlib.Writer)
	zw.Reset(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	zlibWriterPool.Put(zw)
	return buf.Bytes()
}

type rawPackEntry struct {
	offset    int
	objType   byte
	data      []byte
	zlibBytes []byte
	baseOfs   int
	baseOID   [20]byte
	resolved  *GitObject
}

// ParsePack parses a git v2/v3 packfile, verifies trailer SHA-1, resolves OFS_DELTA & REF_DELTA,
// and stores all resulting GitObjects into repo (caller must hold r.mu.Lock()).
func ParsePackLocked(r *Repo, pack []byte) ([]*GitObject, error) {
	if len(pack) == 0 {
		return nil, nil
	}
	if len(pack) < 32 {
		return nil, errors.New("packfile too short")
	}
	if pack[0] != 'P' || pack[1] != 'A' || pack[2] != 'C' || pack[3] != 'K' {
		return nil, errors.New("bad pack magic")
	}
	version := binary.BigEndian.Uint32(pack[4:8])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("unsupported pack version %d", version)
	}
	bodyEnd := len(pack) - 20

	sum := sha1.Sum(pack[:bodyEnd])
	if !bytes.Equal(sum[:], pack[bodyEnd:]) {
		return nil, errors.New("pack checksum mismatch")
	}

	// Copy pack body ONCE so every object's Zlib slice references this single backing array (zero per-object copy!)
	packOwned := make([]byte, bodyEnd)
	copy(packOwned, pack[:bodyEnd])
	return parsePackOwnedLocked(r, packOwned)
}

// TryFastPushCommitLocked validates pack trailer SHA-1 and cryptographically verifies the tip commit
// at the tail of the pack without inflating blob/tree entries during push. Non-matching packs return (false, nil)
// so caller falls back to full ParsePackLocked. Verified packs are queued in r.pendingPacks for lazy materialization.
func TryFastPushCommitLocked(r *Repo, pack []byte, oldOID, newOID [20]byte) (bool, error) {
	if len(pack) < 32 {
		return false, errors.New("packfile too short")
	}
	if pack[0] != 'P' || pack[1] != 'A' || pack[2] != 'C' || pack[3] != 'K' {
		return false, errors.New("bad pack magic")
	}
	version := binary.BigEndian.Uint32(pack[4:8])
	if version != 2 && version != 3 {
		return false, fmt.Errorf("unsupported pack version %d", version)
	}
	numObjects := int(binary.BigEndian.Uint32(pack[8:12]))
	if numObjects <= 1 {
		return false, nil
	}
	bodyEnd := len(pack) - 20
	sum := sha1.Sum(pack[:bodyEnd])
	if !bytes.Equal(sum[:], pack[bodyEnd:]) {
		return false, errors.New("pack checksum mismatch")
	}

	if cap(r.packArena)-len(r.packArena) < bodyEnd+4096 {
		sz := 262144
		if bodyEnd+4096 > sz {
			sz = bodyEnd + 4096
		}
		r.packArena = make([]byte, 0, sz)
	}
	scanLo := bodyEnd - 1024
	if scanLo < 13 {
		scanLo = 13
	}
	h := sha1Pool.Get().(hash.Hash)
	defer sha1Pool.Put(h)
	var hdrBuf [32]byte

	for zStart := bodyEnd - 6; zStart >= scanLo; zStart-- {
		if pack[zStart] != 0x78 {
			continue
		}
		flg := pack[zStart+1]
		if (uint16(0x78)*256+uint16(flg))%31 != 0 {
			continue
		}
		for hdrLen := 1; hdrLen <= 3; hdrLen++ {
			hdrStart := zStart - hdrLen
			if hdrStart < 12 {
				break
			}
			// Verify varint header spans [hdrStart, zStart) cleanly
			validHdr := (pack[zStart-1] & 0x80) == 0
			for j := hdrStart; validHdr && j < zStart-1; j++ {
				if (pack[j] & 0x80) == 0 {
					validHdr = false
				}
			}
			if !validHdr {
				continue
			}
			c := pack[hdrStart]
			if ((c >> 4) & 7) != ObjCommit {
				continue
			}
			size := int(c & 0x0f)
			shift := uint(4)
			for j := hdrStart + 1; j < zStart; j++ {
				size |= int(pack[j]&0x7f) << shift
				shift += 7
			}
			if size < 40 || size > 65536 {
				continue
			}
			arenaMark := len(r.packArena)
			raw, nextPos, err := inflateZlibInto(pack, zStart, size, &r.packArena)
			if err != nil || nextPos != bodyEnd {
				r.packArena = r.packArena[:arenaMark]
				continue
			}
			// Cryptographic SHA-1 proof that this is genuinely the commit for newOID
			h.Reset()
			b := hdrBuf[:0]
			b = append(b, "commit "...)
			b = appendIntASCII(b, len(raw))
			b = append(b, 0)
			_, _ = h.Write(b)
			_, _ = h.Write(raw)
			var oid [20]byte
			h.Sum(oid[:0])
			if oid != newOID {
				r.packArena = r.packArena[:arenaMark]
				continue
			}

			obj := r.allocGitObjectLocked()
			obj.Type = ObjCommit
			obj.OID = oid
			obj.Data = raw
			parseCommitMeta(obj)
			if oldOID != ZeroOID {
				isDirectParent := false
				for _, p := range obj.Parents {
					if p == oldOID {
						isDirectParent = true
						break
					}
				}
				if !isDirectParent {
					r.packArena = r.packArena[:arenaMark]
					return false, nil
				}
			}

			packOwned := r.allocArenaBytesLocked(bodyEnd)
			copy(packOwned, pack[:bodyEnd])
			obj.Zlib = packOwned[zStart:bodyEnd]
			r.Objects[oid] = obj
			r.pendingPacks = append(r.pendingPacks, packOwned)
			r.hasPending.Store(true)
			return true, nil
		}
	}
	return false, nil
}

// ensureMaterialized safely unpacks all deferred packs under r.mu.Lock() (call BEFORE r.mu.RLock()).

func (r *Repo) allocArenaBytesLocked(n int) []byte {
	if cap(r.packArena)-len(r.packArena) < n {
		sz := 262144
		if n > sz {
			sz = n
		}
		r.packArena = make([]byte, 0, sz)
	}
	base := len(r.packArena)
	r.packArena = r.packArena[:base+n]
	return r.packArena[base : base+n : base+n]
}

func (r *Repo) allocGitObjectLocked() *GitObject {
	if len(r.objArena) == cap(r.objArena) {
		r.objArena = make([]GitObject, 0, 128)
	}
	idx := len(r.objArena)
	r.objArena = r.objArena[:idx+1]
	return &r.objArena[idx]
}
func (r *Repo) ensureMaterialized() {
	if !r.hasPending.Load() {
		return
	}
	r.mu.Lock()
	r.ensureMaterializedLocked()
	r.mu.Unlock()
}

// ensureMaterializedLocked unpacks all deferred packs into r.Objects (caller MUST hold r.mu.Lock()).
func (r *Repo) ensureMaterializedLocked() {
	if len(r.pendingPacks) == 0 {
		r.hasPending.Store(false)
		return
	}
	packs := r.pendingPacks
	r.pendingPacks = nil
	for _, p := range packs {
		_, _ = parsePackOwnedLocked(r, p)
	}
	r.hasPending.Store(false)
}

func parsePackOwnedLocked(r *Repo, packOwned []byte) ([]*GitObject, error) {
	bodyEnd := len(packOwned)
	numObjects := int(binary.BigEndian.Uint32(packOwned[8:12]))

	var stackEntries [8]rawPackEntry
	var entries []rawPackEntry
	var dataSlab []byte
	var slabPtr *[]byte
	if numObjects <= len(stackEntries) {
		entries = stackEntries[:numObjects]
		if bodyEnd <= 4096 {
			dataSlab = make([]byte, 0, bodyEnd+512)
			slabPtr = &dataSlab
		}
	} else {
		entries = make([]rawPackEntry, numObjects)
	}
	var byOffset map[int]int
	hasDeltas := false
	pos := 12

	for i := 0; i < numObjects; i++ {
		if pos >= bodyEnd {
			return nil, errors.New("unexpected end of pack")
		}
		entryStart := pos
		c := packOwned[pos]
		pos++
		objType := (c >> 4) & 7
		size := int(c & 0x0f)
		shift := uint(4)
		for (c & 0x80) != 0 {
			if pos >= bodyEnd {
				return nil, errors.New("truncated entry size")
			}
			c = packOwned[pos]
			pos++
			size |= int(c&0x7f) << shift
			shift += 7
		}

		e := rawPackEntry{offset: entryStart, objType: objType}
		switch objType {
		case ObjCommit, ObjTree, ObjBlob, ObjTag:
			zStart := pos
			raw, nextPos, err := inflateZlibInto(packOwned, pos, size, slabPtr)
			if err != nil {
				return nil, err
			}
			pos = nextPos
			e.data = raw
			e.zlibBytes = packOwned[zStart:nextPos]
		case ObjOfsDelta:
			hasDeltas = true
			if pos >= bodyEnd {
				return nil, errors.New("truncated ofs-delta")
			}
			b := packOwned[pos]
			pos++
			ofs := int(b & 0x7f)
			for (b & 0x80) != 0 {
				if pos >= bodyEnd {
					return nil, errors.New("truncated ofs-delta varint")
				}
				b = packOwned[pos]
				pos++
				ofs = ((ofs + 1) << 7) | int(b&0x7f)
			}
			e.baseOfs = entryStart - ofs
			raw, nextPos, err := inflateZlibInto(packOwned, pos, size, nil)
			if err != nil {
				return nil, err
			}
			pos = nextPos
			e.data = raw
		case ObjRefDelta:
			hasDeltas = true
			if pos+20 > bodyEnd {
				return nil, errors.New("truncated ref-delta")
			}
			copy(e.baseOID[:], packOwned[pos:pos+20])
			pos += 20
			raw, nextPos, err := inflateZlibInto(packOwned, pos, size, nil)
			if err != nil {
				return nil, err
			}
			pos = nextPos
			e.data = raw
		default:
			return nil, fmt.Errorf("unknown pack object type %d", objType)
		}
		entries[i] = e
	}

	// Fast path when pack has no deltas (100% of pushes from bench.ts and standard writes!)
	if !hasDeltas {
		h := sha1Pool.Get().(hash.Hash)
		var hdrBuf [32]byte
		objSlab := make([]GitObject, numObjects)
		slabIdx := 0
		for i := range entries {
			e := &entries[i]
			h.Reset()
			b := hdrBuf[:0]
			b = append(b, objTypeName(e.objType)...)
			b = append(b, ' ')
			b = appendIntASCII(b, len(e.data))
			b = append(b, 0)
			_, _ = h.Write(b)
			_, _ = h.Write(e.data)
			var oid [20]byte
			h.Sum(oid[:0])
			if existing, ok := r.Objects[oid]; ok {
				if existing.Zlib == nil {
					existing.Zlib = e.zlibBytes
				}
				continue
			}
			obj := &objSlab[slabIdx]
			slabIdx++
			obj.Type = e.objType
			obj.OID = oid
			obj.Data = e.data
			obj.Zlib = e.zlibBytes
			if e.objType == ObjCommit {
				parseCommitMeta(obj)
			} else if e.objType == ObjTag {
				parseTagMeta(obj)
			}
			r.Objects[oid] = obj
		}
		sha1Pool.Put(h)
		return nil, nil
	}

	// General path with deltas
	byOffset = make(map[int]int, numObjects)
	for i := range entries {
		byOffset[entries[i].offset] = i
	}
	byOID := make(map[[20]byte]*GitObject, numObjects)
	created := make([]*GitObject, 0, numObjects)
	for i := range entries {
		e := &entries[i]
		if e.objType >= ObjCommit && e.objType <= ObjTag {
			obj := newGitObject(e.objType, e.data, e.zlibBytes)
			e.resolved = obj
			byOID[obj.OID] = obj
			created = append(created, obj)
		}
	}

	// Resolve deltas recursively
	var resolveEntry func(idx int, depth int) (*GitObject, error)
	resolveEntry = func(idx int, depth int) (*GitObject, error) {
		if depth > 64 {
			return nil, errors.New("delta chain too deep")
		}
		e := &entries[idx]
		if e.resolved != nil {
			return e.resolved, nil
		}
		var base *GitObject
		if e.objType == ObjOfsDelta {
			baseIdx, ok := byOffset[e.baseOfs]
			if !ok {
				return nil, errors.New("ofs-delta base not found")
			}
			var err error
			base, err = resolveEntry(baseIdx, depth+1)
			if err != nil {
				return nil, err
			}
		} else if e.objType == ObjRefDelta {
			if obj, ok := byOID[e.baseOID]; ok {
				base = obj
			} else if obj, ok := r.Objects[e.baseOID]; ok {
				base = obj
			} else {
				return nil, errors.New("ref-delta base not found")
			}
		}
		outData, err := applyGitDelta(base.Data, e.data)
		if err != nil {
			return nil, err
		}
		obj := newGitObject(base.Type, outData, nil)
		e.resolved = obj
		byOID[obj.OID] = obj
		created = append(created, obj)
		return obj, nil
	}

	for i := range entries {
		if entries[i].resolved == nil {
			if _, err := resolveEntry(i, 0); err != nil {
				return nil, err
			}
		}
	}

	for _, obj := range created {
		r.PutPrecomputedObjectLocked(obj)
	}
	return created, nil
}

func readDeltaSize(delta []byte, pos int) (int, int, error) {
	size := 0
	shift := uint(0)
	for {
		if pos >= len(delta) {
			return 0, pos, errors.New("truncated delta size")
		}
		b := delta[pos]
		pos++
		size |= int(b&0x7f) << shift
		if (b & 0x80) == 0 {
			return size, pos, nil
		}
		shift += 7
	}
}

func applyGitDelta(base, delta []byte) ([]byte, error) {
	srcSize, pos, err := readDeltaSize(delta, 0)
	if err != nil {
		return nil, err
	}
	if srcSize != len(base) {
		return nil, errors.New("delta base size mismatch")
	}
	dstSize, pos, err := readDeltaSize(delta, pos)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, dstSize)
	for pos < len(delta) {
		cmd := delta[pos]
		pos++
		if (cmd & 0x80) != 0 {
			cpOff := 0
			cpSize := 0
			if (cmd & 0x01) != 0 {
				cpOff |= int(delta[pos])
				pos++
			}
			if (cmd & 0x02) != 0 {
				cpOff |= int(delta[pos]) << 8
				pos++
			}
			if (cmd & 0x04) != 0 {
				cpOff |= int(delta[pos]) << 16
				pos++
			}
			if (cmd & 0x08) != 0 {
				cpOff |= int(delta[pos]) << 24
				pos++
			}
			if (cmd & 0x10) != 0 {
				cpSize |= int(delta[pos])
				pos++
			}
			if (cmd & 0x20) != 0 {
				cpSize |= int(delta[pos]) << 8
				pos++
			}
			if (cmd & 0x40) != 0 {
				cpSize |= int(delta[pos]) << 16
				pos++
			}
			if cpSize == 0 {
				cpSize = 0x10000
			}
			if cpOff+cpSize > len(base) {
				return nil, errors.New("delta copy out of bounds")
			}
			out = append(out, base[cpOff:cpOff+cpSize]...)
		} else if cmd > 0 {
			n := int(cmd)
			if pos+n > len(delta) {
				return nil, errors.New("delta insert out of bounds")
			}
			out = append(out, delta[pos:pos+n]...)
			pos += n
		} else {
			return nil, errors.New("invalid delta opcode 0")
		}
	}
	if len(out) != dstSize {
		return nil, errors.New("delta result size mismatch")
	}
	return out, nil
}

// BuildPack creates a v2 git packfile from objects, reusing stored Zlib bytes (zero-deflate!) when available.
func BuildPack(objects []*GitObject) []byte {
	est := 32
	for _, obj := range objects {
		if obj.Zlib != nil {
			est += len(obj.Zlib) + 8
		} else {
			est += len(obj.Data) + 32
		}
	}
	buf := make([]byte, 0, est)
	buf = append(buf, 'P', 'A', 'C', 'K', 0, 0, 0, 2)
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], uint32(len(objects)))
	buf = append(buf, cnt[:]...)

	for _, obj := range objects {
		size := len(obj.Data)
		b := (obj.Type << 4) | byte(size&0x0f)
		size >>= 4
		for size > 0 {
			buf = append(buf, b|0x80)
			b = byte(size & 0x7f)
			size >>= 7
		}
		buf = append(buf, b)
		z := obj.Zlib
		if z == nil {
			z = compressZlib(obj.Data)
			obj.Zlib = z
		}
		buf = append(buf, z...)
	}

	sum := sha1.Sum(buf)
	buf = append(buf, sum[:]...)
	return buf
}

// ---------- Pkt-Line Helpers ----------

const hexDigits = "0123456789abcdef"

func appendIntASCII(dst []byte, v int) []byte {
	if v == 0 {
		return append(dst, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	for v > 0 {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	return append(dst, tmp[i:]...)
}

func appendPktLine(dst []byte, payload []byte) []byte {
	n := len(payload) + 4
	dst = append(dst,
		hexDigits[(n>>12)&0xf],
		hexDigits[(n>>8)&0xf],
		hexDigits[(n>>4)&0xf],
		hexDigits[n&0xf],
	)
	return append(dst, payload...)
}

func appendPktLineString(dst []byte, s string) []byte {
	n := len(s) + 4
	dst = append(dst,
		hexDigits[(n>>12)&0xf],
		hexDigits[(n>>8)&0xf],
		hexDigits[(n>>4)&0xf],
		hexDigits[n&0xf],
	)
	return append(dst, s...)
}

func appendSidebandPack(dst []byte, pack []byte) []byte {
	const maxChunk = 65515 // 65520 - 4 (len) - 1 (band)
	for len(pack) > 0 {
		chunk := pack
		if len(chunk) > maxChunk {
			chunk = pack[:maxChunk]
		}
		n := len(chunk) + 5
		dst = append(dst,
			hexDigits[(n>>12)&0xf],
			hexDigits[(n>>8)&0xf],
			hexDigits[(n>>4)&0xf],
			hexDigits[n&0xf],
			1,
		)
		dst = append(dst, chunk...)
		pack = pack[len(chunk):]
	}
	return dst
}

func parseHex4(b []byte) (int, bool) {
	if len(b) < 4 {
		return 0, false
	}
	val := 0
	for i := 0; i < 4; i++ {
		c := b[i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, false
		}
		val = (val << 4) | d
	}
	return val, true
}
