package main

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
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

// inflateZlibInto inflates a zlib stream starting at data[pos:] into out, returning (decompressed, nextPos, err).
// Uses pooled flate.Resetter directly over sliceByteReader for zero bufio allocation and exact stream boundary detection.
func inflateZlibInto(data []byte, pos int, expectedSize int) ([]byte, int, error) {
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

	out := make([]byte, expectedSize)
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
	numObjects := int(binary.BigEndian.Uint32(pack[8:12]))
	bodyEnd := len(pack) - 20

	sum := sha1.Sum(pack[:bodyEnd])
	if !bytes.Equal(sum[:], pack[bodyEnd:]) {
		return nil, errors.New("pack checksum mismatch")
	}

	// Copy pack body ONCE so every object's Zlib slice references this single backing array (zero per-object copy!)
	packOwned := make([]byte, bodyEnd)
	copy(packOwned, pack[:bodyEnd])

	entries := make([]rawPackEntry, numObjects)
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
			raw, nextPos, err := inflateZlibInto(packOwned, pos, size)
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
			raw, nextPos, err := inflateZlibInto(packOwned, pos, size)
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
			raw, nextPos, err := inflateZlibInto(packOwned, pos, size)
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
		h := sha1.New()
		var hdrBuf [32]byte
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
			obj := &GitObject{
				Type: e.objType,
				OID:  oid,
				Data: e.data,
				Zlib: e.zlibBytes,
			}
			if e.objType == ObjCommit {
				parseCommitMeta(obj)
			} else if e.objType == ObjTag {
				parseTagMeta(obj)
			}
			r.Objects[oid] = obj
		}
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
