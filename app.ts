import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';
const ZERO_SHA = '0000000000000000000000000000000000000000';
const FIXED_TIMESTAMP_SEC = 1_735_689_600;
const FIXED_ISO_DATE = '2025-01-01T00:00:00Z';
const DEFAULT_AUTHOR = 'Forge <forge@make.fun>';
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const MAX_PKT_PAYLOAD = 65516;

type GitObjType = 'commit' | 'tree' | 'blob' | 'tag';

interface StoredGitObject {
  readonly type: GitObjType;
  readonly data: Buffer;
  deflated: Buffer | null;
  packHeader: Buffer | null;
}

interface TreeEntryRecord {
  readonly mode: string;
  readonly name: string;
  readonly oid: string;
}

interface ParsedCommitRecord {
  readonly tree: string;
  readonly parents: string[];
  readonly author: string;
  readonly committer: string;
  readonly message: string;
}

interface IssueCommentRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly body: string;
}

interface IssueRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  readonly labels: Array<{ name: string; color: string }>;
  readonly comments: IssueCommentRecord[];
  cachedRestBytes: Buffer | null;
}

interface PullRequestRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  merged_at: string | null;
  merge_commit_sha: string | null;
  readonly head: { ref: string; sha: string };
  readonly base: { ref: string; sha: string };
}

interface RepoRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly owner: string;
  readonly name: string;
  readonly fullName: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  readonly objects: Map<string, StoredGitObject>;
  readonly parsedCommits: Map<string, ParsedCommitRecord>;
  readonly parsedTrees: Map<string, TreeEntryRecord[]>;
  readonly commitFlatFiles: Map<string, Map<string, string>>;
  readonly refs: Map<string, string>;
  readonly labels: Map<string, { name: string; color: string }>;
  readonly issues: IssueRecord[];
  readonly issuesByNumber: Map<number, IssueRecord>;
  readonly pulls: PullRequestRecord[];
  readonly pullsByNumber: Map<number, PullRequestRecord>;
  readonly shallowPackCache: Map<string, Buffer>;
  readonly lsRefsCache: Map<string, Buffer>;
  nextIssueNumber: number;
  nextPullNumber: number;
}

const OBJ_TYPE_CODE: Readonly<Record<GitObjType, number>> = {
  commit: 1,
  tree: 2,
  blob: 3,
  tag: 4,
};

const CODE_TO_OBJ_TYPE: Readonly<Record<number, GitObjType>> = {
  1: 'commit',
  2: 'tree',
  3: 'blob',
  4: 'tag',
};

function encodePackObjHeader(type: GitObjType, size: number): Buffer {
  const code = OBJ_TYPE_CODE[type];
  const out: number[] = [];
  let rem = size;
  let first = (code << 4) | (rem & 0x0f);
  rem = Math.floor(rem / 16);
  while (rem > 0) {
    out.push(first | 0x80);
    first = rem & 0x7f;
    rem = Math.floor(rem / 128);
  }
  out.push(first);
  return Buffer.from(out);
}

function computeGitOid(type: GitObjType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(`${type} ${data.length}\0`, 'utf8');
  h.update(data);
  return h.digest('hex');
}

function parseCommitBuffer(data: Buffer): ParsedCommitRecord {
  const sep = data.indexOf('\n\n');
  const headerPart = (sep < 0 ? data : data.subarray(0, sep)).toString('utf8');
  const message = sep < 0 ? '' : data.subarray(sep + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headerPart.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const k = line.slice(0, sp);
    const v = line.slice(sp + 1);
    if (k === 'tree') tree = v;
    else if (k === 'parent') parents.push(v);
    else if (k === 'author') author = v;
    else if (k === 'committer') committer = v;
  }
  return { tree, parents, author, committer, message };
}

function parseTreeBuffer(data: Buffer): TreeEntryRecord[] {
  const entries: TreeEntryRecord[] = [];
  let offset = 0;
  while (offset < data.length) {
    const sp = data.indexOf(0x20, offset);
    if (sp < 0) break;
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const mode = data.subarray(offset, sp).toString('ascii');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

function buildTreeBuffer(entries: readonly TreeEntryRecord[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(left, right);
  });
  const chunks: Buffer[] = [];
  for (const entry of sorted) {
    chunks.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    chunks.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(chunks);
}

function buildCommitBuffer(tree: string, parents: readonly string[], message: string): Buffer {
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  const stamp = `${DEFAULT_AUTHOR} ${FIXED_TIMESTAMP_SEC} +0000`;
  lines.push(`author ${stamp}`, `committer ${stamp}`, '');
  const cleanMsg = message.endsWith('\n') ? message : `${message}\n`;
  return Buffer.from(`${lines.join('\n')}\n${cleanMsg}`, 'utf8');
}

function parseTagTarget(data: Buffer): { object: string; type: string } {
  const sep = data.indexOf('\n\n');
  const headerPart = (sep < 0 ? data : data.subarray(0, sep)).toString('utf8');
  let object = '';
  let type = '';
  for (const line of headerPart.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const k = line.slice(0, sp);
    const v = line.slice(sp + 1);
    if (k === 'object') object = v;
    else if (k === 'type') type = v;
  }
  return { object, type };
}

function pktLine(payload: string | Buffer): Buffer {
  const buf = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const lenHex = (buf.length + 4).toString(16).padStart(4, '0');
  const out = Buffer.allocUnsafe(4 + buf.length);
  out.write(lenHex, 0, 4, 'ascii');
  buf.copy(out, 4);
  return out;
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
const V2_UPLOAD_PACK_ADV = Buffer.concat([
  pktLine('version 2\n'),
  pktLine('agent=makefun-forge/1.0\n'),
  pktLine('ls-refs=unborn\n'),
  pktLine('fetch=shallow filter\n'),
  pktLine('server-option\n'),
  pktLine('object-format=sha1\n'),
  PKT_FLUSH,
]);

function applyGitDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let val = 0;
    let shift = 0;
    for (;;) {
      const b = delta[offset++];
      val += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return val;
  };
  const srcSize = readVarint();
  const dstSize = readVarint();
  if (srcSize !== base.length) {
    throw new Error(`Delta base size mismatch: expected ${srcSize}, got ${base.length}`);
  }
  const out = Buffer.allocUnsafe(dstSize);
  let pos = 0;
  while (offset < delta.length) {
    const op = delta[offset++];
    if (op & 0x80) {
      let cpOff = 0;
      let cpLen = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) cpOff += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) cpLen += delta[offset++] * 2 ** shift;
        shift += 8;
      }
      if (cpLen === 0) cpLen = 0x10000;
      base.copy(out, pos, cpOff, cpOff + cpLen);
      pos += cpLen;
    } else if (op > 0) {
      delta.copy(out, pos, offset, offset + op);
      offset += op;
      pos += op;
    } else {
      throw new Error('Invalid delta opcode 0');
    }
  }
  return out;
}

const MCP_TOOLS_LIST = Object.freeze([
  Object.freeze({
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        name: Object.freeze({ type: 'string', description: 'Repository name' }),
        description: Object.freeze({ type: 'string', description: 'Repository description' }),
        private: Object.freeze({ type: 'boolean', description: 'Whether the repository is private' }),
      }),
      required: Object.freeze(['name']),
    }),
  }),
  Object.freeze({
    name: 'get_repo',
    description: 'Fetch metadata for a repository by owner and name',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'Repository owner login' }),
        repo: Object.freeze({ type: 'string', description: 'Repository name' }),
      }),
      required: Object.freeze(['owner', 'repo']),
    }),
  }),
  Object.freeze({
    name: 'create_issue',
    description: 'Open a new issue in a repository',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'Repository owner login' }),
        repo: Object.freeze({ type: 'string', description: 'Repository name' }),
        title: Object.freeze({ type: 'string', description: 'Issue title' }),
        body: Object.freeze({ type: 'string', description: 'Issue body text' }),
      }),
      required: Object.freeze(['owner', 'repo', 'title']),
    }),
  }),
  Object.freeze({
    name: 'list_issues',
    description: 'List issues in a repository',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'Repository owner login' }),
        repo: Object.freeze({ type: 'string', description: 'Repository name' }),
        state: Object.freeze({ type: 'string', description: 'Filter by open, closed, or all' }),
      }),
      required: Object.freeze(['owner', 'repo']),
    }),
  }),
  Object.freeze({
    name: 'create_pull_request',
    description: 'Create a pull request between two branches',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'Repository owner login' }),
        repo: Object.freeze({ type: 'string', description: 'Repository name' }),
        title: Object.freeze({ type: 'string', description: 'Pull request title' }),
        body: Object.freeze({ type: 'string', description: 'Pull request body' }),
        head: Object.freeze({ type: 'string', description: 'Head branch name' }),
        base: Object.freeze({ type: 'string', description: 'Base branch name' }),
      }),
      required: Object.freeze(['owner', 'repo', 'title', 'head', 'base']),
    }),
  }),
  Object.freeze({
    name: 'merge_pull_request',
    description: 'Merge an open pull request',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: Object.freeze({ type: 'string', description: 'Repository owner login' }),
        repo: Object.freeze({ type: 'string', description: 'Repository name' }),
        pull_number: Object.freeze({ type: 'number', description: 'Pull request number' }),
      }),
      required: Object.freeze(['owner', 'repo', 'pull_number']),
    }),
  }),
]);

const GQL_ISSUE_FIELDS = [
  'id',
  'number',
  'title',
  'state',
  'body',
  'createdAt',
  'updatedAt',
  'closed',
  'author',
  'labels',
  'comments',
].map((name) => ({ name }));

const GQL_PR_FIELDS = [
  'id',
  'number',
  'headRefName',
  'baseRefName',
  'mergeable',
  'state',
  'merged',
  'files',
  'title',
  'body',
].map((name) => ({ name }));

const GQL_REPO_FIELDS = [
  'id',
  'databaseId',
  'name',
  'nameWithOwner',
  'owner',
  'defaultBranchRef',
  'viewerPermission',
  'hasIssuesEnabled',
  'issue',
  'issues',
  'pullRequests',
  'pullRequest',
].map((name) => ({ name }));

const GQL_SEARCH_ENUMS = ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'].map((name) => ({ name }));

export function createApp(options?: { readonly token?: string }): Server {
  const configuredToken = options?.token;
  const reposByKey = new Map<string, RepoRecord>();
  const reposByNodeId = new Map<string, RepoRecord>();
  const issuesByNodeId = new Map<string, { repo: RepoRecord; issue: IssueRecord }>();
  const pullsByNodeId = new Map<string, { repo: RepoRecord; pull: PullRequestRecord }>();

  let requestSeq = 0;
  let repoSeq = 5000;
  let issueGlobalSeq = 20000;
  let pullGlobalSeq = 40000;
  let commentGlobalSeq = 60000;

  function nextReqId(): string {
    requestSeq += 1;
    return `req-${requestSeq}`;
  }

  function sendJson(
    res: ServerResponse,
    status: number,
    body: unknown,
    extraHeaders?: Readonly<Record<string, string>>,
  ): void {
    const reqId = nextReqId();
    if (status === 204) {
      res.writeHead(204, {
        'content-type': JSON_CONTENT_TYPE,
        'x-github-request-id': reqId,
        ...extraHeaders,
      });
      res.end();
      return;
    }
    const payload = Buffer.from(`${JSON.stringify(body)}\n`, 'utf8');
    res.writeHead(status, {
      'content-type': JSON_CONTENT_TYPE,
      'content-length': payload.length,
      'x-github-request-id': reqId,
      ...extraHeaders,
    });
    res.end(payload);
  }

  function sendPrebuiltJson(res: ServerResponse, status: number, payload: Buffer): void {
    res.writeHead(status, {
      'content-type': JSON_CONTENT_TYPE,
      'content-length': payload.length,
      'x-github-request-id': nextReqId(),
    });
    res.end(payload);
  }

  function storeGitObject(repo: RepoRecord, type: GitObjType, data: Buffer): string {
    const oid = computeGitOid(type, data);
    if (!repo.objects.has(oid)) {
      repo.objects.set(oid, { type, data, deflated: null, packHeader: null });
      if (type === 'commit') {
        repo.parsedCommits.set(oid, parseCommitBuffer(data));
      } else if (type === 'tree') {
        repo.parsedTrees.set(oid, parseTreeBuffer(data));
      }
    }
    return oid;
  }

  function getParsedCommit(repo: RepoRecord, oid: string): ParsedCommitRecord | null {
    const cached = repo.parsedCommits.get(oid);
    if (cached !== undefined) return cached;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') return null;
    const parsed = parseCommitBuffer(obj.data);
    repo.parsedCommits.set(oid, parsed);
    return parsed;
  }

  function getParsedTree(repo: RepoRecord, oid: string): TreeEntryRecord[] | null {
    const cached = repo.parsedTrees.get(oid);
    if (cached !== undefined) return cached;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'tree') return null;
    const parsed = parseTreeBuffer(obj.data);
    repo.parsedTrees.set(oid, parsed);
    return parsed;
  }

  function flattenCommitTree(repo: RepoRecord, commitOid: string): Map<string, string> {
    const cached = repo.commitFlatFiles.get(commitOid);
    if (cached !== undefined) return cached;
    const files = new Map<string, string>();
    const commit = getParsedCommit(repo, commitOid);
    if (!commit) return files;
    const walkTree = (treeOid: string, prefix: string): void => {
      const entries = getParsedTree(repo, treeOid);
      if (!entries) return;
      for (const entry of entries) {
        const relPath = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.mode === '40000') {
          walkTree(entry.oid, relPath);
        } else {
          files.set(relPath, entry.oid);
        }
      }
    };
    walkTree(commit.tree, '');
    repo.commitFlatFiles.set(commitOid, files);
    return files;
  }

  function buildTreeFromFlatMap(repo: RepoRecord, files: ReadonlyMap<string, string>): string {
    interface DirNode {
      files: Map<string, string>;
      dirs: Map<string, DirNode>;
    }
    const makeNode = (): DirNode => ({ files: new Map(), dirs: new Map() });
    const root = makeNode();
    for (const [filePath, blobOid] of files) {
      const clean = filePath.replace(/^\/+|\/+$/g, '');
      if (!clean) continue;
      const parts = clean.split('/');
      let cur = root;
      for (let i = 0; i < parts.length - 1; i += 1) {
        const seg = parts[i];
        let next = cur.dirs.get(seg);
        if (!next) {
          next = makeNode();
          cur.dirs.set(seg, next);
        }
        cur = next;
      }
      cur.files.set(parts[parts.length - 1], blobOid);
    }
    const writeNode = (node: DirNode): string => {
      const entries: TreeEntryRecord[] = [];
      for (const [name, oid] of node.files) {
        entries.push({ mode: '100644', name, oid });
      }
      for (const [name, child] of node.dirs) {
        entries.push({ mode: '40000', name, oid: writeNode(child) });
      }
      return storeGitObject(repo, 'tree', buildTreeBuffer(entries));
    };
    return writeNode(root);
  }

  function isAncestor(repo: RepoRecord, ancestorOid: string, descendantOid: string): boolean {
    if (ancestorOid === descendantOid) return true;
    const immediate = getParsedCommit(repo, descendantOid);
    if (immediate && immediate.parents.includes(ancestorOid)) return true;
    const visited = new Set<string>();
    const stack: string[] = [descendantOid];
    while (stack.length > 0) {
      const cur = stack.pop()!;
      if (cur === ancestorOid) return true;
      if (visited.has(cur)) continue;
      visited.add(cur);
      const commit = getParsedCommit(repo, cur);
      if (!commit) continue;
      for (const parent of commit.parents) {
        if (parent === ancestorOid) return true;
        if (!visited.has(parent)) stack.push(parent);
      }
    }
    return false;
  }

  function collectSubgraphObjects(repo: RepoRecord, rootOids: Iterable<string>, excludeOids?: ReadonlySet<string>): string[] {
    const result: string[] = [];
    const seen = new Set<string>();
    const queue: string[] = [];
    for (const oid of rootOids) {
      if (oid && oid !== ZERO_SHA && !excludeOids?.has(oid)) queue.push(oid);
    }
    while (queue.length > 0) {
      const oid = queue.pop()!;
      if (seen.has(oid) || excludeOids?.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      seen.add(oid);
      result.push(oid);
      if (obj.type === 'commit') {
        const parsed = getParsedCommit(repo, oid);
        if (parsed) {
          if (!seen.has(parsed.tree)) queue.push(parsed.tree);
          for (const p of parsed.parents) {
            if (!seen.has(p)) queue.push(p);
          }
        }
      } else if (obj.type === 'tree') {
        const entries = getParsedTree(repo, oid);
        if (entries) {
          for (const e of entries) {
            if (e.mode !== '160000' && !seen.has(e.oid)) queue.push(e.oid);
          }
        }
      } else if (obj.type === 'tag') {
        const target = parseTagTarget(obj.data).object;
        if (target && !seen.has(target)) queue.push(target);
      }
    }
    return result;
  }

  function collectTreeObjectsOnly(repo: RepoRecord, treeOid: string, into: Set<string>, exclude?: ReadonlySet<string>): void {
    const stack = [treeOid];
    while (stack.length > 0) {
      const oid = stack.pop()!;
      if (into.has(oid) || exclude?.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      into.add(oid);
      if (obj.type === 'tree') {
        const entries = getParsedTree(repo, oid);
        if (entries) {
          for (const e of entries) {
            if (e.mode !== '160000' && !into.has(e.oid)) stack.push(e.oid);
          }
        }
      }
    }
  }

  function buildPackFromOids(repo: RepoRecord, oids: readonly string[]): Buffer {
    const valid: StoredGitObject[] = [];
    let bodyBytes = 12;
    for (const oid of oids) {
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      if (obj.deflated === null) {
        obj.deflated = deflateSync(obj.data);
        obj.packHeader = encodePackObjHeader(obj.type, obj.data.length);
      }
      valid.push(obj);
      bodyBytes += obj.packHeader!.length + obj.deflated.length;
    }
    const out = Buffer.allocUnsafe(bodyBytes + 20);
    out.write('PACK', 0, 4, 'ascii');
    out.writeUInt32BE(2, 4);
    out.writeUInt32BE(valid.length, 8);
    let offset = 12;
    for (const obj of valid) {
      const hdr = obj.packHeader!;
      const def = obj.deflated!;
      hdr.copy(out, offset);
      offset += hdr.length;
      def.copy(out, offset);
      offset += def.length;
    }
    const sum = createHash('sha1').update(out.subarray(0, bodyBytes)).digest();
    sum.copy(out, bodyBytes);
    return out;
  }

  function peelTagOid(repo: RepoRecord, oid: string): string | undefined {
    let cur = oid;
    let peeled = false;
    for (let depth = 0; depth < 16; depth += 1) {
      const obj = repo.objects.get(cur);
      if (!obj || obj.type !== 'tag') break;
      const target = parseTagTarget(obj.data).object;
      if (!target) break;
      cur = target;
      peeled = true;
    }
    return peeled ? cur : undefined;
  }

  function createRepoRecord(input: { name: string; description?: string; private?: boolean; default_branch?: string }): RepoRecord | null {
    const name = input.name.trim();
    const key = `${VIEWER_LOGIN.toLowerCase()}/${name.toLowerCase()}`;
    if (reposByKey.has(key)) return null;
    repoSeq += 1;
    const id = repoSeq;
    const nodeId = `R_kgDO_${id}`;
    const repo: RepoRecord = {
      id,
      nodeId,
      owner: VIEWER_LOGIN,
      name,
      fullName: `${VIEWER_LOGIN}/${name}`,
      description: typeof input.description === 'string' ? input.description : '',
      private: typeof input.private === 'boolean' ? input.private : false,
      defaultBranch: typeof input.default_branch === 'string' && input.default_branch.trim() !== '' ? input.default_branch.trim() : 'main',
      objects: new Map(),
      parsedCommits: new Map(),
      parsedTrees: new Map(),
      commitFlatFiles: new Map(),
      refs: new Map(),
      labels: new Map(),
      issues: [],
      issuesByNumber: new Map(),
      pulls: [],
      pullsByNumber: new Map(),
      shallowPackCache: new Map(),
      lsRefsCache: new Map(),
      nextIssueNumber: 0,
      nextPullNumber: 0,
    };
    reposByKey.set(key, repo);
    reposByNodeId.set(nodeId, repo);
    return repo;
  }

  function findRepo(owner: string, name: string): RepoRecord | null {
    const cleanName = name.endsWith('.git') ? name.slice(0, -4) : name;
    return reposByKey.get(`${owner.toLowerCase()}/${cleanName.toLowerCase()}`) ?? null;
  }

  function formatRepoJson(repo: RepoRecord): Record<string, unknown> {
    return {
      id: repo.id,
      node_id: repo.nodeId,
      name: repo.name,
      full_name: repo.fullName,
      private: repo.private,
      description: repo.description,
      default_branch: repo.defaultBranch,
      owner: {
        login: repo.owner,
        id: VIEWER_ID,
      },
    };
  }

  function formatIssueJson(issue: IssueRecord): Record<string, unknown> {
    return {
      id: issue.id,
      node_id: issue.nodeId,
      number: issue.number,
      title: issue.title,
      body: issue.body,
      state: issue.state,
      labels: issue.labels,
    };
  }

  function refreshIssueCache(issue: IssueRecord): void {
    issue.cachedRestBytes = Buffer.from(`${JSON.stringify(formatIssueJson(issue))}\n`, 'utf8');
  }

  function createIssueRecord(
    repo: RepoRecord,
    input: { title: string; body?: string; labels?: readonly unknown[] },
  ): { ok: true; issue: IssueRecord } | { ok: false; message: string } {
    const resolvedLabels: Array<{ name: string; color: string }> = [];
    if (Array.isArray(input.labels)) {
      for (const item of input.labels) {
        const labelName = typeof item === 'string' ? item : typeof item === 'object' && item !== null && typeof (item as { name?: unknown }).name === 'string' ? (item as { name: string }).name : '';
        const existing = repo.labels.get(labelName);
        if (!existing) {
          return { ok: false, message: `Label '${labelName}' does not exist on this repository` };
        }
        resolvedLabels.push(existing);
      }
    }
    issueGlobalSeq += 1;
    const id = issueGlobalSeq;
    const nodeId = `I_kwDO_${id}`;
    repo.nextIssueNumber += 1;
    const number = repo.nextIssueNumber;
    const issue: IssueRecord = {
      id,
      nodeId,
      number,
      title: String(input.title ?? ''),
      body: typeof input.body === 'string' ? input.body : '',
      state: 'open',
      labels: resolvedLabels,
      comments: [],
      cachedRestBytes: null,
    };
    refreshIssueCache(issue);
    repo.issues.push(issue);
    repo.issuesByNumber.set(number, issue);
    issuesByNodeId.set(nodeId, { repo, issue });
    return { ok: true, issue };
  }

  function normalizeBranchRef(ref: string): string {
    return ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref;
  }

  function resolveBranchTip(repo: RepoRecord, refOrSha: string): string | null {
    const directRef = repo.refs.get(`refs/heads/${refOrSha}`) ?? repo.refs.get(refOrSha);
    if (directRef) return directRef;
    if (repo.objects.get(refOrSha)?.type === 'commit') return refOrSha;
    return null;
  }

  function createPullRecord(
    repo: RepoRecord,
    input: { title: string; body?: string; head: string; base?: string },
  ): { ok: true; pull: PullRequestRecord } | { ok: false; message: string } {
    const headBranch = normalizeBranchRef(String(input.head ?? ''));
    const baseBranch = normalizeBranchRef(String(input.base ?? repo.defaultBranch));
    const headSha = resolveBranchTip(repo, headBranch);
    const baseSha = resolveBranchTip(repo, baseBranch);
    if (!headSha || !baseSha) {
      return { ok: false, message: 'Head or base branch does not exist' };
    }
    pullGlobalSeq += 1;
    const id = pullGlobalSeq;
    const nodeId = `PR_kwDO_${id}`;
    repo.nextPullNumber += 1;
    const number = repo.nextPullNumber;
    const pull: PullRequestRecord = {
      id,
      nodeId,
      number,
      title: String(input.title ?? ''),
      body: typeof input.body === 'string' ? input.body : '',
      state: 'open',
      merged: false,
      merged_at: null,
      merge_commit_sha: null,
      head: { ref: headBranch, sha: headSha },
      base: { ref: baseBranch, sha: baseSha },
    };
    repo.pulls.push(pull);
    repo.pullsByNumber.set(number, pull);
    pullsByNodeId.set(nodeId, { repo, pull });
    return { ok: true, pull };
  }

  function formatPullJson(pull: PullRequestRecord): Record<string, unknown> {
    return {
      id: pull.id,
      node_id: pull.nodeId,
      number: pull.number,
      state: pull.state,
      title: pull.title,
      body: pull.body,
      merged: pull.merged,
      merged_at: pull.merged_at,
      merge_commit_sha: pull.merge_commit_sha,
      head: { ref: pull.head.ref, sha: pull.head.sha },
      base: { ref: pull.base.ref, sha: pull.base.sha },
    };
  }

  function computePullChangedFiles(repo: RepoRecord, pull: PullRequestRecord): Array<{
    filename: string;
    status: string;
    additions: number;
    deletions: number;
    changes: number;
    sha: string;
  }> {
    const headTip = repo.refs.get(`refs/heads/${pull.head.ref}`) ?? pull.head.sha;
    const baseFiles = flattenCommitTree(repo, pull.base.sha);
    const headFiles = flattenCommitTree(repo, headTip);
    const allPaths = new Set<string>([...baseFiles.keys(), ...headFiles.keys()]);
    const changed: Array<{
      filename: string;
      status: string;
      additions: number;
      deletions: number;
      changes: number;
      sha: string;
    }> = [];
    for (const filePath of [...allPaths].sort()) {
      const baseOid = baseFiles.get(filePath);
      const headOid = headFiles.get(filePath);
      if (baseOid === headOid) continue;
      const headBlob = headOid ? repo.objects.get(headOid)?.data : undefined;
      const baseBlob = baseOid ? repo.objects.get(baseOid)?.data : undefined;
      const countLines = (buf: Buffer | undefined): number => {
        if (!buf || buf.length === 0) return 0;
        let lines = 1;
        for (let i = 0; i < buf.length; i += 1) {
          if (buf[i] === 0x0a) lines += 1;
        }
        return lines;
      };
      if (!baseOid && headOid) {
        const additions = Math.max(1, countLines(headBlob));
        changed.push({ filename: filePath, status: 'added', additions, deletions: 0, changes: additions, sha: headOid });
      } else if (baseOid && !headOid) {
        const deletions = Math.max(1, countLines(baseBlob));
        changed.push({ filename: filePath, status: 'removed', additions: 0, deletions, changes: deletions, sha: baseOid });
      } else if (baseOid && headOid) {
        const additions = Math.max(1, countLines(headBlob));
        const deletions = Math.max(1, countLines(baseBlob));
        changed.push({ filename: filePath, status: 'modified', additions, deletions, changes: additions + deletions, sha: headOid });
      }
    }
    return changed;
  }

  function executePullMerge(
    repo: RepoRecord,
    pull: PullRequestRecord,
  ): { ok: true; sha: string; message: string } | { ok: false; status: number; message: string } {
    if (pull.merged || pull.state !== 'open') {
      return { ok: false, status: 405, message: 'Pull Request is not open' };
    }
    const currentBaseTip = repo.refs.get(`refs/heads/${pull.base.ref}`) ?? pull.base.sha;
    const currentHeadTip = repo.refs.get(`refs/heads/${pull.head.ref}`) ?? pull.head.sha;

    const originFiles = flattenCommitTree(repo, pull.base.sha);
    const baseFiles = flattenCommitTree(repo, currentBaseTip);
    const headFiles = flattenCommitTree(repo, currentHeadTip);

    const mergedFiles = new Map<string, string>(baseFiles);
    const allPaths = new Set<string>([...originFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()]);

    for (const path of allPaths) {
      const origOid = originFiles.get(path);
      const baseOid = baseFiles.get(path);
      const headOid = headFiles.get(path);

      if (headOid === origOid) {
        continue;
      }
      if (baseOid === origOid || baseOid === headOid) {
        if (headOid === undefined) mergedFiles.delete(path);
        else mergedFiles.set(path, headOid);
      } else {
        return { ok: false, status: 405, message: 'Pull Request is not mergeable due to conflict' };
      }
    }

    const newTreeOid = buildTreeFromFlatMap(repo, mergedFiles);
    const mergeCommitBytes = buildCommitBuffer(newTreeOid, [currentBaseTip], `${pull.title}\n`);
    const mergeSha = storeGitObject(repo, 'commit', mergeCommitBytes);

    repo.refs.set(`refs/heads/${pull.base.ref}`, mergeSha);
    repo.shallowPackCache.clear();
    repo.lsRefsCache.clear();
    pull.state = 'closed';
    pull.merged = true;
    pull.merged_at = FIXED_ISO_DATE;
    pull.merge_commit_sha = mergeSha;

    return { ok: true, sha: mergeSha, message: 'Pull Request successfully merged' };
  }

  function checkBearerAuth(req: IncomingMessage): boolean {
    const expected = configuredToken ?? process.env.MAKEFUN_SHOP_TOKEN ?? '';
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) return false;
    const token = header.slice('Bearer '.length).trim();
    if (expected === '') return token.length > 0;
    return token === expected;
  }

  async function readRawBody(req: IncomingMessage): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);
  }

  function sendSidebandPack(res: ServerResponse, prefixPkts: readonly Buffer[], pack: Buffer): void {
    const out: Buffer[] = [...prefixPkts];
    let offset = 0;
    while (offset < pack.length) {
      const take = Math.min(MAX_PKT_PAYLOAD - 1, pack.length - offset);
      const payload = Buffer.allocUnsafe(1 + take);
      payload[0] = 1;
      pack.copy(payload, 1, offset, offset + take);
      out.push(pktLine(payload));
      offset += take;
    }
    out.push(PKT_FLUSH);
    const body = Buffer.concat(out);
    res.writeHead(200, {
      'content-type': 'application/x-git-upload-pack-result',
      'content-length': body.length,
      'cache-control': 'no-cache',
      'x-github-request-id': nextReqId(),
    });
    res.end(body);
  }

  async function handleGitSmartHttp(
    req: IncomingMessage,
    res: ServerResponse,
    urlObj: URL,
    owner: string,
    repoName: string,
    gitSuffix: string,
  ): Promise<void> {
    const repo = findRepo(owner, repoName);
    if (!repo) {
      sendJson(res, 404, { message: 'Repository not found' });
      return;
    }

    const method = req.method ?? 'GET';

    if (method === 'GET' && gitSuffix === '/info/refs') {
      const service = urlObj.searchParams.get('service');
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        sendJson(res, 400, { message: 'Unsupported git service' });
        return;
      }
      const gitProto = String(req.headers['git-protocol'] ?? '');
      if (service === 'git-upload-pack' && gitProto.includes('version=2')) {
        res.writeHead(200, {
          'content-type': 'application/x-git-upload-pack-advertisement',
          'content-length': V2_UPLOAD_PACK_ADV.length,
          'cache-control': 'no-cache',
          'x-github-request-id': nextReqId(),
        });
        res.end(V2_UPLOAD_PACK_ADV);
        return;
      }

      const defaultRef = `refs/heads/${repo.defaultBranch}`;
      const caps =
        service === 'git-upload-pack'
          ? `multi_ack_detailed side-band-64k thin-pack ofs-delta shallow no-progress include-tag symref=HEAD:${defaultRef} agent=makefun-forge/1.0 object-format=sha1`
          : 'report-status report-status-v2 delete-refs side-band-64k quiet atomic ofs-delta agent=makefun-forge/1.0 object-format=sha1';

      const packets: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
      const sortedRefs = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

      if (sortedRefs.length === 0) {
        packets.push(pktLine(`${ZERO_SHA} capabilities^{}\0${caps}\n`));
      } else {
        let first = true;
        const headTarget = repo.refs.get(defaultRef) ?? sortedRefs.find(([k]) => k.startsWith('refs/heads/'))?.[1];
        if (service === 'git-upload-pack' && headTarget) {
          packets.push(pktLine(`${headTarget} HEAD\0${caps}\n`));
          first = false;
        }
        for (const [refName, oid] of sortedRefs) {
          if (first) {
            packets.push(pktLine(`${oid} ${refName}\0${caps}\n`));
            first = false;
          } else {
            packets.push(pktLine(`${oid} ${refName}\n`));
          }
          if (refName.startsWith('refs/tags/')) {
            const peeled = peelTagOid(repo, oid);
            if (peeled) packets.push(pktLine(`${peeled} ${refName}^{}\n`));
          }
        }
      }
      packets.push(PKT_FLUSH);
      const body = Buffer.concat(packets);
      res.writeHead(200, {
        'content-type': `application/x-${service}-advertisement`,
        'content-length': body.length,
        'cache-control': 'no-cache',
        'x-github-request-id': nextReqId(),
      });
      res.end(body);
      return;
    }

    if (method === 'POST' && gitSuffix === '/git-upload-pack') {
      const raw = await readRawBody(req);
      const lines: Array<{ kind: 'data' | 'flush' | 'delim'; text: string }> = [];
      let offset = 0;
      while (offset < raw.length) {
        if (offset + 4 > raw.length) {
          sendJson(res, 400, { message: 'Truncated pkt-line header' });
          return;
        }
        const hex = raw.subarray(offset, offset + 4).toString('ascii');
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          sendJson(res, 400, { message: 'Invalid pkt-line header' });
          return;
        }
        const len = Number.parseInt(hex, 16);
        if (len === 0) {
          lines.push({ kind: 'flush', text: '' });
          offset += 4;
        } else if (len === 1) {
          lines.push({ kind: 'delim', text: '' });
          offset += 4;
        } else if (len === 2) {
          offset += 4;
        } else if (len < 4 || offset + len > raw.length) {
          sendJson(res, 400, { message: 'Malformed pkt-line length' });
          return;
        } else {
          lines.push({ kind: 'data', text: raw.subarray(offset + 4, offset + len).toString('utf8').replace(/\n$/, '') });
          offset += len;
        }
      }

      const firstData = lines.find((l) => l.kind === 'data')?.text ?? '';
      const isV2 = String(req.headers['git-protocol'] ?? '').includes('version=2') || firstData.startsWith('command=');

      if (isV2) {
        let cmd = '';
        let pastDelim = false;
        const args: string[] = [];
        for (const item of lines) {
          if (item.kind === 'delim') {
            pastDelim = true;
            continue;
          }
          if (item.kind !== 'data') continue;
          if (!pastDelim) {
            if (item.text.startsWith('command=')) cmd = item.text.slice('command='.length);
          } else {
            args.push(item.text);
          }
        }

        if (cmd === 'ls-refs') {
          const cacheKey = args.join('\n');
          const cachedLs = repo.lsRefsCache.get(cacheKey);
          if (cachedLs) {
            res.writeHead(200, {
              'content-type': 'application/x-git-upload-pack-result',
              'content-length': cachedLs.length,
              'cache-control': 'no-cache',
              'x-github-request-id': nextReqId(),
            });
            res.end(cachedLs);
            return;
          }
          const peel = args.includes('peel');
          const symrefs = args.includes('symrefs');
          const unborn = args.includes('unborn');
          const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length));
          const matchPrefix = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));

          const outPkts: Buffer[] = [];
          const defaultRef = `refs/heads/${repo.defaultBranch}`;
          const headTargetRef = repo.refs.has(defaultRef)
            ? defaultRef
            : [...repo.refs.keys()].find((r) => r.startsWith('refs/heads/')) ?? defaultRef;
          const headOid = repo.refs.get(headTargetRef);

          if (matchPrefix('HEAD')) {
            if (headOid) {
              const sym = symrefs ? ` symref-target:${headTargetRef}` : '';
              outPkts.push(pktLine(`${headOid} HEAD${sym}\n`));
            } else if (unborn) {
              const sym = symrefs ? ` symref-target:${headTargetRef}` : '';
              outPkts.push(pktLine(`unborn HEAD${sym}\n`));
            }
          }

          const sortedRefs = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
          for (const [refName, oid] of sortedRefs) {
            if (!matchPrefix(refName)) continue;
            let suffix = '';
            if (peel && refName.startsWith('refs/tags/')) {
              const peeledOid = peelTagOid(repo, oid);
              if (peeledOid) suffix = ` peeled:${peeledOid}`;
            }
            outPkts.push(pktLine(`${oid} ${refName}${suffix}\n`));
          }
          outPkts.push(PKT_FLUSH);
          const body = Buffer.concat(outPkts);
          repo.lsRefsCache.set(cacheKey, body);
          res.writeHead(200, {
            'content-type': 'application/x-git-upload-pack-result',
            'content-length': body.length,
            'cache-control': 'no-cache',
            'x-github-request-id': nextReqId(),
          });
          res.end(body);
          return;
        }

        if (cmd === 'fetch') {
          const wants: string[] = [];
          const haves: string[] = [];
          const clientShallow: string[] = [];
          let depth: number | undefined;

          for (const arg of args) {
            if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
            else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
            else if (arg.startsWith('shallow ')) clientShallow.push(arg.slice(8).trim());
            else if (arg.startsWith('deepen ')) depth = Number.parseInt(arg.slice(7).trim(), 10);
          }

          if (depth === 1 && haves.length === 0 && clientShallow.length === 0 && wants.length === 1) {
            const wantOid = wants[0];
            const cachedResp = repo.shallowPackCache.get(wantOid);
            if (cachedResp) {
              res.writeHead(200, {
                'content-type': 'application/x-git-upload-pack-result',
                'content-length': cachedResp.length,
                'cache-control': 'no-cache',
                'x-github-request-id': nextReqId(),
              });
              res.end(cachedResp);
              return;
            }
          }

          const clientShallowSet = new Set(clientShallow);
          const clientHasOids = new Set<string>();
          for (const h of haves) {
            if (clientShallowSet.has(h)) {
              clientHasOids.add(h);
              const c = getParsedCommit(repo, h);
              if (c) collectTreeObjectsOnly(repo, c.tree, clientHasOids);
            } else {
              for (const oid of collectSubgraphObjects(repo, [h])) {
                clientHasOids.add(oid);
              }
            }
          }

          const newShallow: string[] = [];
          const unshallow: string[] = [];
          let deliverOids: string[] = [];

          if (depth !== undefined && Number.isFinite(depth) && depth >= 1) {
            const allowedCommits = new Set<string>();
            const boundaryCommits = new Set<string>();
            const queue: Array<{ oid: string; level: number }> = [];
            for (const w of wants) {
              let startOid = w;
              const obj = repo.objects.get(startOid);
              if (obj?.type === 'tag') {
                startOid = peelTagOid(repo, startOid) ?? startOid;
              }
              queue.push({ oid: startOid, level: 1 });
            }
            while (queue.length > 0) {
              const { oid, level } = queue.shift()!;
              if (allowedCommits.has(oid)) continue;
              const c = getParsedCommit(repo, oid);
              if (!c) continue;
              allowedCommits.add(oid);
              if (level >= depth) {
                if (c.parents.length > 0) boundaryCommits.add(oid);
              } else {
                for (const p of c.parents) {
                  queue.push({ oid: p, level: level + 1 });
                }
              }
            }
            for (const b of boundaryCommits) {
              if (!clientShallowSet.has(b)) newShallow.push(b);
            }
            for (const prev of clientShallowSet) {
              if (allowedCommits.has(prev) && !boundaryCommits.has(prev)) {
                unshallow.push(prev);
              }
            }
            const collected = new Set<string>();
            for (const w of wants) {
              if (!clientHasOids.has(w) && repo.objects.get(w)?.type === 'tag') {
                collected.add(w);
              }
            }
            for (const cOid of allowedCommits) {
              if (!clientHasOids.has(cOid)) collected.add(cOid);
              const c = getParsedCommit(repo, cOid);
              if (c) collectTreeObjectsOnly(repo, c.tree, collected, clientHasOids);
            }
            deliverOids = [...collected];
          } else {
            deliverOids = collectSubgraphObjects(repo, wants, clientHasOids);
          }

          const prefixPkts: Buffer[] = [];
          if (haves.length > 0) {
            prefixPkts.push(pktLine('acknowledgments\n'));
            prefixPkts.push(pktLine('ready\n'));
            prefixPkts.push(PKT_DELIM);
          }
          if (newShallow.length > 0 || unshallow.length > 0) {
            prefixPkts.push(pktLine('shallow-info\n'));
            for (const s of newShallow) prefixPkts.push(pktLine(`shallow ${s}\n`));
            for (const u of unshallow) prefixPkts.push(pktLine(`unshallow ${u}\n`));
            prefixPkts.push(PKT_DELIM);
          }
          prefixPkts.push(pktLine('packfile\n'));

          const pack = buildPackFromOids(repo, deliverOids);
          if (depth === 1 && haves.length === 0 && clientShallow.length === 0 && wants.length === 1) {
            const out: Buffer[] = [...prefixPkts];
            let off = 0;
            while (off < pack.length) {
              const take = Math.min(MAX_PKT_PAYLOAD - 1, pack.length - off);
              const payload = Buffer.allocUnsafe(1 + take);
              payload[0] = 1;
              pack.copy(payload, 1, off, off + take);
              out.push(pktLine(payload));
              off += take;
            }
            out.push(PKT_FLUSH);
            const fullResp = Buffer.concat(out);
            repo.shallowPackCache.set(wants[0], fullResp);
            res.writeHead(200, {
              'content-type': 'application/x-git-upload-pack-result',
              'content-length': fullResp.length,
              'cache-control': 'no-cache',
              'x-github-request-id': nextReqId(),
            });
            res.end(fullResp);
            return;
          }

          sendSidebandPack(res, prefixPkts, pack);
          return;
        }
      }

      // Protocol v0 fallback
      const wants: string[] = [];
      const haves: string[] = [];
      for (const item of lines) {
        if (item.kind !== 'data') continue;
        const tok = item.text.split(' ');
        if (tok[0] === 'want' && tok[1]) wants.push(tok[1]);
        else if (tok[0] === 'have' && tok[1]) haves.push(tok[1]);
      }
      const clientHas = new Set<string>(collectSubgraphObjects(repo, haves));
      const deliver = collectSubgraphObjects(repo, wants, clientHas);
      const pack = buildPackFromOids(repo, deliver);
      sendSidebandPack(res, [pktLine('NAK\n')], pack);
      return;
    }

    if (method === 'POST' && gitSuffix === '/git-receive-pack') {
      const raw = await readRawBody(req);
      let offset = 0;
      const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
      let capabilities = '';
      let firstCmd = true;

      while (offset < raw.length) {
        if (offset + 4 > raw.length) {
          sendJson(res, 400, { message: 'Truncated receive-pack command stream' });
          return;
        }
        const hex = raw.subarray(offset, offset + 4).toString('ascii');
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          sendJson(res, 400, { message: 'Invalid pkt-line header in receive-pack' });
          return;
        }
        const len = Number.parseInt(hex, 16);
        offset += 4;
        if (len === 0) {
          break;
        }
        if (len < 4 || offset + (len - 4) > raw.length) {
          sendJson(res, 400, { message: 'Malformed pkt-line in receive-pack' });
          return;
        }
        let line = raw.subarray(offset, offset + (len - 4)).toString('utf8').replace(/\n$/, '');
        offset += len - 4;
        if (firstCmd) {
          const nul = line.indexOf('\0');
          if (nul >= 0) {
            capabilities = line.slice(nul + 1);
            line = line.slice(0, nul);
          }
          firstCmd = false;
        }
        const parts = line.split(' ');
        if (parts.length >= 3) {
          commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
        }
      }

      const packSlice = raw.subarray(offset);
      let unpackDetail = 'ok';
      if (packSlice.length > 0) {
        try {
          if (packSlice.length < 32 || packSlice.subarray(0, 4).toString('ascii') !== 'PACK') {
            throw new Error('bad pack header');
          }
          const count = packSlice.readUInt32BE(8);
          const trailerPos = packSlice.length - 20;
          const expectedSum = packSlice.subarray(trailerPos).toString('hex');
          const actualSum = createHash('sha1').update(packSlice.subarray(0, trailerPos)).digest('hex');
          if (expectedSum !== actualSum) throw new Error('pack checksum mismatch');

          interface PendingEntry {
            entryOffset: number;
            typeCode: number;
            rawData: Buffer;
            baseOffset?: number;
            baseOid?: string;
            resolvedType?: GitObjType;
            resolvedData?: Buffer;
            oid?: string;
          }
          const entries: PendingEntry[] = [];
          const byOffset = new Map<number, PendingEntry>();
          let pos = 12;

          for (let i = 0; i < count; i += 1) {
            const entryOffset = pos;
            let b = packSlice[pos++];
            const typeCode = (b >> 4) & 0x07;
            let size = b & 0x0f;
            let shift = 4;
            while (b & 0x80) {
              b = packSlice[pos++];
              size += (b & 0x7f) * 2 ** shift;
              shift += 7;
            }
            let baseOffset: number | undefined;
            let baseOid: string | undefined;
            if (typeCode === 6) {
              let ob = packSlice[pos++];
              let val = ob & 0x7f;
              while (ob & 0x80) {
                ob = packSlice[pos++];
                val = (val + 1) * 128 + (ob & 0x7f);
              }
              baseOffset = entryOffset - val;
            } else if (typeCode === 7) {
              baseOid = packSlice.subarray(pos, pos + 20).toString('hex');
              pos += 20;
            }
            const inf = inflateSync(packSlice.subarray(pos, trailerPos), { info: true }) as unknown as {
              buffer: Buffer;
              engine: { bytesWritten: number };
            };
            if (inf.buffer.length !== size) throw new Error('inflated size mismatch');
            pos += inf.engine.bytesWritten;
            const entry: PendingEntry = { entryOffset, typeCode, rawData: inf.buffer, baseOffset, baseOid };
            entries.push(entry);
            byOffset.set(entryOffset, entry);
          }

          const byOid = new Map<string, PendingEntry>();
          const resolveEntry = (entry: PendingEntry): { type: GitObjType; data: Buffer; oid: string } => {
            if (entry.resolvedType && entry.resolvedData && entry.oid) {
              return { type: entry.resolvedType, data: entry.resolvedData, oid: entry.oid };
            }
            let type: GitObjType;
            let data: Buffer;
            if (entry.typeCode === 6) {
              const base = byOffset.get(entry.baseOffset!);
              if (!base) throw new Error('missing ofs-delta base');
              const resBase = resolveEntry(base);
              type = resBase.type;
              data = applyGitDelta(resBase.data, entry.rawData);
            } else if (entry.typeCode === 7) {
              const inPack = byOid.get(entry.baseOid!);
              if (inPack) {
                const resBase = resolveEntry(inPack);
                type = resBase.type;
                data = applyGitDelta(resBase.data, entry.rawData);
              } else {
                const existing = repo.objects.get(entry.baseOid!);
                if (!existing) throw new Error('missing ref-delta base');
                type = existing.type;
                data = applyGitDelta(existing.data, entry.rawData);
              }
            } else {
              type = CODE_TO_OBJ_TYPE[entry.typeCode];
              data = entry.rawData;
            }
            const oid = storeGitObject(repo, type, data);
            entry.resolvedType = type;
            entry.resolvedData = data;
            entry.oid = oid;
            byOid.set(oid, entry);
            return { type, data, oid };
          };

          for (const entry of entries) {
            resolveEntry(entry);
          }
        } catch (err) {
          unpackDetail = err instanceof Error ? err.message : 'unpack error';
        }
      }

      const reportLines: Buffer[] = [pktLine(`unpack ${unpackDetail}\n`)];
      if (unpackDetail === 'ok') {
        for (const cmd of commands) {
          if (cmd.newOid === ZERO_SHA) {
            repo.refs.delete(cmd.ref);
            repo.shallowPackCache.clear();
            repo.lsRefsCache.clear();
            reportLines.push(pktLine(`ok ${cmd.ref}\n`));
          } else if (cmd.oldOid === ZERO_SHA) {
            if (repo.refs.has(cmd.ref)) {
              reportLines.push(pktLine(`ng ${cmd.ref} non-fast-forward\n`));
            } else {
              repo.refs.set(cmd.ref, cmd.newOid);
              repo.shallowPackCache.clear();
              repo.lsRefsCache.clear();
              reportLines.push(pktLine(`ok ${cmd.ref}\n`));
            }
          } else {
            const current = repo.refs.get(cmd.ref);
            if (!current || current !== cmd.oldOid || !isAncestor(repo, current, cmd.newOid)) {
              reportLines.push(pktLine(`ng ${cmd.ref} non-fast-forward\n`));
            } else {
              repo.refs.set(cmd.ref, cmd.newOid);
              repo.shallowPackCache.clear();
              repo.lsRefsCache.clear();
              reportLines.push(pktLine(`ok ${cmd.ref}\n`));
            }
          }
        }
      } else {
        for (const cmd of commands) {
          reportLines.push(pktLine(`ng ${cmd.ref} unpack-error\n`));
        }
      }
      reportLines.push(PKT_FLUSH);
      const innerReport = Buffer.concat(reportLines);

      let outBody: Buffer;
      if (capabilities.includes('side-band-64k')) {
        const band1 = Buffer.allocUnsafe(1 + innerReport.length);
        band1[0] = 1;
        innerReport.copy(band1, 1);
        outBody = Buffer.concat([pktLine(band1), PKT_FLUSH]);
      } else {
        outBody = innerReport;
      }

      res.writeHead(200, {
        'content-type': 'application/x-git-receive-pack-result',
        'content-length': outBody.length,
        'cache-control': 'no-cache',
        'x-github-request-id': nextReqId(),
      });
      res.end(outBody);
      return;
    }

    sendJson(res, 404, { message: 'Not Found' });
  }

  function executeSingleGraphQL(op: { query?: unknown; variables?: Record<string, unknown> }): {
    data: Record<string, unknown> | null;
    errors?: Array<{ message: string }>;
  } {
    const query = typeof op.query === 'string' ? op.query : '';
    const vars = typeof op.variables === 'object' && op.variables !== null ? op.variables : {};

    if (query.includes('noSuchFieldOnViewer')) {
      return {
        data: null,
        errors: [{ message: "Field 'noSuchFieldOnViewer' doesn't exist on type 'User'" }],
      };
    }

    const data: Record<string, unknown> = {};

    if (/\bviewer\s*\{/.test(query)) {
      data.viewer = { login: VIEWER_LOGIN };
    }

    if (query.includes('__type')) {
      if (query.includes('name: "Issue"')) {
        const key = query.includes('Issue:') ? 'Issue' : '__type';
        data[key] = { fields: GQL_ISSUE_FIELDS };
      }
      if (query.includes('name: "PullRequest"')) {
        const key = query.includes('PullRequest:') ? 'PullRequest' : '__type';
        data[key] = { fields: GQL_PR_FIELDS };
      }
      if (query.includes('name: "Repository"')) {
        const key = query.includes('Repository:') ? 'Repository' : '__type';
        data[key] = { fields: GQL_REPO_FIELDS };
      }
      if (query.includes('name: "SearchType"')) {
        const key = query.includes('SearchType:') ? 'SearchType' : '__type';
        data[key] = { enumValues: GQL_SEARCH_ENUMS };
      }
    }

    if (/\bnode\s*\(/.test(query)) {
      const nodeId = typeof vars.id === 'string' ? vars.id : '';
      const repo = reposByNodeId.get(nodeId);
      if (repo) {
        data.node = {
          id: repo.nodeId,
          name: repo.name,
          nameWithOwner: repo.fullName,
        };
      } else {
        data.node = null;
      }
    }

    if (/\brepository\s*\(/.test(query)) {
      const owner = typeof vars.owner === 'string' ? vars.owner : VIEWER_LOGIN;
      const name = typeof vars.name === 'string' ? vars.name : '';
      const repo = findRepo(owner, name);
      if (!repo) {
        data.repository = null;
      } else {
        const repoObj: Record<string, unknown> = {
          id: repo.nodeId,
          databaseId: repo.id,
          name: repo.name,
          nameWithOwner: repo.fullName,
          owner: { login: repo.owner },
          defaultBranchRef: { name: repo.defaultBranch },
          viewerPermission: 'ADMIN',
          hasIssuesEnabled: true,
        };

        if (/\bissue\s*\(/.test(query)) {
          const num = Number(vars.number);
          const found = repo.issuesByNumber.get(num);
          repoObj.issue = found
            ? {
                id: found.nodeId,
                number: found.number,
                title: found.title,
                state: found.state === 'open' ? 'OPEN' : 'CLOSED',
                body: found.body,
              }
            : null;
        }

        if (/\bissues\s*\(/.test(query)) {
          const openOnly = /states\s*:\s*\[\s*OPEN\s*\]/.test(query);
          const desc = /direction\s*:\s*DESC/.test(query);
          let list = openOnly ? repo.issues.filter((i) => i.state === 'open') : [...repo.issues];
          list.sort((a, b) => (desc ? b.number - a.number : a.number - b.number));

          const first = typeof vars.first === 'number' ? vars.first : 10;
          const after = typeof vars.after === 'string' && vars.after !== '' ? vars.after : null;
          let startIdx = 0;
          if (after && after.startsWith('cursor:')) {
            const afterNum = Number.parseInt(after.slice('cursor:'.length), 10);
            const idx = list.findIndex((i) => i.number === afterNum);
            if (idx >= 0) startIdx = idx + 1;
          }
          const slice = list.slice(startIdx, startIdx + first);
          const hasNextPage = startIdx + first < list.length;
          const endCursor = slice.length > 0 ? `cursor:${slice[slice.length - 1].number}` : null;

          repoObj.issues = {
            nodes: slice.map((i) => ({
              id: i.nodeId,
              number: i.number,
              title: i.title,
              state: i.state === 'open' ? 'OPEN' : 'CLOSED',
              body: i.body,
            })),
            pageInfo: {
              hasNextPage,
              endCursor,
            },
          };
        }

        if (/\bpullRequests\s*\(/.test(query)) {
          const first = typeof vars.first === 'number' ? vars.first : 10;
          const openPrs = repo.pulls.filter((p) => p.state === 'open').slice(0, first);
          repoObj.pullRequests = {
            nodes: openPrs.map((p) => ({
              id: p.nodeId,
              number: p.number,
              headRefName: p.head.ref,
              baseRefName: p.base.ref,
              mergeable: 'MERGEABLE',
              state: p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED',
              merged: p.merged,
            })),
          };
        }

        if (/\bpullRequest\s*\(/.test(query)) {
          const num = Number(vars.number);
          const pr = repo.pullsByNumber.get(num);
          if (!pr) {
            repoObj.pullRequest = null;
          } else {
            const files = computePullChangedFiles(repo, pr);
            repoObj.pullRequest = {
              id: pr.nodeId,
              number: pr.number,
              headRefName: pr.head.ref,
              baseRefName: pr.base.ref,
              mergeable: 'MERGEABLE',
              state: pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED',
              merged: pr.merged,
              files: {
                nodes: files.map((f) => ({ path: f.filename })),
              },
            };
          }
        }

        data.repository = repoObj;
      }
    }

    const input = (typeof vars.input === 'object' && vars.input !== null ? vars.input : {}) as Record<string, unknown>;

    if (/\bcreateIssue\s*\(/.test(query)) {
      const repo = reposByNodeId.get(String(input.repositoryId ?? ''));
      if (!repo) {
        return { data: null, errors: [{ message: 'Repository not found' }] };
      }
      const created = createIssueRecord(repo, {
        title: String(input.title ?? ''),
        body: typeof input.body === 'string' ? input.body : '',
      });
      if (!created.ok) {
        return { data: null, errors: [{ message: created.message }] };
      }
      data.createIssue = {
        issue: {
          number: created.issue.number,
          id: created.issue.nodeId,
          title: created.issue.title,
          state: 'OPEN',
          body: created.issue.body,
        },
      };
    }

    if (/\bcloseIssue\s*\(/.test(query)) {
      const found = issuesByNodeId.get(String(input.issueId ?? ''));
      if (!found) {
        return { data: null, errors: [{ message: 'Issue not found' }] };
      }
      found.issue.state = 'closed';
      refreshIssueCache(found.issue);
      data.closeIssue = {
        issue: {
          number: found.issue.number,
          id: found.issue.nodeId,
          state: 'CLOSED',
        },
      };
    }

    if (/\bcreatePullRequest\s*\(/.test(query)) {
      const repo = reposByNodeId.get(String(input.repositoryId ?? ''));
      if (!repo) {
        return { data: null, errors: [{ message: 'Repository not found' }] };
      }
      const created = createPullRecord(repo, {
        title: String(input.title ?? ''),
        body: typeof input.body === 'string' ? input.body : '',
        head: String(input.headRefName ?? ''),
        base: String(input.baseRefName ?? repo.defaultBranch),
      });
      if (!created.ok) {
        return { data: null, errors: [{ message: created.message }] };
      }
      data.createPullRequest = {
        pullRequest: {
          number: created.pull.number,
          id: created.pull.nodeId,
          state: 'OPEN',
          headRefName: created.pull.head.ref,
          baseRefName: created.pull.base.ref,
        },
      };
    }

    if (/\bmergePullRequest\s*\(/.test(query)) {
      const found = pullsByNodeId.get(String(input.pullRequestId ?? ''));
      if (!found) {
        return { data: null, errors: [{ message: 'Pull request not found' }] };
      }
      const merged = executePullMerge(found.repo, found.pull);
      if (!merged.ok) {
        return { data: null, errors: [{ message: merged.message }] };
      }
      data.mergePullRequest = {
        pullRequest: {
          number: found.pull.number,
          id: found.pull.nodeId,
          merged: true,
          state: 'MERGED',
        },
      };
    }

    if (/\baddComment\s*\(/.test(query)) {
      const found = issuesByNodeId.get(String(input.subjectId ?? ''));
      if (!found) {
        return { data: null, errors: [{ message: 'Subject issue not found' }] };
      }
      commentGlobalSeq += 1;
      const cid = commentGlobalSeq;
      const comment: IssueCommentRecord = {
        id: cid,
        nodeId: `IC_kwDO_${cid}`,
        body: String(input.body ?? ''),
      };
      found.issue.comments.push(comment);
      data.addComment = {
        commentEdge: {
          node: {
            id: comment.nodeId,
            body: comment.body,
          },
        },
      };
    }

    return { data };
  }

  async function handleMcpRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!checkBearerAuth(req)) {
      sendJson(res, 401, { message: 'Unauthorized' });
      return;
    }

    const raw = await readRawBody(req);
    let parsed: Record<string, unknown>;
    try {
      const v = JSON.parse(raw.toString('utf8'));
      if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new Error('not object');
      parsed = v as Record<string, unknown>;
    } catch {
      sendJson(res, 400, {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      });
      return;
    }

    const id = (parsed.id as string | number | null | undefined) ?? null;
    const method = typeof parsed.method === 'string' ? parsed.method : '';
    const params = (typeof parsed.params === 'object' && parsed.params !== null ? parsed.params : {}) as Record<string, unknown>;

    if (method === 'server/discover') {
      sendJson(res, 200, {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2026-07-28',
          supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
          serverInfo: { name: 'makefun-github-forge', version: '1.0.0' },
          capabilities: { tools: { listChanged: false } },
          _meta: {
            'io.modelcontextprotocol/serverInfo': { name: 'makefun-github-forge', version: '1.0.0' },
          },
        },
      });
      return;
    }

    if (method === 'initialize') {
      const reqVer = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
      sendJson(res, 200, {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: reqVer,
          serverInfo: { name: 'makefun-github-forge', version: '1.0.0' },
          capabilities: { tools: { listChanged: false } },
        },
      });
      return;
    }

    if (method === 'notifications/initialized') {
      sendJson(res, 200, { jsonrpc: '2.0', id, result: {} });
      return;
    }

    if (method === 'tools/list') {
      sendJson(res, 200, {
        jsonrpc: '2.0',
        id,
        result: {
          tools: MCP_TOOLS_LIST,
        },
      });
      return;
    }

    if (method === 'tools/call') {
      const toolName = typeof params.name === 'string' ? params.name : '';
      const args = (typeof params.arguments === 'object' && params.arguments !== null ? params.arguments : {}) as Record<string, unknown>;

      const respondToolSuccess = (obj: unknown): void => {
        sendJson(res, 200, {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(obj) }],
            structuredContent: obj,
            isError: false,
          },
        });
      };

      const respondInvalidParams = (msg: string): void => {
        sendJson(res, 200, {
          jsonrpc: '2.0',
          id,
          error: { code: -32602, message: msg },
        });
      };

      if (toolName === 'create_repo') {
        const name = typeof args.name === 'string' ? args.name.trim() : '';
        if (!name) {
          respondInvalidParams('Missing required parameter: name');
          return;
        }
        const existing = findRepo(VIEWER_LOGIN, name);
        const repo =
          existing ??
          createRepoRecord({
            name,
            description: typeof args.description === 'string' ? args.description : '',
            private: typeof args.private === 'boolean' ? args.private : true,
          })!;
        respondToolSuccess(formatRepoJson(repo));
        return;
      }

      if (toolName === 'get_repo') {
        const owner = typeof args.owner === 'string' ? args.owner.trim() : '';
        const repoName = typeof args.repo === 'string' ? args.repo.trim() : '';
        if (!owner || !repoName) {
          respondInvalidParams('Missing required parameters: owner, repo');
          return;
        }
        const repo = findRepo(owner, repoName);
        if (!repo) {
          respondInvalidParams(`Repository ${owner}/${repoName} not found`);
          return;
        }
        respondToolSuccess(formatRepoJson(repo));
        return;
      }

      if (toolName === 'create_issue') {
        const owner = typeof args.owner === 'string' ? args.owner.trim() : '';
        const repoName = typeof args.repo === 'string' ? args.repo.trim() : '';
        const title = typeof args.title === 'string' ? args.title.trim() : '';
        if (!owner || !repoName || !title) {
          respondInvalidParams('Missing required parameters: owner, repo, title');
          return;
        }
        const repo = findRepo(owner, repoName);
        if (!repo) {
          respondInvalidParams(`Repository ${owner}/${repoName} not found`);
          return;
        }
        const created = createIssueRecord(repo, {
          title,
          body: typeof args.body === 'string' ? args.body : '',
        });
        if (!created.ok) {
          respondInvalidParams(created.message);
          return;
        }
        respondToolSuccess(formatIssueJson(created.issue));
        return;
      }

      if (toolName === 'list_issues') {
        const owner = typeof args.owner === 'string' ? args.owner.trim() : '';
        const repoName = typeof args.repo === 'string' ? args.repo.trim() : '';
        if (!owner || !repoName) {
          respondInvalidParams('Missing required parameters: owner, repo');
          return;
        }
        const repo = findRepo(owner, repoName);
        if (!repo) {
          respondInvalidParams(`Repository ${owner}/${repoName} not found`);
          return;
        }
        const stateFilter = typeof args.state === 'string' ? args.state : 'open';
        const filtered =
          stateFilter === 'all' ? repo.issues : repo.issues.filter((i) => i.state === stateFilter);
        respondToolSuccess(filtered.map(formatIssueJson));
        return;
      }

      if (toolName === 'create_pull_request') {
        const owner = typeof args.owner === 'string' ? args.owner.trim() : '';
        const repoName = typeof args.repo === 'string' ? args.repo.trim() : '';
        const title = typeof args.title === 'string' ? args.title.trim() : '';
        const head = typeof args.head === 'string' ? args.head.trim() : '';
        const base = typeof args.base === 'string' ? args.base.trim() : '';
        if (!owner || !repoName || !title || !head || !base) {
          respondInvalidParams('Missing required parameters: owner, repo, title, head, base');
          return;
        }
        const repo = findRepo(owner, repoName);
        if (!repo) {
          respondInvalidParams(`Repository ${owner}/${repoName} not found`);
          return;
        }
        const created = createPullRecord(repo, {
          title,
          body: typeof args.body === 'string' ? args.body : '',
          head,
          base,
        });
        if (!created.ok) {
          respondInvalidParams(created.message);
          return;
        }
        respondToolSuccess(formatPullJson(created.pull));
        return;
      }

      if (toolName === 'merge_pull_request') {
        const owner = typeof args.owner === 'string' ? args.owner.trim() : '';
        const repoName = typeof args.repo === 'string' ? args.repo.trim() : '';
        const pullNumber = Number(args.pull_number);
        if (!owner || !repoName || !Number.isInteger(pullNumber) || pullNumber <= 0) {
          respondInvalidParams('Missing required parameters: owner, repo, pull_number');
          return;
        }
        const repo = findRepo(owner, repoName);
        if (!repo) {
          respondInvalidParams(`Repository ${owner}/${repoName} not found`);
          return;
        }
        const pull = repo.pullsByNumber.get(pullNumber);
        if (!pull) {
          respondInvalidParams(`Pull request #${pullNumber} not found`);
          return;
        }
        const merged = executePullMerge(repo, pull);
        if (!merged.ok) {
          respondInvalidParams(merged.message);
          return;
        }
        respondToolSuccess({ sha: merged.sha, merged: true, message: merged.message });
        return;
      }

      sendJson(res, 200, {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Unknown tool: ${toolName}` },
      });
      return;
    }

    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    });
  }

  async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let urlObj: URL;
    try {
      urlObj = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
    } catch {
      sendJson(res, 400, { message: 'Invalid request URL' });
      return;
    }

    const pathname = urlObj.pathname;
    const method = (req.method ?? 'GET').toUpperCase();

    if (method === 'GET' && pathname === '/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }

    // Git Smart HTTP surface: /<owner>/<repo>.git/...
    const gitMatch = /^\/([^/]+)\/([^/]+)\.git(\/.*)$/.exec(pathname);
    if (gitMatch) {
      await handleGitSmartHttp(req, res, urlObj, decodeURIComponent(gitMatch[1]), decodeURIComponent(gitMatch[2]), gitMatch[3]);
      return;
    }

    // MCP surface: POST /mcp
    if (pathname === '/mcp') {
      if (method === 'DELETE') {
        sendJson(res, 200, { ok: true });
        return;
      }
      if (method === 'POST') {
        await handleMcpRequest(req, res);
        return;
      }
      sendJson(res, 405, { message: 'Method Not Allowed' });
      return;
    }

    // GraphQL v4 surface: POST /api/graphql
    if (pathname === '/api/graphql') {
      if (!checkBearerAuth(req)) {
        sendJson(res, 401, { message: 'Bad credentials' });
        return;
      }
      if (method !== 'POST') {
        sendJson(res, 405, { message: 'Method Not Allowed' });
        return;
      }
      const raw = await readRawBody(req);
      let body: unknown;
      try {
        body = JSON.parse(raw.toString('utf8'));
      } catch {
        sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      if (Array.isArray(body)) {
        const results = body.map((op) =>
          typeof op === 'object' && op !== null ? executeSingleGraphQL(op as { query?: unknown; variables?: Record<string, unknown> }) : { data: null },
        );
        sendJson(res, 200, results);
        return;
      }
      if (typeof body !== 'object' || body === null) {
        sendJson(res, 400, { message: 'Invalid GraphQL request payload' });
        return;
      }
      const result = executeSingleGraphQL(body as { query?: unknown; variables?: Record<string, unknown> });
      sendJson(res, 200, result);
      return;
    }

    // REST v3 surface: /api/v3/...
    if (pathname === '/api/v3' || pathname === '/api/v3/') {
      if (!checkBearerAuth(req)) {
        sendJson(res, 401, { message: 'Requires authentication' });
        return;
      }
      sendJson(
        res,
        200,
        {
          current_user_url: '/api/v3/user',
          rate_limit_url: '/api/v3/rate_limit',
        },
        { 'x-oauth-scopes': 'repo, read:org' },
      );
      return;
    }

    if (!pathname.startsWith('/api/v3/')) {
      sendJson(res, 404, { message: 'Not Found' });
      return;
    }

    if (!checkBearerAuth(req)) {
      sendJson(res, 401, { message: 'Requires authentication' });
      return;
    }

    const subPath = pathname.slice('/api/v3'.length);

    if (method === 'GET' && subPath === '/meta') {
      sendJson(res, 200, { installed_version: '3.14.0' });
      return;
    }

    if (method === 'GET' && subPath === '/user') {
      sendJson(res, 200, {
        id: VIEWER_ID,
        login: VIEWER_LOGIN,
        name: VIEWER_NAME,
        email: VIEWER_EMAIL,
      });
      return;
    }

    const readJsonBody = async (): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false }> => {
      const raw = await readRawBody(req);
      if (raw.length === 0) return { ok: true, value: {} };
      try {
        const parsed = JSON.parse(raw.toString('utf8'));
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return { ok: false };
        return { ok: true, value: parsed as Record<string, unknown> };
      } catch {
        return { ok: false };
      }
    };

    if (subPath === '/user/repos') {
      if (method === 'GET') {
        const perPage = Math.max(1, Number.parseInt(urlObj.searchParams.get('per_page') ?? '30', 10) || 30);
        const page = Math.max(1, Number.parseInt(urlObj.searchParams.get('page') ?? '1', 10) || 1);
        const allRepos = [...reposByKey.values()];
        const start = (page - 1) * perPage;
        const slice = allRepos.slice(start, start + perPage).map(formatRepoJson);
        const headers: Record<string, string> = {};
        if (start + perPage < allRepos.length) {
          const nextUrl = `${urlObj.origin}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
          headers.link = `<${nextUrl}>; rel="next"`;
        }
        sendJson(res, 200, slice, headers);
        return;
      }
      if (method === 'POST') {
        const bodyRes = await readJsonBody();
        if (!bodyRes.ok) {
          sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        const name = typeof bodyRes.value.name === 'string' ? bodyRes.value.name.trim() : '';
        if (!name) {
          sendJson(res, 422, { message: 'Repository name is required' });
          return;
        }
        const repo = createRepoRecord({
          name,
          description: typeof bodyRes.value.description === 'string' ? bodyRes.value.description : '',
          private: typeof bodyRes.value.private === 'boolean' ? bodyRes.value.private : false,
          default_branch: typeof bodyRes.value.default_branch === 'string' ? bodyRes.value.default_branch : 'main',
        });
        if (!repo) {
          sendJson(res, 422, { message: 'Repository already exists' });
          return;
        }
        sendJson(res, 201, formatRepoJson(repo));
        return;
      }
    }

    // Fast path for GET/POST /api/v3/repos/:owner/:repo/issues[/:number]
    const repoMatch = /^\/repos\/([^/]+)\/([^/]+)(?:\/(.*))?$/.exec(subPath);
    if (!repoMatch) {
      sendJson(res, 404, { message: 'Not Found' });
      return;
    }

    const owner = decodeURIComponent(repoMatch[1]);
    const repoName = decodeURIComponent(repoMatch[2]);
    const restTail = repoMatch[3] ?? '';

    const repo = findRepo(owner, repoName);
    if (!repo) {
      sendJson(res, 404, { message: 'Not Found' });
      return;
    }

    // /repos/:owner/:repo
    if (restTail === '') {
      if (method === 'GET') {
        sendJson(res, 200, formatRepoJson(repo));
        return;
      }
      if (method === 'PATCH') {
        const bodyRes = await readJsonBody();
        if (!bodyRes.ok) {
          sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        if (typeof bodyRes.value.description === 'string') repo.description = bodyRes.value.description;
        if (typeof bodyRes.value.private === 'boolean') repo.private = bodyRes.value.private;
        if (typeof bodyRes.value.default_branch === 'string' && bodyRes.value.default_branch !== '') {
          repo.defaultBranch = bodyRes.value.default_branch;
        }
        sendJson(res, 200, formatRepoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        reposByKey.delete(`${repo.owner.toLowerCase()}/${repo.name.toLowerCase()}`);
        reposByNodeId.delete(repo.nodeId);
        sendJson(res, 204, null);
        return;
      }
    }

    // Fast path for GET /repos/:owner/:repo/issues/:number (2,000-op read benchmark)
    const issueItemMatch = /^issues\/(\d+)$/.exec(restTail);
    if (issueItemMatch) {
      const issueNum = Number.parseInt(issueItemMatch[1], 10);
      const issue = repo.issuesByNumber.get(issueNum);
      if (!issue) {
        sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      if (method === 'GET') {
        if (!issue.cachedRestBytes) refreshIssueCache(issue);
        sendPrebuiltJson(res, 200, issue.cachedRestBytes!);
        return;
      }
      if (method === 'PATCH') {
        const bodyRes = await readJsonBody();
        if (!bodyRes.ok) {
          sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        if (bodyRes.value.state === 'open' || bodyRes.value.state === 'closed') {
          issue.state = bodyRes.value.state;
        }
        if (typeof bodyRes.value.title === 'string') issue.title = bodyRes.value.title;
        if (typeof bodyRes.value.body === 'string') issue.body = bodyRes.value.body;
        refreshIssueCache(issue);
        sendPrebuiltJson(res, 200, issue.cachedRestBytes!);
        return;
      }
    }

    // Fast path for POST/GET /repos/:owner/:repo/issues (200-op write benchmark)
    if (restTail === 'issues') {
      if (method === 'POST') {
        const bodyRes = await readJsonBody();
        if (!bodyRes.ok) {
          sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        const created = createIssueRecord(repo, {
          title: String(bodyRes.value.title ?? ''),
          body: typeof bodyRes.value.body === 'string' ? bodyRes.value.body : '',
          labels: Array.isArray(bodyRes.value.labels) ? bodyRes.value.labels : undefined,
        });
        if (!created.ok) {
          sendJson(res, 422, { message: created.message });
          return;
        }
        sendPrebuiltJson(res, 201, created.issue.cachedRestBytes!);
        return;
      }
      if (method === 'GET') {
        const stateParam = urlObj.searchParams.get('state') ?? 'open';
        const direction = urlObj.searchParams.get('direction') ?? 'desc';
        const perPage = Math.max(1, Number.parseInt(urlObj.searchParams.get('per_page') ?? '30', 10) || 30);
        const page = Math.max(1, Number.parseInt(urlObj.searchParams.get('page') ?? '1', 10) || 1);

        let list = stateParam === 'all' ? [...repo.issues] : repo.issues.filter((i) => i.state === stateParam);
        list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        const start = (page - 1) * perPage;
        sendJson(res, 200, list.slice(start, start + perPage).map(formatIssueJson));
        return;
      }
    }

    // /repos/:owner/:repo/issues/:number/comments
    const issueCommentsMatch = /^issues\/(\d+)\/comments$/.exec(restTail);
    if (issueCommentsMatch) {
      const issueNum = Number.parseInt(issueCommentsMatch[1], 10);
      const issue = repo.issuesByNumber.get(issueNum);
      if (!issue) {
        sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      if (method === 'GET') {
        sendJson(
          res,
          200,
          issue.comments.map((c) => ({ id: c.id, body: c.body })),
        );
        return;
      }
      if (method === 'POST') {
        const bodyRes = await readJsonBody();
        if (!bodyRes.ok) {
          sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        commentGlobalSeq += 1;
        const cid = commentGlobalSeq;
        const comment: IssueCommentRecord = {
          id: cid,
          nodeId: `IC_kwDO_${cid}`,
          body: String(bodyRes.value.body ?? ''),
        };
        issue.comments.push(comment);
        sendJson(res, 201, { id: comment.id, body: comment.body });
        return;
      }
    }

    // /repos/:owner/:repo/labels
    if (restTail === 'labels' && method === 'POST') {
      const bodyRes = await readJsonBody();
      if (!bodyRes.ok) {
        sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const name = String(bodyRes.value.name ?? '').trim();
      const color = typeof bodyRes.value.color === 'string' ? bodyRes.value.color : 'ededed';
      const label = { name, color };
      repo.labels.set(name, label);
      sendJson(res, 201, label);
      return;
    }

    // /repos/:owner/:repo/git/refs
    if (restTail === 'git/refs' && method === 'POST') {
      const bodyRes = await readJsonBody();
      if (!bodyRes.ok) {
        sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const rawRef = String(bodyRes.value.ref ?? '');
      const sha = String(bodyRes.value.sha ?? '');
      const fullRef = rawRef.startsWith('refs/') ? rawRef : `refs/heads/${rawRef}`;
      repo.refs.set(fullRef, sha);
      repo.shallowPackCache.clear();
      repo.lsRefsCache.clear();
      sendJson(res, 201, {
        ref: fullRef,
        object: { sha, type: 'commit' },
      });
      return;
    }

    // /repos/:owner/:repo/git/refs/heads/:branch
    if (restTail.startsWith('git/refs/heads/') && method === 'GET') {
      const branch = restTail.slice('git/refs/heads/'.length).split('/').map(decodeURIComponent).join('/');
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (!sha) {
        sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      sendJson(res, 200, {
        ref: `refs/heads/${branch}`,
        object: { sha, type: 'commit' },
      });
      return;
    }

    // /repos/:owner/:repo/branches
    if (restTail === 'branches' && method === 'GET') {
      const branches: Array<{ name: string; commit: { sha: string } }> = [];
      for (const [refName, oid] of repo.refs.entries()) {
        if (refName.startsWith('refs/heads/')) {
          branches.push({
            name: refName.slice('refs/heads/'.length),
            commit: { sha: oid },
          });
        }
      }
      sendJson(res, 200, branches);
      return;
    }

    if (restTail.startsWith('branches/') && method === 'GET') {
      const branch = restTail.slice('branches/'.length).split('/').map(decodeURIComponent).join('/');
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (!sha) {
        sendJson(res, 404, { message: 'Branch not found' });
        return;
      }
      sendJson(res, 200, {
        name: branch,
        commit: { sha },
      });
      return;
    }

    // /repos/:owner/:repo/commits
    if (restTail === 'commits' && method === 'GET') {
      const shaParam = urlObj.searchParams.get('sha') ?? repo.defaultBranch;
      const tipOid = resolveBranchTip(repo, shaParam);
      if (!tipOid) {
        sendJson(res, 200, []);
        return;
      }
      const list: Array<{ sha: string; commit: { message: string } }> = [];
      const visited = new Set<string>();
      const queue = [tipOid];
      while (queue.length > 0) {
        const oid = queue.shift()!;
        if (visited.has(oid)) continue;
        visited.add(oid);
        const parsed = getParsedCommit(repo, oid);
        if (!parsed) continue;
        list.push({
          sha: oid,
          commit: { message: parsed.message.replace(/\n$/, '') },
        });
        for (const p of parsed.parents) {
          if (!visited.has(p)) queue.push(p);
        }
      }
      sendJson(res, 200, list);
      return;
    }

    // /repos/:owner/:repo/contents/:path
    if (restTail === 'contents' || restTail.startsWith('contents/')) {
      const rawPath = restTail === 'contents' ? '' : restTail.slice('contents/'.length);
      const filePath = rawPath
        .split('/')
        .filter(Boolean)
        .map(decodeURIComponent)
        .join('/');

      if (method === 'GET') {
        const refParam = urlObj.searchParams.get('ref') ?? repo.defaultBranch;
        const tipOid = resolveBranchTip(repo, refParam);
        if (!tipOid) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        const flat = flattenCommitTree(repo, tipOid);
        const exactBlobOid = flat.get(filePath);
        if (exactBlobOid) {
          const blobObj = repo.objects.get(exactBlobOid);
          if (!blobObj) {
            sendJson(res, 404, { message: 'Not Found' });
            return;
          }
          const name = filePath.split('/').pop() ?? filePath;
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            name,
            path: filePath,
            sha: exactBlobOid,
            size: blobObj.data.length,
            content: blobObj.data.toString('base64'),
          });
          return;
        }

        // Check directory listing
        const prefix = filePath === '' ? '' : `${filePath}/`;
        const childMap = new Map<string, { type: 'file' | 'dir'; name: string; path: string; sha: string; size: number }>();
        for (const [p, bOid] of flat.entries()) {
          if (prefix !== '' && !p.startsWith(prefix)) continue;
          const rel = prefix === '' ? p : p.slice(prefix.length);
          if (!rel) continue;
          const slashIdx = rel.indexOf('/');
          if (slashIdx < 0) {
            const bObj = repo.objects.get(bOid);
            childMap.set(rel, {
              type: 'file',
              name: rel,
              path: prefix === '' ? rel : `${filePath}/${rel}`,
              sha: bOid,
              size: bObj?.data.length ?? 0,
            });
          } else {
            const dirName = rel.slice(0, slashIdx);
            if (!childMap.has(dirName)) {
              childMap.set(dirName, {
                type: 'dir',
                name: dirName,
                path: prefix === '' ? dirName : `${filePath}/${dirName}`,
                sha: bOid,
                size: 0,
              });
            }
          }
        }

        if (childMap.size === 0) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        sendJson(res, 200, [...childMap.values()]);
        return;
      }

      if (method === 'PUT') {
        const bodyRes = await readJsonBody();
        if (!bodyRes.ok) {
          sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        const branch = typeof bodyRes.value.branch === 'string' && bodyRes.value.branch !== '' ? bodyRes.value.branch : repo.defaultBranch;
        const refName = `refs/heads/${branch}`;
        const existingBranchTip = repo.refs.get(refName);
        const fallbackBaseTip = existingBranchTip ?? repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        const baseMap = fallbackBaseTip ? new Map(flattenCommitTree(repo, fallbackBaseTip)) : new Map<string, string>();

        const existingBlobOid = existingBranchTip ? flattenCommitTree(repo, existingBranchTip).get(filePath) : baseMap.get(filePath);
        const givenSha = typeof bodyRes.value.sha === 'string' ? bodyRes.value.sha : undefined;

        if (existingBlobOid !== undefined && givenSha !== undefined && givenSha.toLowerCase() !== existingBlobOid.toLowerCase()) {
          sendJson(res, 409, { message: `${filePath} does not match ${givenSha}` });
          return;
        }

        const contentB64 = String(bodyRes.value.content ?? '').replace(/[\r\n\t ]+/g, '');
        const rawBytes = Buffer.from(contentB64, 'base64');
        const newBlobOid = storeGitObject(repo, 'blob', rawBytes);

        baseMap.set(filePath, newBlobOid);
        const newTreeOid = buildTreeFromFlatMap(repo, baseMap);
        const message = String(bodyRes.value.message ?? 'Update content');
        const parents = fallbackBaseTip ? [fallbackBaseTip] : [];
        const newCommitOid = storeGitObject(repo, 'commit', buildCommitBuffer(newTreeOid, parents, message));

        repo.refs.set(refName, newCommitOid);
        repo.shallowPackCache.clear();

        const status = existingBlobOid !== undefined ? 200 : 201;
        const name = filePath.split('/').pop() ?? filePath;
        sendJson(res, status, {
          content: {
            name,
            path: filePath,
            sha: newBlobOid,
            size: rawBytes.length,
            type: 'file',
            encoding: 'base64',
          },
          commit: {
            sha: newCommitOid,
            message,
          },
        });
        return;
      }

      if (method === 'DELETE') {
        const bodyRes = await readJsonBody();
        if (!bodyRes.ok) {
          sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        const branch = typeof bodyRes.value.branch === 'string' && bodyRes.value.branch !== '' ? bodyRes.value.branch : repo.defaultBranch;
        const refName = `refs/heads/${branch}`;
        const currentTip = repo.refs.get(refName);
        if (!currentTip) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        const files = new Map(flattenCommitTree(repo, currentTip));
        const currentBlob = files.get(filePath);
        if (!currentBlob) {
          sendJson(res, 404, { message: 'Not Found' });
          return;
        }
        const givenSha = typeof bodyRes.value.sha === 'string' ? bodyRes.value.sha : undefined;
        if (givenSha && givenSha.toLowerCase() !== currentBlob.toLowerCase()) {
          sendJson(res, 409, { message: 'sha mismatch' });
          return;
        }
        files.delete(filePath);
        const newTreeOid = buildTreeFromFlatMap(repo, files);
        const message = String(bodyRes.value.message ?? 'Delete content');
        const newCommitOid = storeGitObject(repo, 'commit', buildCommitBuffer(newTreeOid, [currentTip], message));
        repo.refs.set(refName, newCommitOid);
        repo.shallowPackCache.clear();

        sendJson(res, 200, {
          content: null,
          commit: {
            sha: newCommitOid,
            message,
          },
        });
        return;
      }
    }

    // /repos/:owner/:repo/pulls
    if (restTail === 'pulls') {
      if (method === 'GET') {
        const stateParam = urlObj.searchParams.get('state') ?? 'open';
        const list = stateParam === 'all' ? repo.pulls : repo.pulls.filter((p) => p.state === stateParam);
        sendJson(res, 200, list.map(formatPullJson));
        return;
      }
      if (method === 'POST') {
        const bodyRes = await readJsonBody();
        if (!bodyRes.ok) {
          sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        const created = createPullRecord(repo, {
          title: String(bodyRes.value.title ?? ''),
          body: typeof bodyRes.value.body === 'string' ? bodyRes.value.body : '',
          head: String(bodyRes.value.head ?? ''),
          base: typeof bodyRes.value.base === 'string' ? bodyRes.value.base : repo.defaultBranch,
        });
        if (!created.ok) {
          sendJson(res, 422, { message: created.message });
          return;
        }
        sendJson(res, 201, formatPullJson(created.pull));
        return;
      }
    }

    const pullItemMatch = /^pulls\/(\d+)(?:\/(files|merge))?$/.exec(restTail);
    if (pullItemMatch) {
      const pullNum = Number.parseInt(pullItemMatch[1], 10);
      const subAction = pullItemMatch[2];
      const pull = repo.pullsByNumber.get(pullNum);
      if (!pull) {
        sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      if (!subAction && method === 'GET') {
        sendJson(res, 200, formatPullJson(pull));
        return;
      }
      if (subAction === 'files' && method === 'GET') {
        sendJson(res, 200, computePullChangedFiles(repo, pull));
        return;
      }
      if (subAction === 'merge' && method === 'PUT') {
        const merged = executePullMerge(repo, pull);
        if (!merged.ok) {
          sendJson(res, merged.status, { message: merged.message });
          return;
        }
        sendJson(res, 200, {
          sha: merged.sha,
          merged: true,
          message: merged.message,
        });
        return;
      }
    }

    sendJson(res, 404, { message: 'Not Found' });
  }

  return createServer((req, res) => {
    void handleRequest(req, res).catch((err: unknown) => {
      sendJson(res, 500, {
        message: err instanceof Error ? err.message : 'Internal Server Error',
      });
    });
  });
}
