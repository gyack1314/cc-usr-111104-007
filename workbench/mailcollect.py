"""赛务邮箱资料收集端：只读 IMAP 取件、严格 MIME 附件提取与可重放存档。

- 协议：IMAP4rev1 只读 EXAMINE、UID SEARCH、UID FETCH BODY.PEEK[]。
- 邮件身份 = 邮箱标识 + UIDVALIDITY + UID；Message-ID 仅作元数据，不参与去重。
- 每轮先固定 UIDNEXT 边界，仅处理小于边界的 UID；UID 空洞不视为缺件。
- UIDVALIDITY 变化开启新世代：旧世代档案保留，且不再用旧 UID 取件。
- FETCH 响应按实际 UID 关联，与请求顺序、消息序号（EXPUNGE 等）无关。
- 仅 attachment disposition 的叶部件进入材料目录；inline 资源不进入。
- message/rfc822 作为附件时保留其原始内容，不再重复导入其中附件。
- 非法编码、重复或缺失续段、危险文件名一律旁路，不默默容错。
"""
import argparse
import base64
import binascii
import hashlib
import imaplib
import json
import os
import quopri
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from pathlib import Path

from .raw_store import read_bytes, save_bytes

ALLOWED_CTE = {'base64', 'quoted-printable', '7bit', '8bit', 'binary'}
CONTAINER_CTE = {'7bit', '8bit', 'binary'}
NAME_CHARSETS = {'utf-8', 'us-ascii'}
DEFAULT_MAX_PART = 16 * 1024 * 1024
MAX_DEPTH = 50
COMPLETE = ('parsed', 'bypassed')


class Bypass(Exception):
    """内容非法：旁路对应部件或整封邮件，原始字节仍保留在档案中。"""


class RoundAbort(Exception):
    """轮次无法继续（连接中断或服务器拒绝）。"""


class GenerationChanged(RoundAbort):
    """UIDVALIDITY 在轮次中变化：立即停止用旧 UID 取件。"""


def now_iso():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


# ---------------------------------------------------------------- 身份与存储名

@dataclass(frozen=True)
class Identity:
    """邮件身份：邮箱标识 + UIDVALIDITY + UID。"""
    mailbox: str
    uidvalidity: int
    uid: int

    def key(self):
        return f'{self.mailbox}/{self.uidvalidity}/{self.uid}'

    @staticmethod
    def parse(text):
        parts = text.rsplit('/', 2)
        if len(parts) != 3 or not parts[0]:
            raise ValueError(f'身份格式应为 <邮箱>/<UIDVALIDITY>/<UID>: {text!r}')
        mailbox, validity, uid = parts
        return Identity(mailbox, int(validity), int(uid))


def encode_mailbox(name):
    """邮箱标识转目录名：仅保留ASCII字母数字与-_，其余按UTF-8百分号编码。"""
    out = []
    for ch in name:
        if ch.isascii() and (ch.isalnum() or ch in '-_'):
            out.append(ch)
        else:
            out.extend(f'%{byte:02X}' for byte in ch.encode('utf-8'))
    return ''.join(out) or '%00'


# ---------------------------------------------------------------- 头字段参数

def split_quoted(text, sep):
    """按分隔符拆分，忽略引号内的分隔符；引号未闭合视为非法。"""
    out, cur, quoted, escaped = [], [], False, False
    for ch in text:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == '\\' and quoted:
            cur.append(ch)
            escaped = True
        elif ch == '"':
            cur.append(ch)
            quoted = not quoted
        elif ch == sep and not quoted:
            out.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    if quoted or escaped:
        raise Bypass('引号未闭合')
    out.append(''.join(cur))
    return out


def unquote_token(value):
    if not value.startswith('"'):
        if '"' in value:
            raise Bypass('引号位置非法')
        return value
    if len(value) < 2 or not value.endswith('"'):
        raise Bypass('引号未闭合')
    body = value[1:-1]
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch == '\\':
            i += 1
            if i >= len(body):
                raise Bypass('转义不完整')
            out.append(body[i])
        elif ch == '"':
            raise Bypass('引号位置非法')
        else:
            out.append(ch)
        i += 1
    return ''.join(out)


def parse_params(raw):
    """解析 `主值; k=v` 形式的头字段值，保留参数顺序与重复项。"""
    segments = split_quoted(raw, ';')
    head = segments[0].strip().lower()
    params = []
    for seg in segments[1:]:
        seg = seg.strip()
        if not seg:
            continue
        if '=' not in seg:
            raise Bypass(f'参数缺少等号: {seg!r}')
        key, _, value = seg.partition('=')
        key = key.strip().lower()
        if not key:
            raise Bypass('参数名为空')
        params.append((key, unquote_token(value.strip())))
    return head, params


def one_param(params, name):
    values = [v for k, v in params if k == name]
    if len(values) > 1:
        raise Bypass(f'参数重复: {name}')
    return values[0] if values else None


# ---------------------------------------------------------------- RFC2231 文件名

def check_plain_text(value, what):
    if any(0xDC80 <= ord(ch) <= 0xDCFF for ch in value):
        raise Bypass(f'{what}含未编码的8bit字节')
    return value


def pct_decode(data, what):
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x25:  # '%'
            pair = data[i + 1:i + 3]
            if len(pair) != 2 or not re.fullmatch(rb'[0-9A-Fa-f]{2}', pair):
                raise Bypass(f'{what}的%编码非法')
            out.append(int(pair, 16))
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def decode_charset(data, charset):
    try:
        return data.decode(charset, 'strict')
    except (UnicodeDecodeError, LookupError) as exc:
        raise Bypass(f'字符集 {charset} 解码失败: {exc}')


def split_extended(value, what):
    """拆分 charset'lang'text 形式的扩展参数值。"""
    try:
        raw = value.encode('ascii')
    except UnicodeEncodeError:
        raise Bypass(f'{what}含非ASCII字节')
    match = re.match(rb"^([^\x27]+)\x27[^\x27]*\x27(.*)$", raw, re.S)
    if not match:
        raise Bypass(f'{what}缺少字符集标记')
    charset = match.group(1).decode('ascii').lower()
    if charset not in NAME_CHARSETS:
        raise Bypass(f'不支持的字符集: {charset}')
    return charset, match.group(2)


def decode_extended_single(value, what):
    charset, text = split_extended(value, what)
    return decode_charset(pct_decode(text, what), charset)


def join_continuations(segments, what):
    """segments: [(值, 是否编码)]，下标已验证从零连续。"""
    first_value, first_encoded = segments[0]
    if not first_encoded:
        if any(encoded for _, encoded in segments[1:]):
            raise Bypass(f'{what}首段未编码而后段编码')
        return check_plain_text(''.join(value for value, _ in segments), what)
    charset, first_text = split_extended(first_value, what)
    chunks = [pct_decode(first_text, what)]
    for value, encoded in segments[1:]:
        try:
            raw = value.encode('ascii')
        except UnicodeEncodeError:
            raise Bypass(f'{what}含非ASCII字节')
        chunks.append(pct_decode(raw, what) if encoded else raw)
    return decode_charset(b''.join(chunks), charset)


def rfc2231_name(params, base):
    """按RFC2231重组文件名参数；冲突、重复、缺段均视为非法。"""
    plain = [v for k, v in params if k == base]
    if len(plain) > 1:
        raise Bypass(f'参数 {base} 重复')
    single = [v for k, v in params if k == base + '*']
    if len(single) > 1:
        raise Bypass(f'参数 {base}* 重复')
    segments = {}
    pattern = re.compile(re.escape(base) + r'\*(\d+)(\*)?$')
    for key, value in params:
        match = pattern.fullmatch(key)
        if not match:
            continue
        index = int(match.group(1))
        if index in segments:
            raise Bypass(f'续段 {base}*{index} 重复')
        segments[index] = (value, bool(match.group(2)))
    extended = None
    if single:
        extended = decode_extended_single(single[0], base)
    elif segments:
        if sorted(segments) != list(range(len(segments))):
            raise Bypass(f'续段 {base} 必须从零连续')
        extended = join_continuations([segments[i] for i in sorted(segments)], base)
    if plain and extended is not None:
        if check_plain_text(plain[0], base) != extended:
            raise Bypass(f'普通名与扩展名冲突: {base}')
        return extended
    if extended is not None:
        return extended
    if plain:
        return check_plain_text(plain[0], base)
    return None


def check_safe_filename(name):
    """危险文件名旁路：分隔符、控制字符、相对路径、空名、超长。"""
    try:
        encoded = name.encode('utf-8', 'strict')
    except UnicodeEncodeError:
        raise Bypass('文件名含无法编码的字符')
    if not name.strip():
        raise Bypass('文件名为空')
    if len(encoded) > 255:
        raise Bypass('文件名过长')
    if name in ('.', '..'):
        raise Bypass('文件名为相对路径')
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        raise Bypass('文件名含控制字符')
    if '/' in name or '\\' in name:
        raise Bypass('文件名含路径分隔符')
    return name


# ---------------------------------------------------------------- 传输编码

def validate_qp(body):
    """quoted-printable 严格检查：= 后只能是两位十六进制或软换行。"""
    i, n = 0, len(body)
    while i < n:
        byte = body[i]
        if byte == 0x3D:  # '='
            nxt = body[i + 1:i + 3]
            if nxt == b'\r\n' or nxt[:1] == b'\n':
                i += 1 + len(nxt if nxt == b'\r\n' else b'\n')
                continue
            if len(nxt) != 2 or not re.fullmatch(rb'[0-9A-Fa-f]{2}', nxt):
                raise Bypass('quoted-printable转义非法')
            i += 3
        elif byte in (0x09, 0x0A, 0x0D) or 0x20 <= byte <= 0x7E:
            i += 1
        else:
            raise Bypass('quoted-printable含非法字节')


def decode_cte(body, cte, limit):
    """按声明编码解码叶部件，严格校验，解码结果限额。"""
    if cte == 'base64':
        compact = re.sub(rb'[ \t\r\n]+', b'', body)
        if len(compact) % 4:
            raise Bypass('base64长度不是4的倍数')
        if not re.fullmatch(rb'[A-Za-z0-9+/]*={0,2}', compact):
            raise Bypass('base64含非法字符')
        if len(compact) // 4 * 3 > limit:
            raise Bypass(f'部件超过解码限额 {limit}')
        try:
            data = base64.b64decode(compact, validate=True)
        except binascii.Error as exc:
            raise Bypass(f'base64非法: {exc}')
    elif cte == 'quoted-printable':
        validate_qp(body)
        data = quopri.decodestring(body)
    elif cte == '7bit':
        if any(byte > 0x7F for byte in body):
            raise Bypass('7bit含8bit字节')
        data = body
    else:  # 8bit / binary
        data = body
    if len(data) > limit:
        raise Bypass(f'部件超过解码限额 {limit}')
    return data


# ---------------------------------------------------------------- MIME 结构

HEAD_SEP = re.compile(rb'\r?\n\r?\n')


def split_head_body(raw):
    match = HEAD_SEP.search(raw)
    if match:
        return raw[:match.start()], raw[match.end():]
    return raw, b''


def parse_headers(raw):
    return Parser(policy=policy.compat32).parsestr(
        raw.decode('ascii', 'surrogateescape'), headersonly=True)


def single_header(msg, name):
    values = msg.get_all(name, [])
    if len(values) > 1:
        raise Bypass(f'头字段重复: {name}')
    return values[0] if values else None


def header_head(msg, name):
    """取头字段主值（分号前），仅用于结构判断，参数校验留给叶部件处理。"""
    values = msg.get_all(name, [])
    if not values:
        return None
    return values[0].split(';', 1)[0].strip().lower()


def read_cte(msg):
    raw = single_header(msg, 'content-transfer-encoding')
    if raw is None:
        return None
    token = raw.strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', token):
        raise Bypass(f'编码标记非法: {raw!r}')
    if token not in ALLOWED_CTE:
        raise Bypass(f'不支持的编码: {token}')
    return token


def split_multipart(body, boundary):
    """按boundary切分multipart正文，返回各子部件原始字节（含各自头字段）。"""
    try:
        token = boundary.encode('ascii')
    except UnicodeEncodeError:
        raise Bypass('boundary含非ASCII字符')
    if not token:
        raise Bypass('boundary为空')
    delimiter = b'--' + token
    closer = delimiter + b'--'
    parts, current, closed = [], None, False
    for line in body.splitlines(keepends=True):
        core = line.rstrip(b'\r\n').rstrip(b' \t')
        if core == delimiter or core == closer:
            if current is not None:
                parts.append(b''.join(current))
            current = None
            if core == closer:
                closed = True
                break
            current = []
        elif current is not None:
            current.append(line)
    if not closed:
        raise Bypass('multipart缺少结束边界')
    if not parts:
        raise Bypass('multipart没有子部件')
    return parts


@dataclass
class Leaf:
    path: str
    msg: object
    body: bytes


def child_path(path, index):
    return f'{path}.{index}' if path else str(index)


def walk(raw, path, leaves, depth=0):
    """按字节遍历MIME结构，叶部件保留原始正文；部件路径为从1开始的子部件序号。"""
    if depth > MAX_DEPTH:
        raise Bypass('MIME嵌套过深')
    head_raw, body = split_head_body(raw)
    msg = parse_headers(head_raw)
    ctype = header_head(msg, 'content-type') or 'text/plain'
    if '/' not in ctype:
        raise Bypass(f'Content-Type非法: {ctype!r}')
    disp = header_head(msg, 'content-disposition')
    if ctype.startswith('multipart/'):
        cte = read_cte(msg)
        if cte is not None and cte not in CONTAINER_CTE:
            raise Bypass(f'multipart编码非法: {cte}')
        _, ct_params = parse_params(single_header(msg, 'content-type') or '')
        boundary = one_param(ct_params, 'boundary')
        if boundary is None:
            raise Bypass('multipart缺少boundary')
        for index, sub in enumerate(split_multipart(body, boundary), 1):
            walk(sub, child_path(path, index), leaves, depth + 1)
    elif ctype == 'message/rfc822' and disp != 'attachment':
        # 非附件的内嵌邮件是容器，继续向下找附件叶部件
        cte = read_cte(msg)
        if cte is not None and cte not in CONTAINER_CTE:
            raise Bypass(f'message/rfc822编码非法: {cte}')
        walk(body, child_path(path, 1), leaves, depth + 1)
    else:
        leaves.append(Leaf(path or '1', msg, body))


@dataclass
class PartContent:
    path: str
    filename: object
    content_type: str
    data: bytes


def process_leaf(leaf, max_part_bytes):
    """叶部件筛选：仅 attachment disposition 进入材料目录，其余返回None。"""
    msg = leaf.msg
    ct_raw = single_header(msg, 'content-type')
    ctype, ct_params = parse_params(ct_raw) if ct_raw is not None else ('text/plain', [])
    if '/' not in ctype:
        raise Bypass(f'Content-Type非法: {ctype!r}')
    disp_raw = single_header(msg, 'content-disposition')
    disp, disp_params = parse_params(disp_raw) if disp_raw is not None else (None, [])
    if disp != 'attachment':
        return None
    cte = read_cte(msg) or '7bit'
    if ctype == 'message/rfc822':
        # 内嵌邮件作为附件：保留原始内容，不做传输解码，也不再导入其中附件
        if cte not in CONTAINER_CTE:
            raise Bypass(f'message/rfc822编码非法: {cte}')
        data = leaf.body
        if len(data) > max_part_bytes:
            raise Bypass(f'部件超过解码限额 {max_part_bytes}')
    else:
        data = decode_cte(leaf.body, cte, max_part_bytes)
    filename = rfc2231_name(disp_params, 'filename')
    if filename is None:
        filename = rfc2231_name(ct_params, 'name')
    if filename is not None:
        check_safe_filename(filename)
    return PartContent(leaf.path, filename, ctype, data)


def parse_message(raw, max_part_bytes):
    """解析RFC822原文，返回(附件列表, 旁路列表, Message-ID, 非附件叶数)。

    整封结构非法时抛 Bypass；单个部件非法只记入旁路列表。
    """
    leaves = []
    walk(raw, '', leaves)
    top_msg = parse_headers(split_head_body(raw)[0])
    message_id = top_msg.get('Message-ID')
    message_id = str(message_id).strip() if message_id is not None else None
    parts, bypassed, skipped = [], [], 0
    for leaf in leaves:
        try:
            part = process_leaf(leaf, max_part_bytes)
        except Bypass as exc:
            bypassed.append({'path': leaf.path, 'reason': str(exc)})
            continue
        if part is None:
            skipped += 1
        else:
            parts.append(part)
    return parts, bypassed, message_id, skipped


# ---------------------------------------------------------------- 存档

def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.part-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_json(path, obj):
    atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True).encode('utf-8'))


class Store:
    """资料输出目录：raw/原始邮件、materials/附件、state.json索引、reports/轮次报告。"""

    def __init__(self, root):
        self.root = Path(root)
        self.raw_root = self.root / 'raw'
        self.materials_root = self.root / 'materials'
        self.reports_root = self.root / 'reports'
        for path in (self.raw_root, self.materials_root, self.reports_root):
            path.mkdir(parents=True, exist_ok=True)

    def state_path(self):
        return self.root / 'state.json'

    def load_state(self):
        path = self.state_path()
        if not path.exists():
            return {'version': 1, 'generations': {}, 'messages': {}, 'rounds_run': 0}
        with path.open(encoding='utf-8') as fh:
            state = json.load(fh)
        if state.get('version') != 1:
            raise ValueError('状态文件版本不支持')
        return state

    def save_state(self, state):
        atomic_json(self.state_path(), state)

    def materials_dir(self, ident):
        return (self.materials_root / encode_mailbox(ident.mailbox)
                / str(ident.uidvalidity) / str(ident.uid))

    def clear_materials(self, ident):
        target = self.materials_dir(ident)
        if target.exists():
            shutil.rmtree(target)

    def write_part(self, ident, part):
        """存储名由邮件身份与部件路径决定，不用来件文件名拼路径。"""
        target = self.materials_dir(ident) / f'part-{part.path}'
        atomic_write(target, part.data)
        return target.relative_to(self.root).as_posix(), hashlib.sha256(part.data).hexdigest()

    def save_report(self, state, report):
        """轮次计数先入状态文件，再写报告，避免报告编号重用覆盖旧报告。"""
        state['rounds_run'] += 1
        report['round'] = state['rounds_run']
        report['report_file'] = f"reports/round-{state['rounds_run']:04d}.json"
        self.save_state(state)
        atomic_json(self.root / report['report_file'], report)


def new_record(ident):
    return {'mailbox': ident.mailbox, 'uidvalidity': ident.uidvalidity, 'uid': ident.uid,
            'message_id': None, 'raw_key': None, 'raw_size': None,
            'status': 'pending', 'error': None, 'attempts': 0, 'updated': now_iso(),
            'parts': [], 'bypassed_parts': [], 'bypass_reason': None,
            'skipped_non_attachment': 0}


def parse_and_record(store, state, ident, raw, rec, report, max_part_bytes):
    """解析已持久化的原文并重建附件索引；单封失败不影响其它邮件。"""
    rec['attempts'] = rec.get('attempts', 0) + 1
    rec['updated'] = now_iso()
    try:
        parts, bypassed, message_id, skipped = parse_message(raw, max_part_bytes)
    except Bypass as exc:
        store.clear_materials(ident)
        rec.update(status='bypassed', bypass_reason=str(exc), parts=[],
                   bypassed_parts=[], error=None)
        report['bypassed'].append({'identity': ident.key(), 'part': None, 'reason': str(exc)})
        return
    except Exception as exc:  # 未预期错误：标记失败并留在待处理集合
        rec.update(status='failed', error=f'{type(exc).__name__}: {exc}')
        report['failed'].append({'identity': ident.key(), 'error': rec['error']})
        return
    store.clear_materials(ident)
    written = []
    for part in parts:
        rel, digest = store.write_part(ident, part)
        entry = {'path': part.path, 'filename': part.filename,
                 'content_type': part.content_type, 'size': len(part.data),
                 'sha256': digest, 'stored_as': rel}
        written.append(entry)
        report['materials'].append({'identity': ident.key(), **entry})
    rec.update(status='bypassed' if bypassed else 'parsed', parts=written,
               bypassed_parts=bypassed, bypass_reason=None, message_id=message_id,
               skipped_non_attachment=skipped, error=None)
    report['inline_skipped'] = report.get('inline_skipped', 0) + skipped
    for item in bypassed:
        report['bypassed'].append({'identity': ident.key(), 'part': item['path'],
                                   'reason': item['reason']})


# ---------------------------------------------------------------- 协议

FETCH_UID = re.compile(rb'\bUID (\d+)\b')


def read_validity(conn, mailbox):
    """EXAMINE 只读打开邮箱，读取 UIDVALIDITY 与 UIDNEXT。"""
    typ, _ = conn.select(mailbox, readonly=True)
    if typ != 'OK':
        raise RoundAbort(f'EXAMINE失败: {typ}')
    values = {}
    for name in ('UIDVALIDITY', 'UIDNEXT'):
        data = conn.response(name)[1]
        if not data or data[0] is None:
            raise RoundAbort(f'EXAMINE响应缺少{name}')
        values[name] = int(data[0])
    return values['UIDVALIDITY'], values['UIDNEXT']


def ensure_generation(conn, mailbox, validity):
    """取件前复查世代：UIDVALIDITY 变了就不得继续用旧 UID。"""
    current, _ = read_validity(conn, mailbox)
    if current != validity:
        raise GenerationChanged(f'UIDVALIDITY在轮次中变化: {validity} -> {current}')


def fetch_chunk(conn, uids):
    """UID FETCH BODY.PEEK[]；按响应中的实际UID关联，与请求顺序、消息序号无关。"""
    uidset = ','.join(str(uid) for uid in uids)
    typ, data = conn.uid('FETCH', uidset, '(UID BODY.PEEK[])')
    if typ != 'OK':
        raise imaplib.IMAP4.error(f'UID FETCH被拒绝: {typ}')
    found = {}
    for item in data or []:
        if not (isinstance(item, tuple) and len(item) == 2):
            continue
        header, literal = item
        if not isinstance(literal, bytes):
            continue
        if not isinstance(header, bytes):
            header = str(header).encode('ascii', 'replace')
        match = FETCH_UID.search(header)
        if match:
            found[int(match.group(1))] = literal
    return found


def apply_generation(state, mailbox, validity, report):
    """登记世代：UIDVALIDITY 变化时开启新世代，旧世代档案保留。"""
    gens = state['generations']
    gen = gens.get(mailbox)
    if gen is None:
        gens[mailbox] = {'current': validity, 'history': [
            {'uidvalidity': validity, 'since': now_iso(), 'retired': None}]}
        report['generation_events'].append({'event': 'established', 'uidvalidity': validity})
        return
    if gen['current'] != validity:
        old = gen['current']
        for entry in gen['history']:
            if entry['uidvalidity'] == old and entry['retired'] is None:
                entry['retired'] = now_iso()
        gen['history'].append({'uidvalidity': validity, 'since': now_iso(), 'retired': None})
        gen['current'] = validity
        report['generation_events'].append({
            'event': 'rollover', 'from': old, 'to': validity,
            'note': '开启新世代，旧世代档案保留，不再用旧UID取件'})


def chunks(items, size):
    size = max(1, size)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def mark_failed(state, ident, error, report):
    rec = state['messages'].get(ident.key()) or new_record(ident)
    state['messages'][ident.key()] = rec
    rec.update(status='failed', error=error,
               attempts=rec.get('attempts', 0) + 1, updated=now_iso())
    report['failed'].append({'identity': ident.key(), 'error': error})


def collect_round(store, host, port, mailbox, user, password,
                  max_part_bytes=DEFAULT_MAX_PART, chunk_size=32, timeout=10):
    """执行一轮只读收集，返回轮次报告（同时写入 reports/ 与 state.json）。"""
    state = store.load_state()
    report = {'started': now_iso(), 'mailbox': mailbox, 'host': host, 'port': port,
              'max_part_bytes': max_part_bytes, 'aborted': None,
              'uidvalidity': None, 'uidnext_boundary': None,
              'generation_events': [],
              'search': {'returned': [], 'in_scope': [], 'beyond_boundary': []},
              'already_done': [], 'fetched': [], 'reparsed': [], 'unexpected': [],
              'materials': [], 'bypassed': [], 'failed': [],
              'inline_skipped': 0, 'pending_after': []}
    in_scope = []
    created_this_round = []
    conn = None
    try:
        conn = imaplib.IMAP4(host, port, timeout=timeout)
        try:
            conn.login(user, password)
        except imaplib.IMAP4.error as exc:
            raise RoundAbort(f'LOGIN失败: {exc}')
        validity, uidnext = read_validity(conn, mailbox)
        report['uidvalidity'] = validity
        report['uidnext_boundary'] = uidnext
        apply_generation(state, mailbox, validity, report)
        # 固定UIDNEXT边界：只处理小于边界的UID；UID空洞不视为缺件
        typ, data = conn.uid('SEARCH', None, 'ALL')
        if typ != 'OK':
            raise RoundAbort(f'UID SEARCH失败: {typ}')
        returned = sorted(int(x) for x in (data[0].split() if data and data[0] else []))
        in_scope = [uid for uid in returned if uid < uidnext]
        report['search'] = {'returned': returned, 'in_scope': in_scope,
                            'beyond_boundary': [uid for uid in returned if uid >= uidnext]}
        # 分类：已完成跳过；原文已持久化但索引未完成的重开解析；其余取件
        to_fetch, to_reparse = [], []
        for uid in in_scope:
            ident = Identity(mailbox, validity, uid)
            rec = state['messages'].get(ident.key())
            if rec and rec['status'] in COMPLETE:
                report['already_done'].append(ident.key())
            elif rec and rec.get('raw_key'):
                to_reparse.append((ident, rec))
            else:
                to_fetch.append(ident)
        for ident, rec in to_reparse:
            raw = read_bytes(store.raw_root, rec['raw_key'])
            parse_and_record(store, state, ident, raw, rec, report, max_part_bytes)
            report['reparsed'].append(ident.key())
        for chunk in chunks(to_fetch, chunk_size):
            ensure_generation(conn, mailbox, validity)
            try:
                found = fetch_chunk(conn, [ident.uid for ident in chunk])
            except imaplib.IMAP4.error as exc:
                for ident in chunk:
                    mark_failed(state, ident, f'FETCH失败: {exc}', report)
                continue
            for ident in chunk:
                if ident.uid not in found:
                    mark_failed(state, ident, 'FETCH响应缺少该UID', report)
                    continue
                raw = found[ident.uid]
                rec = state['messages'].get(ident.key()) or new_record(ident)
                state['messages'][ident.key()] = rec
                rec.update(raw_key=save_bytes(store.raw_root, raw), raw_size=len(raw),
                           status='fetched', updated=now_iso())
                created_this_round.append(ident.key())
                report['fetched'].append(ident.key())
                parse_and_record(store, state, ident, raw, rec, report, max_part_bytes)
            requested = {ident.uid for ident in chunk}
            report['unexpected'].extend(sorted(set(found) - requested))
        ensure_generation(conn, mailbox, validity)
    except GenerationChanged as exc:
        # 世代在轮次中变化：本轮新取记录的身份不可靠，撤出索引（旧世代档案不动）
        report['aborted'] = str(exc)
        report['discarded'] = created_this_round
        for key in created_this_round:
            rec = state['messages'].pop(key, None)
            if rec:
                store.clear_materials(
                    Identity(rec['mailbox'], rec['uidvalidity'], rec['uid']))
    except (RoundAbort, imaplib.IMAP4.abort, OSError) as exc:
        report['aborted'] = f'{type(exc).__name__}: {exc}'
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                pass
    pending = []
    for uid in in_scope:
        key = Identity(mailbox, report['uidvalidity'], uid).key()
        rec = state['messages'].get(key)
        if not rec or rec['status'] not in COMPLETE:
            pending.append(key)
    report['pending_after'] = pending
    report['finished'] = now_iso()
    store.save_report(state, report)
    return report


# ---------------------------------------------------------------- 命令行

def cmd_collect(args):
    report = collect_round(Store(args.out), args.host, args.port, args.mailbox,
                           args.user, args.password,
                           max_part_bytes=args.max_part_bytes, chunk_size=args.chunk,
                           timeout=args.timeout)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if report['aborted'] else 0


def cmd_report(args):
    store = Store(args.out)
    state = store.load_state()
    messages = state['messages']
    by_status = {}
    for rec in messages.values():
        by_status[rec['status']] = by_status.get(rec['status'], 0) + 1
    summary = {
        'generations': state['generations'],
        'rounds_run': state['rounds_run'],
        'messages_by_status': by_status,
        'pending': sorted(key for key, rec in messages.items()
                          if rec['status'] not in COMPLETE),
        'bypassed': [{'identity': key,
                      'reason': rec.get('bypass_reason') or
                                '; '.join(p['reason'] for p in rec.get('bypassed_parts', []))}
                     for key, rec in sorted(messages.items()) if rec['status'] == 'bypassed'],
        'reports': sorted(p.name for p in store.reports_root.glob('round-*.json')),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def cmd_replay(args):
    """按身份离线重放：从已持久化的原文重新解析，不连接服务器。"""
    store = Store(args.out)
    state = store.load_state()
    try:
        ident = Identity.parse(args.identity)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    rec = state['messages'].get(ident.key())
    if rec is None:
        print(f'未知身份: {ident.key()}', file=sys.stderr)
        return 1
    if not rec.get('raw_key'):
        print(f'该身份尚无持久化原文: {ident.key()}', file=sys.stderr)
        return 1
    raw = read_bytes(store.raw_root, rec['raw_key'])
    report = {'materials': [], 'bypassed': [], 'failed': []}
    parse_and_record(store, state, ident, raw, rec, report, args.max_part_bytes)
    store.save_state(state)
    out = {'identity': ident.key(), 'status': rec['status'], 'parts': rec['parts'],
           'bypassed_parts': rec['bypassed_parts'], 'bypass_reason': rec.get('bypass_reason'),
           'error': rec.get('error')}
    print(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if rec['status'] in COMPLETE else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='workbench.mailcollect', description='赛务邮箱资料收集端（只读）')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('collect', help='对授权邮箱执行一轮只读收集并输出轮次报告')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--mailbox', default='INBOX')
    p.add_argument('--user', default='demo')
    p.add_argument('--password', default='demo')
    p.add_argument('--out', required=True, help='资料输出目录')
    p.add_argument('--max-part-bytes', type=int, default=DEFAULT_MAX_PART,
                   help='单个部件解码后的字节限额')
    p.add_argument('--chunk', type=int, default=32, help='单次UID FETCH的UID数量')
    p.add_argument('--timeout', type=int, default=10)
    p.set_defaults(func=cmd_collect)
    p = sub.add_parser('report', help='汇总存档状态、世代与待处理集合')
    p.add_argument('--out', required=True)
    p.set_defaults(func=cmd_report)
    p = sub.add_parser('replay', help='按身份离线重放解析（不连接服务器）')
    p.add_argument('--out', required=True)
    p.add_argument('--identity', required=True, help='<邮箱>/<UIDVALIDITY>/<UID>')
    p.add_argument('--max-part-bytes', type=int, default=DEFAULT_MAX_PART)
    p.set_defaults(func=cmd_replay)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
