"""核对邮件材料收集端：乱序FETCH、世代切换、嵌套邮件、编码文件名与UID空洞。"""
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from source_lab.imap import start
from workbench import mailcollect
from workbench.mailcollect import (Bypass, Identity, Store, collect_round,
                                   encode_mailbox, parse_message)

SOURCES = Path('sources')


def copy_box(tmp):
    for eml in ('mail-a.eml', 'mail-b.eml', 'mail-bad.eml'):
        shutil.copy(SOURCES / eml, Path(tmp) / eml)
    cfg = Path(tmp) / 'box.json'
    shutil.copy(SOURCES / 'mailbox.json', cfg)
    return cfg


def make_message(headers, body=b'x\n'):
    return b'\n'.join(headers) + b'\n\n' + body


ATTACH = b'Content-Disposition: attachment; filename="a.bin"'
OCTET = b'Content-Type: application/octet-stream'


class RoundTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = copy_box(self.tmp.name)
        self.server = start(self.cfg)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.port = self.server.server_address[1]
        self.out = Path(self.tmp.name) / 'out'

    def collect(self, **kw):
        return collect_round(Store(self.out), '127.0.0.1', self.port,
                             'INBOX', 'demo', 'demo', **kw)

    def load_state(self):
        return json.loads((self.out / 'state.json').read_text(encoding='utf-8'))

    def test_round_associates_by_uid_and_ignores_holes(self):
        report = self.collect()
        self.assertIsNone(report['aborted'])
        self.assertEqual(report['uidvalidity'], 700)
        self.assertEqual(report['uidnext_boundary'], 12)
        # UID空洞（3-6,8-10）不是缺件：范围内只有搜索到的2,7,11
        self.assertEqual(report['search']['in_scope'], [2, 7, 11])
        self.assertEqual(report['search']['beyond_boundary'], [])
        self.assertEqual(report['pending_after'], [])
        self.assertEqual(sorted(report['fetched']),
                         ['INBOX/700/11', 'INBOX/700/2', 'INBOX/700/7'])
        # 服务器乱序返回且穿插EXISTS，材料仍按UID归位
        part = (self.out / 'materials/INBOX/700/2/part-2').read_bytes()
        self.assertEqual(part, b'robot-data')
        # inline图片不进入材料目录
        self.assertFalse((self.out / 'materials/INBOX/700/2/part-3').exists())
        # 三封原文都按摘要留存
        self.assertEqual(len(list((self.out / 'raw').iterdir())), 3)
        state = self.load_state()
        self.assertEqual(set(state['messages']),
                         {'INBOX/700/2', 'INBOX/700/7', 'INBOX/700/11'})
        # Message-ID重复也只作元数据，两封都独立建档
        self.assertEqual(state['messages']['INBOX/700/2']['message_id'],
                         '<shared@example.invalid>')
        self.assertEqual(state['messages']['INBOX/700/11']['message_id'],
                         '<shared@example.invalid>')
        rec = state['messages']['INBOX/700/2']
        self.assertEqual(rec['status'], 'parsed')
        self.assertEqual(rec['parts'][0]['filename'], '机器人资料.bin')
        self.assertEqual(rec['parts'][0]['stored_as'],
                         'materials/INBOX/700/2/part-2')
        self.assertEqual(rec['skipped_non_attachment'], 2)  # 正文+inline图片
        # 轮次报告已落盘
        saved = json.loads((self.out / report['report_file']).read_text(encoding='utf-8'))
        self.assertEqual(saved['round'], 1)

    def test_embedded_message_kept_whole(self):
        self.collect()
        src = (SOURCES / 'mail-b.eml').read_bytes()
        begin = src.index(b'From: source@example.invalid')
        end = src.index(b'--synthetic-nested-boundary--')
        stored = (self.out / 'materials/INBOX/700/7/part-2').read_bytes()
        # message/rfc822附件保留原始内容，其中附件不重复导入
        self.assertEqual(stored, src[begin:end])
        files = sorted(p.name for p in (self.out / 'materials/INBOX/700/7').iterdir())
        self.assertEqual(files, ['part-2'])
        rec = self.load_state()['messages']['INBOX/700/7']
        self.assertEqual(rec['parts'][0]['content_type'], 'message/rfc822')

    def test_bad_base64_bypassed_but_raw_kept(self):
        report = self.collect()
        rec = self.load_state()['messages']['INBOX/700/11']
        self.assertEqual(rec['status'], 'bypassed')
        self.assertEqual(rec['parts'], [])
        self.assertIn('base64', rec['bypassed_parts'][0]['reason'])
        self.assertFalse((self.out / 'materials/INBOX/700/11').exists())
        # 原始邮件仍可留存并核验
        raw = mailcollect.read_bytes(self.out / 'raw', rec['raw_key'])
        self.assertEqual(raw, (SOURCES / 'mail-bad.eml').read_bytes())
        reasons = [b['reason'] for b in report['bypassed']
                   if b['identity'] == 'INBOX/700/11']
        self.assertTrue(any('base64' in r for r in reasons))

    def test_uidnext_boundary(self):
        box = json.loads(self.cfg.read_text(encoding='utf-8'))
        box['uidnext'] = 8
        self.cfg.write_text(json.dumps(box), encoding='utf-8')
        report = self.collect()
        self.assertEqual(report['search']['in_scope'], [2, 7])
        self.assertEqual(report['search']['beyond_boundary'], [11])
        self.assertNotIn('INBOX/700/11', self.load_state()['messages'])

    def test_generation_rollover_keeps_old_archive(self):
        first = self.collect()
        self.assertEqual(first['uidvalidity'], 700)
        # 切换世代：同一UID在新UIDVALIDITY下是新邮件
        self.cfg.write_text(json.dumps({
            'uidvalidity': 701, 'uidnext': 3,
            'messages': {'2': 'mail-b.eml'},
        }), encoding='utf-8')
        second = self.collect()
        self.assertIsNone(second['aborted'])
        self.assertEqual(second['uidvalidity'], 701)
        self.assertEqual(second['generation_events'][0]['event'], 'rollover')
        self.assertEqual(second['fetched'], ['INBOX/701/2'])
        state = self.load_state()
        self.assertEqual(state['generations']['INBOX']['current'], 701)
        self.assertEqual(len(state['generations']['INBOX']['history']), 2)
        # 旧世代档案保留，新世代独立取件
        self.assertTrue((self.out / 'materials/INBOX/700/2/part-2').exists())
        self.assertTrue((self.out / 'materials/INBOX/701/2/part-2').exists())
        self.assertIn('INBOX/700/2', state['messages'])
        self.assertIn('INBOX/701/2', state['messages'])

    def test_resume_reparses_without_refetch(self):
        self.collect()
        state = self.load_state()
        rec = state['messages']['INBOX/700/2']
        rec['status'] = 'fetched'  # 模拟原文已持久化但附件索引未完成
        rec['parts'] = []
        (self.out / 'state.json').write_text(json.dumps(state), encoding='utf-8')
        shutil.rmtree(self.out / 'materials/INBOX/700/2')
        report = self.collect()
        self.assertIn('INBOX/700/2', report['reparsed'])
        self.assertEqual(report['fetched'], [])
        part = (self.out / 'materials/INBOX/700/2/part-2').read_bytes()
        self.assertEqual(part, b'robot-data')
        self.assertEqual(self.load_state()['messages']['INBOX/700/2']['status'],
                         'parsed')

    def test_failure_stays_pending_and_recovers(self):
        original = mailcollect.parse_message

        def flaky(raw, limit):
            if b'synthetic-nested-boundary' in raw:
                raise RuntimeError('injected failure')
            return original(raw, limit)

        mailcollect.parse_message = flaky
        try:
            report = self.collect()
        finally:
            mailcollect.parse_message = original
        # 单封失败不卡死后续UID，也不从待处理集合消失
        self.assertIsNone(report['aborted'])
        self.assertEqual(report['pending_after'], ['INBOX/700/7'])
        self.assertEqual(self.load_state()['messages']['INBOX/700/7']['status'], 'failed')
        self.assertTrue((self.out / 'materials/INBOX/700/2/part-2').exists())
        recovered = self.collect()
        self.assertIn('INBOX/700/7', recovered['reparsed'])
        self.assertNotIn('INBOX/700/7', recovered['fetched'])
        self.assertEqual(recovered['pending_after'], [])
        self.assertEqual(self.load_state()['messages']['INBOX/700/7']['status'],
                         'parsed')

    def test_replay_command_rebuilds_materials_offline(self):
        self.collect()
        shutil.rmtree(self.out / 'materials/INBOX/700/2')
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = mailcollect.main(['replay', '--out', str(self.out),
                                   '--identity', 'INBOX/700/2'])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out['status'], 'parsed')
        self.assertEqual(out['parts'][0]['filename'], '机器人资料.bin')
        self.assertEqual((self.out / 'materials/INBOX/700/2/part-2').read_bytes(),
                         b'robot-data')
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = mailcollect.main(['replay', '--out', str(self.out),
                                   '--identity', 'INBOX/700/99'])
        self.assertEqual(rc, 1)

    def test_cli_collect_and_report(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = mailcollect.main(['collect', '--port', str(self.port),
                                   '--out', str(self.out)])
        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report['round'], 1)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = mailcollect.main(['report', '--out', str(self.out)])
        self.assertEqual(rc, 0)
        summary = json.loads(buf.getvalue())
        self.assertEqual(summary['pending'], [])
        self.assertEqual(summary['bypassed'][0]['identity'], 'INBOX/700/11')
        self.assertEqual(summary['messages_by_status'],
                         {'bypassed': 1, 'parsed': 2})


class MimeTests(unittest.TestCase):
    def parts(self, raw, limit=1024):
        return parse_message(raw, limit)

    def test_rfc2231_continuation_join(self):
        raw = make_message([
            OCTET,
            b"Content-Disposition: attachment; filename*0*=utf-8''%E6%9C%BA;",
            b' filename*1*=%E5%99%A8',
            b'Content-Transfer-Encoding: 7bit',
        ])
        parts, bypassed, _, _ = self.parts(raw)
        self.assertEqual(bypassed, [])
        self.assertEqual(parts[0].filename, '机器')
        self.assertEqual(parts[0].path, '1')

    def test_continuation_plain_and_mixed(self):
        raw = make_message([
            OCTET,
            b'Content-Disposition: attachment; filename*0="ab"; filename*1="c"',
        ])
        parts, _, _, _ = self.parts(raw)
        self.assertEqual(parts[0].filename, 'abc')
        raw = make_message([
            OCTET,
            b"Content-Disposition: attachment; filename*0*=utf-8''%E6%9C;",
            b' filename*1*=%BA',
        ])
        parts, _, _, _ = self.parts(raw)
        self.assertEqual(parts[0].filename, '机')
        # 非编码续段是字面文本，不做百分号解码
        raw = make_message([
            OCTET,
            b"Content-Disposition: attachment; filename*0*=utf-8''%E6%9C;",
            b' filename*1=%BA',
        ])
        _, bypassed, _, _ = self.parts(raw)
        self.assertEqual(len(bypassed), 1)

    def test_continuation_duplicate_and_gap_bypassed(self):
        for disp in (b"Content-Disposition: attachment; filename*0*=utf-8''a;"
                     b' filename*0*=utf-8\'\'b',
                     b"Content-Disposition: attachment; filename*0*=utf-8''a;"
                     b' filename*2*=utf-8\'\'b'):
            _, bypassed, _, _ = self.parts(make_message([OCTET, disp]))
            self.assertEqual(len(bypassed), 1)
            self.assertIn('续段', bypassed[0]['reason'])

    def test_plain_extended_conflict(self):
        raw = make_message([
            OCTET,
            b"Content-Disposition: attachment; filename=\"a.txt\";"
            b" filename*=utf-8''b.txt",
        ])
        _, bypassed, _, _ = self.parts(raw)
        self.assertIn('冲突', bypassed[0]['reason'])
        raw = make_message([
            OCTET,
            b"Content-Disposition: attachment; filename=\"a.txt\";"
            b" filename*=utf-8''a.txt",
        ])
        parts, bypassed, _, _ = self.parts(raw)
        self.assertEqual(bypassed, [])
        self.assertEqual(parts[0].filename, 'a.txt')

    def test_dangerous_filenames_bypassed(self):
        names = [b'filename="../x"', b'filename=".."', b'filename="."',
                 b'filename="a/b"', b'filename="a\\\\b"', b'filename="a\x00b"',
                 b"filename*=utf-8''..%2F"]
        for name in names:
            raw = make_message([OCTET, b'Content-Disposition: attachment; ' + name])
            _, bypassed, _, _ = self.parts(raw)
            self.assertEqual(len(bypassed), 1, name)

    def test_bad_extended_param_bypassed(self):
        for name in (b"filename*=utf-8''%ZZ", b"filename*=klingon''abc",
                     b"filename*=''abc"):
            raw = make_message([OCTET, b'Content-Disposition: attachment; ' + name])
            _, bypassed, _, _ = self.parts(raw)
            self.assertEqual(len(bypassed), 1, name)

    def test_base64_strict(self):
        def run(body):
            raw = make_message([OCTET, ATTACH,
                                b'Content-Transfer-Encoding: base64'], body)
            return self.parts(raw)
        parts, bypassed, _, _ = run(b'cm9i b3Qt\nZGF0YQ==\n')
        self.assertEqual(bypassed, [])
        self.assertEqual(parts[0].data, b'robot-data')
        for body in (b'@@invalid-base64@@', b'====', b'abc', b'Zg==Zg=='):
            _, bypassed, _, _ = run(body)
            self.assertEqual(len(bypassed), 1, body)

    def test_quoted_printable_strict(self):
        def run(body):
            raw = make_message([OCTET, ATTACH,
                                b'Content-Transfer-Encoding: quoted-printable'],
                               body)
            return self.parts(raw)
        parts, _, _, _ = run(b'a=0Ab\n')
        self.assertEqual(parts[0].data, b'a\nb\n')
        parts, _, _, _ = run(b'ab=\ncd\n')
        self.assertEqual(parts[0].data, b'abcd\n')
        for body in (b'a=ZZ', b'a=', b'a\x80b'):
            _, bypassed, _, _ = run(body)
            self.assertEqual(len(bypassed), 1, body)

    def test_cte_rejected(self):
        for headers in (
            [OCTET, ATTACH, b'Content-Transfer-Encoding: x-uue'],
            [OCTET, ATTACH, b'Content-Transfer-Encoding: 7bit',
             b'Content-Transfer-Encoding: 7bit'],
        ):
            _, bypassed, _, _ = self.parts(make_message(headers))
            self.assertEqual(len(bypassed), 1, headers)
        raw = make_message([OCTET, ATTACH, b'Content-Transfer-Encoding: 7bit'],
                           b'a\x80b')
        _, bypassed, _, _ = self.parts(raw)
        self.assertIn('8bit', bypassed[0]['reason'])

    def test_size_limit(self):
        raw = make_message([OCTET, ATTACH], b'12345')
        _, bypassed, _, _ = self.parts(raw, limit=3)
        self.assertIn('限额', bypassed[0]['reason'])
        raw = make_message([OCTET, ATTACH, b'Content-Transfer-Encoding: base64'],
                           b'MTIzNDU=')
        _, bypassed, _, _ = self.parts(raw, limit=3)
        self.assertIn('限额', bypassed[0]['reason'])

    def test_nested_multipart_paths(self):
        raw = make_message([
            b'Content-Type: multipart/mixed; boundary="A"',
        ], b'--A\nContent-Type: text/plain\n\nhello\n'
           b'--A\nContent-Type: multipart/alternative; boundary="B"\n\n'
           b'--B\nContent-Type: text/plain\n\ninner\n'
           b'--B\nContent-Type: application/pdf\n'
           b'Content-Disposition: attachment; filename="d.pdf"\n\nPDFDATA\n'
           b'--B--\n--A--\n')
        parts, bypassed, _, skipped = self.parts(raw)
        self.assertEqual(bypassed, [])
        self.assertEqual([(p.path, p.data) for p in parts],
                         [('2.2', b'PDFDATA\n')])
        self.assertEqual(skipped, 2)

    def test_inline_rfc822_descends(self):
        inner = (b'Subject: i\nContent-Type: multipart/mixed; boundary="C"\n\n'
                 b'--C\nContent-Type: text/plain\n\ny\n'
                 b'--C\nContent-Type: application/octet-stream\n'
                 b'Content-Disposition: attachment; filename="i.bin"\n\nINNER\n'
                 b'--C--\n')
        raw = make_message([
            b'Content-Type: multipart/mixed; boundary="A"',
        ], b'--A\nContent-Type: text/plain\n\nx\n'
           b'--A\nContent-Type: message/rfc822\n\n' + inner + b'--A--\n')
        parts, _, _, _ = self.parts(raw)
        self.assertEqual([(p.path, p.data) for p in parts],
                         [('2.1.2', b'INNER\n')])

    def test_rfc822_attachment_kept_whole(self):
        inner = (b'Subject: i\nContent-Type: application/octet-stream\n'
                 b'Content-Disposition: attachment; filename="i.bin"\n\nINNER\n')
        raw = make_message([
            b'Content-Type: multipart/mixed; boundary="A"',
        ], b'--A\nContent-Type: text/plain\n\nx\n'
           b'--A\nContent-Type: message/rfc822\n'
           b'Content-Disposition: attachment\n\n' + inner + b'--A--\n')
        parts, bypassed, _, _ = self.parts(raw)
        self.assertEqual(bypassed, [])
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0].path, '2')
        self.assertEqual(parts[0].content_type, 'message/rfc822')
        self.assertEqual(parts[0].data, inner)

    def test_structural_defects_raise_bypass(self):
        raw = make_message([b'Content-Type: multipart/mixed'], b'--A\n\nx\n')
        with self.assertRaises(Bypass):
            self.parts(raw)
        raw = make_message([b'Content-Type: multipart/mixed; boundary="A"'],
                           b'--A\nContent-Type: text/plain\n\nx\n')
        with self.assertRaises(Bypass):
            self.parts(raw)

    def test_name_param_fallback(self):
        raw = make_message([
            b'Content-Type: application/octet-stream; name="n.bin"',
            b'Content-Disposition: attachment',
        ])
        parts, _, _, _ = self.parts(raw)
        self.assertEqual(parts[0].filename, 'n.bin')

    def test_inline_and_plain_leaves_skipped(self):
        raw = make_message([
            b'Content-Type: multipart/mixed; boundary="A"',
        ], b'--A\nContent-Type: text/plain\n\nx\n'
           b'--A\nContent-Type: image/png\n'
           b'Content-Disposition: inline; filename="p.png"\n\nPNG\n'
           b'--A--\n')
        parts, _, _, skipped = self.parts(raw)
        self.assertEqual(parts, [])
        self.assertEqual(skipped, 2)


class IdentityTests(unittest.TestCase):
    def test_identity_roundtrip(self):
        ident = Identity.parse('INBOX/700/2')
        self.assertEqual(ident.key(), 'INBOX/700/2')
        ident = Identity.parse('A/B/701/9')
        self.assertEqual((ident.mailbox, ident.uidvalidity, ident.uid),
                         ('A/B', 701, 9))
        with self.assertRaises(ValueError):
            Identity.parse('700/2')

    def test_mailbox_encoding_safe(self):
        self.assertEqual(encode_mailbox('INBOX'), 'INBOX')
        self.assertNotIn('/', encode_mailbox('a/b'))
        self.assertNotIn('..', encode_mailbox('..'))


if __name__ == '__main__':
    unittest.main()
