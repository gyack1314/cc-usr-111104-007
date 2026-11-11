"""检查只读邮箱的UID与原始literal传输。"""
import imaplib,unittest
from source_lab.imap import start
class MailTests(unittest.TestCase):
    def test_wire(self):
        s=start('sources/mailbox.json')
        try:
            with imaplib.IMAP4(*s.server_address,timeout=3) as c:
                self.assertEqual(c.login('demo','demo')[0],'OK')
                self.assertEqual(c.select('INBOX',readonly=True)[0],'OK')
                self.assertEqual(c.response('UIDVALIDITY')[1],[b'700'])
                self.assertEqual(c.uid('SEARCH',None,'ALL')[1],[b'2 7 11'])
                status,rows=c.uid('FETCH','2,7','(UID BODY.PEEK[])')
                literals=[x for x in rows if isinstance(x,tuple)]
                self.assertEqual(status,'OK');self.assertEqual(len(literals),2)
                self.assertIn(b'UID 7',literals[0][0]);self.assertIn(b'UID 2',literals[1][0])
        finally:s.shutdown();s.server_close()
