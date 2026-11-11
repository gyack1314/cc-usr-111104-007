"""本地只读IMAP资料源，支持标准库imaplib的基础命令。"""
import argparse,json,re,socketserver,threading
from pathlib import Path
def start(config,port=0):
    config=Path(config)
    class Handler(socketserver.StreamRequestHandler):
        def emit(self,b):self.wfile.write(b+b'\r\n');self.wfile.flush()
        def handle(self):
            self.emit(b'* OK synthetic source ready')
            while True:
                raw=self.rfile.readline()
                if not raw:return
                parts=raw.decode('ascii').strip().split(' ',2)
                if len(parts)<2:return
                tag,cmd=parts[:2];arg=parts[2] if len(parts)>2 else '';cmd=cmd.upper()
                box=json.loads(config.read_text(encoding='utf8'))
                if cmd=='CAPABILITY':self.emit(b'* CAPABILITY IMAP4rev1')
                elif cmd=='LOGIN':pass
                elif cmd=='EXAMINE':
                    self.emit(f"* {len(box['messages'])} EXISTS".encode())
                    self.emit(f"* OK [UIDVALIDITY {box['uidvalidity']}] epoch".encode())
                    self.emit(f"* OK [UIDNEXT {box['uidnext']}] next".encode())
                    self.emit(b'* FLAGS (\\Seen)')
                elif cmd=='UID':
                    op,_,tail=arg.partition(' ')
                    if op.upper()=='SEARCH':
                        self.emit(('* SEARCH '+' '.join(sorted(box['messages'],key=int))).encode())
                    elif op.upper()=='FETCH':
                        wanted=tail.split(' ',1)[0];selected=[]
                        for uid in sorted(box['messages'],key=int):
                            for part in wanted.split(','):
                                lo,sep,hi=part.partition(':'); high=int(hi) if sep and hi!='*' else (box['uidnext']-1 if sep else int(lo))
                                if int(lo)<=int(uid)<=high:selected.append(uid);break
                        if box.get('reverse_fetch'):selected.reverse()
                        if box.get('unsolicited'):self.emit(b'* 999 EXISTS')
                        for uid in selected:
                            data=(config.parent/box['messages'][uid]).read_bytes()
                            self.emit(f'* {list(sorted(box["messages"],key=int)).index(uid)+1} FETCH (UID {uid} BODY[] {{{len(data)}}}'.encode())
                            self.wfile.write(data+b')\r\n');self.wfile.flush()
                    else:self.emit(f'{tag} BAD unsupported UID command'.encode());continue
                elif cmd=='LOGOUT':self.emit(b'* BYE closing');self.emit(f'{tag} OK logout'.encode());return
                elif cmd=='NOOP':pass
                else:self.emit(f'{tag} BAD read-only command not supported'.encode());continue
                self.emit(f'{tag} OK completed'.encode())
    s=socketserver.ThreadingTCPServer(('127.0.0.1',port),Handler);s.daemon_threads=True
    threading.Thread(target=s.serve_forever,daemon=True).start();return s
def main():
    p=argparse.ArgumentParser();p.add_argument('config');p.add_argument('--port',type=int,default=8143);a=p.parse_args();s=start(a.config,a.port)
    print(s.server_address[1],flush=True)
    try:threading.Event().wait()
    except KeyboardInterrupt:pass
    finally:s.shutdown();s.server_close()
if __name__=='__main__':main()
