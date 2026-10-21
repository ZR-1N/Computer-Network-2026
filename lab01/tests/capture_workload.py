"""Short, fixed-port chat workload for an independently recorded packet trace."""
from integration import ROOT, EVIDENCE, Peer
import subprocess
import time

if __name__ == '__main__':
    peers=[]
    with open(EVIDENCE/'capture-server.txt','wb') as log:
        server=subprocess.Popen([str(ROOT/'bin/chat_server.exe'),'127.0.0.1','9001'],
                                stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT)
        try:
            time.sleep(.5)
            if server.poll() is not None: raise RuntimeError('Port 9001 unavailable')
            for name in ['CaptureA','CaptureB','CaptureC']: peers.append(Peer(9001,name))
            for i in range(20):
                peers[0].send(3,f'抓包验证-{i:02d}-Hello TCP')
                for p in peers: assert p.until(4)[2].endswith(f'抓包验证-{i:02d}-Hello TCP')
            for p in peers:
                p.send(9); assert p.until(10)[0]==10; p.close()
            print('capture workload: 20 messages, 60 verified deliveries')
        finally:
            for p in peers: p.close()
            if server.poll() is None:
                server.stdin.write(b'/quit\n'); server.stdin.flush()
            server.wait(timeout=10); server.stdin.close()
