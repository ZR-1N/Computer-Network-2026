"""Black-box tests against the actual Windows C++ executables.
Python is a test driver only; the delivered chat implementation is C++.
"""
import concurrent.futures
import json
from pathlib import Path
import platform
import socket
import struct
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'evidence'
EVIDENCE.mkdir(exist_ok=True)
METRICS = {}

def packet(kind, seq, body=b''):
    if isinstance(body, str):
        body = body.encode('utf-8')
    return struct.pack('!IHHII', 0x434e4554, 1, kind, len(body), seq) + body

class Peer:
    def __init__(self, port, name=None):
        self.s = socket.create_connection(('127.0.0.1', port), timeout=8)
        self.seq = 1
        if name is not None:
            self.send(1, name)
            assert self.read()[0] == 2
    def exact(self, n):
        b = b''
        while len(b) < n:
            p = self.s.recv(n-len(b))
            if not p:
                raise EOFError('connection closed')
            b += p
        return b
    def read(self):
        magic, version, kind, length, seq = struct.unpack('!IHHII', self.exact(16))
        assert magic == 0x434e4554 and version == 1 and length <= 16384
        return kind, seq, self.exact(length).decode('utf-8')
    def until(self, kind):
        for _ in range(20000):
            f = self.read()
            if f[0] == kind:
                return f
        raise AssertionError('missing frame')
    def send(self, kind, body=''):
        self.s.sendall(packet(kind, self.seq, body))
        self.seq += 1
    def close(self):
        self.s.close()

class ChatTest(unittest.TestCase):
    def setUp(self):
        probe = socket.socket(); probe.bind(('127.0.0.1', 0))
        self.port = probe.getsockname()[1]; probe.close()
        self.log = open(EVIDENCE / f'{self._testMethodName}-server.txt', 'wb')
        self.server = subprocess.Popen([str(ROOT/'bin/chat_server.exe'), '127.0.0.1', str(self.port)],
                                       stdin=subprocess.PIPE, stdout=self.log, stderr=subprocess.STDOUT)
        self.peers = []
        deadline = time.monotonic()+5
        while True:
            try:
                p = self.peer(); p.close(); break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.03)
    def peer(self, name=None):
        p = Peer(self.port, name); self.peers.append(p); return p
    def stop(self):
        if self.server.poll() is None:
            self.server.stdin.write(b'/quit\n'); self.server.stdin.flush()
        self.server.wait(timeout=12)
    def tearDown(self):
        for p in self.peers:
            p.close()
        try:
            self.stop()
        finally:
            if self.server.poll() is None:
                self.server.kill(); self.server.wait()
            self.server.stdin.close(); self.log.close()
        self.assertEqual(self.server.returncode, 0)

    def test_01_bilingual_broadcast_and_list(self):
        a, b, c = self.peer('小明'), self.peer('Alice'), self.peer('小红')
        for text in ['你好，网络！ Hello TCP 🌍', 'English message']:
            a.send(3, text)
            for p in [a,b,c]:
                self.assertTrue(p.until(4)[2].endswith('小明\n'+text))
        c.send(7)
        self.assertEqual(set(c.until(8)[2].split('\n')[1].split()), {'小明','Alice','小红'})

    def test_02_private_isolation(self):
        a,b,c = self.peer('Alice'),self.peer('Bob'),self.peer('Carol')
        c.send(7); c.until(8)  # consume all earlier notices
        a.send(5, 'Bob\n秘密 hello')
        for p in [a,b]:
            self.assertTrue(p.until(6)[2].endswith('Alice\nBob\n秘密 hello'))
        c.s.settimeout(.25)
        with self.assertRaises(socket.timeout): c.read()
        a.send(5, 'Nobody\nhello'); self.assertIn('不在线', a.until(12)[2])

    def test_03_fragmentation_and_coalescing(self):
        a = self.peer()
        for byte in packet(1,1,'分片昵称'): a.s.sendall(bytes([byte]))
        a.seq=2; self.assertEqual(a.read()[0],2)
        a.s.sendall(packet(3,2,'第一条')+packet(3,3,'second')+packet(7,4))
        self.assertTrue(a.until(4)[2].endswith('第一条'))
        self.assertTrue(a.until(4)[2].endswith('second'))
        self.assertEqual(a.until(8)[2].split('\n')[1], '分片昵称')

    def test_04_duplicate_and_reuse(self):
        a = self.peer('Alice'); b=self.peer(); b.send(1,'Alice')
        self.assertIn('already in use',b.until(12)[2])
        a.send(9); self.assertEqual(a.until(10)[0],10)
        with self.assertRaises(EOFError): a.read()
        self.peer('Alice')

    def test_05_malformed_headers(self):
        invalid = [struct.pack('!IHHII', 0,1,1,0,1),
                   struct.pack('!IHHII', 0x434e4554,2,1,0,1),
                   struct.pack('!IHHII', 0x434e4554,1,99,0,1),
                   struct.pack('!IHHII', 0x434e4554,1,1,16385,1), packet(1,1,b'\xff')]
        for data in invalid:
            p=self.peer(); p.s.sendall(data)
            self.assertEqual(p.until(12)[0],12)
            with self.assertRaises(EOFError): p.read()

    def test_06_sequence_and_direction(self):
        p=self.peer('Sequence'); p.s.sendall(packet(3,9,'bad'))
        self.assertIn('sequence',p.until(12)[2])
        p=self.peer('Direction'); p.send(4,'bad')
        self.assertEqual(p.until(12)[0],12)

    def test_07_message_boundaries_and_recovery(self):
        p=self.peer('Boundaries')
        for text in ['', 'x'*4097, 'bad\nline']:
            p.send(3,text); self.assertEqual(p.until(12)[0],12)
        text='中'*1365+'a'  # exactly 4096 UTF-8 bytes
        p.send(3,text); self.assertTrue(p.until(4)[2].endswith(text))

    def test_08_abrupt_disconnect(self):
        a,b=self.peer('Abrupt'),self.peer('Observer')
        a.close(); self.assertIn('Abrupt 离线',b.until(11)[2]); self.peer('Abrupt')

    def test_09_handshake_timeout_and_truncated_frame(self):
        p=self.peer(); start=time.monotonic(); p.s.sendall(b'C')
        with self.assertRaises(EOFError): p.read()
        self.assertLess(time.monotonic()-start,7)
        p=self.peer('Truncated'); p.s.sendall(packet(3,2,'hello')[:-2]); p.s.shutdown(socket.SHUT_WR)
        with self.assertRaises(EOFError): p.read()

    def test_10_concurrent_integrity(self):
        count, n = 300, 4
        peers=[self.peer(f'User{i}') for i in range(n)]
        expected={f'User{i}\n消息-{i}-{j:04d}-Hello' for i in range(n) for j in range(count)}
        def receive(p):
            received=[]
            while len(received)<count*n:
                f=p.read()
                if f[0]==4: received.append(f[2].split('\n',1)[1])
            self.assertEqual(len(set(received)),count*n)
            self.assertEqual(set(received),expected)
            return received
        def send(i):
            for j in range(count): peers[i].send(3,f'消息-{i}-{j:04d}-Hello')
        start=time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            readers=[ex.submit(receive,p) for p in peers]
            writers=[ex.submit(send,i) for i in range(n)]
            for f in writers: f.result(timeout=30)
            results=[f.result(timeout=30) for f in readers]
        self.assertTrue(all(r==results[0] for r in results))
        METRICS.update(clients=n, messages_sent=count*n, deliveries_expected=count*n*n,
                       deliveries_received=sum(map(len,results)), missing=0, duplicates=0,
                       elapsed_seconds=round(time.monotonic()-start,3))

    def test_11_real_client_chinese_and_commands(self):
        p=subprocess.Popen([str(ROOT/'bin/chat_client.exe'),'127.0.0.1',str(self.port),'客户端小明'],
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        out,_=p.communicate('你好 Hello\n/list\n/msg 客户端小明 自己的私聊\n/quit\n'.encode(),timeout=10)
        text=out.decode('utf-8').replace('\r\n','\n'); (EVIDENCE/'client-transcript.txt').write_text(text,encoding='utf-8')
        self.assertEqual(p.returncode,0)
        for expected in ['欢迎 客户端小明','你好 Hello','自己的私聊','正常退出','客户端已退出']:
            self.assertIn(expected,text)

    def test_12_server_shutdown_unblocks_idle_client(self):
        p=subprocess.Popen([str(ROOT/'bin/chat_client.exe'),'127.0.0.1',str(self.port),'Idle'],
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        try:
            time.sleep(.3); self.stop(); p.wait(timeout=5)
            text=p.stdout.read().decode('utf-8'); self.assertIn('服务器关闭',text); self.assertEqual(p.returncode,0)
        finally:
            if p.poll() is None: p.kill(); p.wait()
            p.stdin.close(); p.stdout.close()

    def test_13_repeated_connect_quit(self):
        for i in range(80):
            p=self.peer('Reused')
            p.send(9); self.assertEqual(p.until(10)[0],10)
            with self.assertRaises(EOFError): p.read()
            p.close()

    def test_14_connection_capacity(self):
        # 64 active sessions are accepted; the next connection is closed promptly.
        peers=[self.peer(f'Capacity{i}') for i in range(64)]
        extra=self.peer()
        with self.assertRaises(EOFError): extra.read()
        self.assertEqual(len(peers),64)

if __name__ == '__main__':
    start=time.time()
    with open(EVIDENCE/'test-results.txt','w',encoding='utf-8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ChatTest))
    report={'time':time.strftime('%Y-%m-%d %H:%M:%S %z'), 'os':platform.platform(),
            'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
            'duration_seconds':round(time.time()-start,3),'stress':METRICS}
    (EVIDENCE/'results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print((EVIDENCE/'test-results.txt').read_text(encoding='utf-8'))
    print(json.dumps(report,ensure_ascii=False,indent=2))
    raise SystemExit(not result.wasSuccessful())
