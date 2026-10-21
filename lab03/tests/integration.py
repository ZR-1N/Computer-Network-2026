"""Real C++ processes, real UDP sockets, independent byte/SHA256 checks.
Python only drives tests and constructs malformed-peer fixtures.
"""
import hashlib
import json
from pathlib import Path
import random
import re
import socket
import struct
import subprocess
import time
import unittest
import uuid
import zlib

ROOT=Path(__file__).resolve().parents[1]
E=ROOT/'evidence'; E.mkdir(exist_ok=True)
CASES=E/'cases';CASES.mkdir(exist_ok=True)
WORK=ROOT/'work';WORK.mkdir(exist_ok=True)
EXE=ROOT/'bin/rudp.exe'
RECORDS=[]

def free_port():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]

def checksum(b):
    b+=b'\0' if len(b)%2 else b''
    total=sum(struct.unpack('!'+str(len(b)//2)+'H',b))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535

def packet(kind,session,size,window=4,seq=0,body=b''):
    b=bytearray(48+len(body))
    struct.pack_into('!IBBHQIIQHHHHQ',b,0,0x52554450,1,kind,48,session,seq,0,0,len(body),window,0,0,size)
    b[48:]=body;struct.pack_into('!H',b,36,checksum(bytes(b)));return bytes(b)

def read_json(path):return json.loads(path.read_text(encoding='utf-8-sig'))

class Process:
    def __init__(self,name,args):
        self.log=CASES/(name+'.txt');self.stats=CASES/(name+'.json')
        self.out=self.log.open('wb')
        self.p=subprocess.Popen([str(EXE),*map(str,args),'--stats',str(self.stats)],stdin=subprocess.PIPE,
                                stdout=self.out,stderr=subprocess.STDOUT)
    def ready(self,text):
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if text in self.log.read_text(encoding='utf-8'):return
            if self.p.poll() is not None:break
            time.sleep(.01)
        raise AssertionError(self.log.read_text(encoding='utf-8'))
    def wait(self,timeout=12):
        try:return self.p.wait(timeout=timeout)
        finally:
            if self.p.poll() is None:self.p.kill();self.p.wait()
            self.out.close();self.p.stdin.close()
    def stop(self):
        if self.p.poll() is None:
            self.p.stdin.write(b'quit\n');self.p.stdin.flush()
        return self.wait()

def transfer(name,data,window=8,chunk=1200,impair=None,success=True,receiver_window=None,extra_sender=None):
    folder=WORK/(name+'-'+uuid.uuid4().hex[:8]);folder.mkdir()
    source=folder/'输入文件.bin';source.write_bytes(data);target=folder/'接收文件.bin'
    port=free_port(); relay_port=free_port()
    receiver=Process(name+'-receiver',['recv','--port',port,'--output',target,'--window',receiver_window or window,
        '--rto-ms',120,'--idle-ms',1800,'--retries',8,'--verbose'])
    relay=None;sender=None
    try:
        receiver.ready('STATE LISTEN')
        if impair is not None:
            relay=Process(name+'-relay',['relay','--port',relay_port,'--target-port',port,'--seconds',30,'--verbose',*impair])
            relay.ready('RELAY_READY')
        sender=Process(name+'-sender',['send','--port',relay_port if relay else port,'--file',source,'--window',window,
            '--chunk',chunk,'--rto-ms',120,'--retries',8,'--verbose',*(extra_sender or [])])
        sc=sender.wait();rc=receiver.wait()
        sm=read_json(sender.stats);rm=read_json(receiver.stats)
        if success:
            assert sc==rc==0,(sc,rc,sm,rm)
            assert target.read_bytes()==data and not Path(str(target)+'.part').exists()
            assert sm['success'] and rm['success']
            assert sm['max_in_flight']<=window and rm['max_buffered']<=window
        else:
            assert sc!=0 and rc!=0,(sc,rc,sm,rm)
            assert not target.exists() and not Path(str(target)+'.part').exists()
        record={'case':name,'success_expected':success,'sender':sm,'receiver':rm,
                'input_sha256':hashlib.sha256(data).hexdigest(),
                'output_sha256':hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None}
        if relay:
            assert relay.stop()==0;record['relay']=read_json(relay.stats)
        RECORDS.append(record)
        return record,sender.log.read_text(encoding='utf-8')
    finally:
        for process in [sender,receiver,relay]:
            if process and process.p.poll() is None:process.p.kill();process.wait()

def manual_receiver(name,data,wrong_crc=False,partial=False,noise=False):
    folder=WORK/(name+'-'+uuid.uuid4().hex[:8]);folder.mkdir();output=folder/'output.bin';port=free_port()
    recv=Process(name+'-receiver',['recv','--port',port,'--output',output,'--window',4,'--idle-ms',400,'--rto-ms',50,'--retries',3])
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.settimeout(2);peer=('127.0.0.1',port)
    session=0x1234567812345678;crc=zlib.crc32(data)^(1 if wrong_crc else 0)
    chunk=3;meta=struct.pack('!HHI',chunk,0,crc)
    def send(kind,seq=0,body=b''):sock.sendto(packet(kind,session,len(data),seq=seq,body=body),peer)
    try:
        recv.ready('STATE LISTEN');send(1,body=meta);assert sock.recv(2048)[5]==2
        send(3,body=meta);assert sock.recv(2048)[5]==5
        if noise:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as foreign:
                foreign.sendto(packet(4,session,len(data),body=data[:3]),peer)
            sock.sendto(packet(4,session+1,len(data),body=data[:3]),peer)
            bad=bytearray(packet(4,session,len(data),body=data[:3]));bad[-1]^=1;sock.sendto(bad,peer)
            send(4,seq=99,body=data[:3])
        count=(len(data)+chunk-1)//chunk
        for seq in range(1 if partial else count):
            send(4,seq,body=data[seq*chunk:(seq+1)*chunk]);assert sock.recv(2048)[5]==5
        if not partial:
            send(6,count,struct.pack('!II',crc,count));reply=sock.recv(2048)
            if wrong_crc:assert reply[5]==9
            else:assert reply[5]==7;send(8)
        code=recv.wait()
        expected=not wrong_crc and not partial
        assert (code==0)==expected
        assert not Path(str(output)+'.part').exists()
        if expected:assert output.read_bytes()==data
        else:assert not output.exists()
        return read_json(recv.stats)
    finally:
        sock.close()
        if recv.p.poll() is None:recv.p.kill();recv.wait()

class Tests(unittest.TestCase):
    def test_01_empty_file(self):transfer('empty',b'',window=1)
    def test_02_odd_and_chunk_boundaries(self):
        for n in (1,1200,1201):transfer('boundary-'+str(n),bytes((i%256 for i in range(n))),window=4)
    def test_03_utf8_and_all_byte_values(self):transfer('utf8',('中文 English\n'*100).encode()+bytes(range(256)))
    def test_04_large_streaming_file(self):
        row,_=transfer('large',random.Random(2026).randbytes(1024*1024),window=16)
        self.assertEqual(row['input_sha256'],row['output_sha256'])
    def test_05_maximum_window(self):
        row,_=transfer('window64',b'a'*80000,window=64)
        self.assertEqual(row['sender']['max_in_flight'],64)
    def test_06_selective_retransmit_only_hole(self):
        row,log=transfer('selective',bytes(range(256))*8,window=8,chunk=256,impair=['--drop-data','2','--delay-ms','2'])
        resent=re.findall(r'RETRANSMIT DATA seq=(\d+)',log)
        self.assertEqual(resent,['2']);self.assertGreater(row['receiver']['out_of_order'],0)
        self.assertRegex(log,r'RECV ACK base=2 sack=0x[1-9a-f]')
    def test_07_last_data_ack_loss(self):
        row,_=transfer('ack-loss',b'b'*1024,window=4,chunk=256,impair=['--drop-ack-base','4'])
        self.assertGreaterEqual(row['sender']['retransmissions'],1);self.assertGreaterEqual(row['receiver']['duplicates'],1)
    def test_08_checksum_corruption(self):
        row,_=transfer('corrupt',b'c'*4096,impair=['--corrupt-data','1'])
        self.assertGreaterEqual(row['receiver']['checksum_errors'],1)
    def test_09_reorder_without_unnecessary_retransmit(self):
        row,_=transfer('reorder',b'r'*2048,window=8,chunk=256,impair=['--delay-data','0','--reorder-ms','60'])
        self.assertEqual(row['sender']['retransmissions'],0);self.assertGreater(row['receiver']['out_of_order'],0)
    def test_10_duplicate_datagrams(self):
        row,_=transfer('duplicate',b'd'*4096,impair=['--duplicate','1','--delay-ms','2'])
        self.assertGreater(row['receiver']['duplicates'],0)
    def test_11_handshake_and_close_recovery(self):
        row,_=transfer('control-loss',b'e'*1024,impair=['--drop-type','SYN:1,SYN_ACK:1,START:1,ACK:1,FIN:1,FIN_ACK:1,CLOSE_ACK:1'])
        self.assertGreaterEqual(row['sender']['control_retries'],4)
    def test_12_combined_random_impairments(self):
        row,_=transfer('random',random.Random(7).randbytes(65537),window=16,
            impair=['--loss','.1','--corrupt','.04','--duplicate','.1','--jitter-ms','8','--delay-ms','2','--seed','13'])
        self.assertGreater(row['sender']['retransmissions'],0)
    def test_13_window_mismatch_rejected(self):transfer('mismatch',b'x',window=4,receiver_window=8,success=False)
    def test_14_exhausted_retry_cleanup(self):transfer('exhausted',b'x'*2400,impair=['--drop-type','DATA:10000'],success=False)
    def test_15_unreachable_peer_bounded_failure(self):
        path=WORK/'unreachable-input.bin';path.write_bytes(b'test')
        process=Process('unreachable-sender',['send','--port',free_port(),'--file',path,'--rto-ms',30,'--retries',2])
        self.assertNotEqual(process.wait(),0);self.assertIn('Retry limit',read_json(process.stats)['error'])
    def test_16_partial_file_timeout_cleanup(self):self.assertFalse(manual_receiver('partial',b'abcdef',partial=True)['success'])
    def test_17_end_to_end_crc_mismatch(self):self.assertIn('CRC32 mismatch',manual_receiver('crc-mismatch',b'abcdef',wrong_crc=True)['error'])
    def test_18_foreign_and_malformed_packets(self):
        row=manual_receiver('foreign',b'abcdef',noise=True)
        self.assertGreaterEqual(row['foreign_packets'],2);self.assertGreaterEqual(row['checksum_errors'],1)
    def test_19_existing_output_preserved(self):
        path=WORK/'keep-existing.txt';path.write_bytes(b'KEEP')
        p=Process('existing-receiver',['recv','--output',path,'--port',free_port()])
        self.assertNotEqual(p.wait(),0);self.assertEqual(path.read_bytes(),b'KEEP')
    def test_20_invalid_arguments(self):
        for args in (['send','--window','0'],['send','--window','65'],['send','--rto-ms','1'],['send','--file','missing-file'],['send','--unknown','x']):
            p=subprocess.run([str(EXE),*args],capture_output=True,timeout=5);self.assertNotEqual(p.returncode,0)

if __name__=='__main__':
    start=time.monotonic()
    unit=subprocess.run([str(ROOT/'bin/protocol_tests.exe')],capture_output=True,timeout=10)
    (E/'protocol-tests.txt').write_text(unit.stdout.decode('utf-8').replace('\r\n','\n'),encoding='utf-8')
    if unit.returncode:raise SystemExit(unit.returncode)
    with (E/'integration-tests.txt').open('w',encoding='utf-8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    report={'time':time.strftime('%Y-%m-%d %H:%M:%S %z'),'protocol_tests':32,'integration_tests':result.testsRun,
        'failures':len(result.failures),'errors':len(result.errors),'elapsed_seconds':round(time.monotonic()-start,3),'transfers':RECORDS}
    (E/'results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print((E/'integration-tests.txt').read_text(encoding='utf-8'));print('Transfers verified:',len(RECORDS))
    raise SystemExit(not result.wasSuccessful())
