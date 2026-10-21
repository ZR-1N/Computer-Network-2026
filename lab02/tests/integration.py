"""Tests drive the actual C++ executable; Python is not the capture implementation.
Synthetic fixtures are clearly separated from the real Npcap ICMP capture.
"""
import json
from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
E=ROOT/'evidence'; E.mkdir(exist_ok=True)
EXE=ROOT/'bin/packet_capture.exe'
NET=json.loads((E/'network-info.json').read_text(encoding='utf-8-sig'))
METRICS={}

def execute(*args, expected=0):
    p=subprocess.run([str(EXE),*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    out=p.stdout.decode('utf-8').replace('\r\n','\n'); err=p.stderr.decode('utf-8').replace('\r\n','\n')
    if expected is not None:
        assert p.returncode==expected,(p.returncode,out,err)
    return p.returncode,out,err

def events(text):
    return [json.loads(line) for line in text.splitlines() if line.strip()]

def frame(field,payload=b''):
    return bytes.fromhex('000102030405aabbccddeeff')+struct.pack('!H',field)+payload

def write_pcap(path,packets,linktype=1):
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,linktype))
        for i,item in enumerate(packets):
            data,original=item if isinstance(item,tuple) else (item,len(item))
            out.write(struct.pack('<IIII',1_792_588_800+i,123456,len(data),original));out.write(data)

def read_pcap(path):
    raw=path.read_bytes(); magic=raw[:4]
    order='<' if magic==b'\xd4\xc3\xb2\xa1' else '>'
    assert magic in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4')
    assert struct.unpack_from(order+'I',raw,20)[0]==1
    pos=24; packets=[]
    while pos<len(raw):
        sec,usec,caplen,wirelen=struct.unpack_from(order+'IIII',raw,pos);pos+=16
        buf=raw[pos:pos+caplen];pos+=caplen;assert len(buf)==caplen
        packets.append((buf,wirelen))
    return packets

def start_live(*args):
    p=subprocess.Popen([str(EXE),'--device',METRICS['device']['name'],'--json',*map(str,args)],
                       stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    lines=[]; ready=threading.Event()
    def read():
        for line in iter(p.stdout.readline,b''):
            text=line.decode('utf-8').replace('\r\n','\n');lines.append(text)
            if '"event":"start"' in text: ready.set()
        p.stdout.close()
    reader=threading.Thread(target=read);reader.start()
    if not ready.wait(8):
        if p.poll() is None:p.kill()
        p.wait();reader.join()
        raise AssertionError('Capture did not start: '+''.join(lines))
    return p,reader,lines

def finish_live(p,reader,lines):
    try:p.wait(timeout=12)
    finally:
        if p.poll() is None:p.kill();p.wait()
        reader.join(timeout=3)
    text=''.join(lines)
    assert p.returncode==0,(p.returncode,text)
    return text,events(text)

class CaptureTests(unittest.TestCase):
    def test_01_enumerate_real_devices(self):
        _,text,_=execute('--list','--json')
        (E/'devices.jsonl').write_text(text,encoding='utf-8')
        rows=events(text);devices=[r for r in rows if r['event']=='device']
        self.assertTrue(devices)
        selected=[d for d in devices if NET['ipv4'] in d['ipv4']]
        self.assertEqual(len(selected),1,'Select the adapter of the recorded default IPv4 route')
        METRICS['device']=selected[0];METRICS['runtime']=rows[0]['version']

    def test_02_offline_boundaries_and_vlan(self):
        path=E/'synthetic-boundaries.pcap'
        packets=[b'\x00'*13,frame(0x0800),(frame(0x0800,b'\x45'),1500),
                 frame(0x0806,b'\x00'),frame(0x86dd,b'\x60'),
                 frame(0x8100,bytes.fromhex('a064080045')),frame(1500,b'\xaa'),frame(1501,b'\x00')]
        write_pcap(path,packets)
        _,text,_=execute('--read',path,'--count',0,'--json')
        (E/'synthetic-boundaries.jsonl').write_text(text,encoding='utf-8')
        rows=[e for e in events(text) if e['event']=='packet']
        self.assertEqual(len(rows),8)
        self.assertIsNone(rows[0]['source_mac']);self.assertIsNone(rows[1]['after_type'])
        self.assertEqual(rows[2]['after_type'],'0x45');self.assertTrue(rows[2]['truncated'])
        self.assertEqual(rows[3]['after_type'],'0x00')
        self.assertEqual(rows[5]['type_length'],'0x8100');self.assertEqual(rows[5]['after_type'],'0xA0')
        self.assertEqual(rows[5]['inner_type'],'0x0800');self.assertEqual(rows[5]['payload_first'],'0x45')
        self.assertEqual(rows[6]['protocol'],'IEEE802.3(length=1500)')
        self.assertEqual(rows[7]['protocol'],'Reserved(1501..1535)')

    def test_03_reject_non_ethernet_without_fake_mac(self):
        path=E/'synthetic-null.pcap';write_pcap(path,[struct.pack('<I',2)+b'\x45'*20],linktype=0)
        _,out,err=execute('--read',path,'--json',expected=1)
        self.assertIn('not Ethernet',err);self.assertNotIn('source_mac',out)

    def test_04_invalid_cli_and_device(self):
        for args in [('--count','-1'),('--seconds','12x'),('--snaplen','13'),('--count',),('--unknown',)]:
            self.assertNotEqual(execute(*args,expected=None)[0],0)
        self.assertNotEqual(execute('--device','9999',expected=None)[0],0)

    def test_05_invalid_bpf_and_missing_input(self):
        _,_,err=execute('--read',E/'synthetic-boundaries.pcap','--filter','invalid ( (',expected=1)
        self.assertIn('BPF compile',err)
        self.assertNotEqual(execute('--read',E/'missing-file.pcap',expected=None)[0],0)

    def test_06_idle_time_limit_without_traffic(self):
        p,r,lines=start_live('--count',0,'--seconds',1,'--filter','ether proto 0x88b5')
        _,rows=finish_live(p,r,lines);summary=rows[-1]
        self.assertEqual(summary['event'],'summary');self.assertEqual(summary['reason'],'time')
        self.assertLess(summary['elapsed_seconds'],2.5)
        self.assertEqual(summary['received'],0)

    def test_07_real_capture_and_byte_comparison(self):
        path=E/'real-capture.pcap'
        p,r,lines=start_live('--count',0,'--seconds',4,'--filter','icmp and host '+NET['gateway'],'--save',path)
        try:
            ping=subprocess.run(['ping','-n','3','-w','400',NET['gateway']],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=8)
            # Ping's exit status is not an assertion: outgoing frames still count if the router does not reply.
            (E/'ping-output.txt').write_text(ping.stdout.decode('oem',errors='replace'),encoding='utf-8')
        finally:text,rows=finish_live(p,r,lines)
        (E/'live-capture.jsonl').write_text(text,encoding='utf-8')
        observed=[e for e in rows if e['event']=='packet'];raw=read_pcap(path)
        self.assertGreaterEqual(len(raw),3)
        self.assertEqual(len(observed),len(raw))
        def mac(b):return ':'.join(f'{n:02X}' for n in b)
        for row,(buf,wire) in zip(observed,raw):
            self.assertEqual(row['source_mac'],mac(buf[6:12]))
            self.assertEqual(row['destination_mac'],mac(buf[:6]))
            self.assertEqual(row['type_length'],f'0x{int.from_bytes(buf[12:14],"big"):04X}')
            self.assertEqual(row['after_type'],f'0x{buf[14]:02X}')
            self.assertEqual(row['captured_length'],len(buf));self.assertEqual(row['original_length'],wire)
        summary=rows[-1];METRICS['real_capture']={'packets':len(raw),'summary':summary,'filter':'icmp and host '+NET['gateway']}
        _,screen,_=execute('--read',path,'--count',0)
        (E/'capture-screen.txt').write_text(screen,encoding='utf-8')

    def test_08_replay_filter_and_chinese_filename(self):
        original=E/'real-capture.pcap';path=E/'中文路径复核.pcap';path.write_bytes(original.read_bytes())
        _,text,_=execute('--read',path,'--count',0,'--json','--filter','icmp')
        self.assertEqual(len([e for e in events(text) if e['event']=='packet']),METRICS['real_capture']['packets'])

    def test_09_count_limit(self):
        _,text,_=execute('--read',E/'real-capture.pcap','--count',1,'--json')
        rows=events(text);self.assertEqual(rows[-1]['received'],1);self.assertEqual(rows[-1]['reason'],'count')

    def test_10_ctrl_break_normal_exit(self):
        p,r,lines=start_live('--seconds',0,'--count',0,'--filter','ether proto 0x88b5')
        p.send_signal(signal.CTRL_BREAK_EVENT)
        _,rows=finish_live(p,r,lines)
        self.assertEqual(rows[-1]['reason'],'stopped')

    def test_11_default_no_disk_capture(self):
        before={str(p):p.stat().st_mtime_ns for p in E.iterdir() if p.suffix in ('.pcap','.pcapng')}
        p,r,lines=start_live('--seconds',1,'--count',0,'--filter','ether proto 0x88b5')
        finish_live(p,r,lines)
        after={str(p):p.stat().st_mtime_ns for p in E.iterdir() if p.suffix in ('.pcap','.pcapng')}
        self.assertEqual(before,after)

if __name__=='__main__':
    start=time.monotonic()
    parser=subprocess.run([str(ROOT/'bin/parser_tests.exe')],stdout=subprocess.PIPE,timeout=10)
    (E/'parser-tests.txt').write_text(parser.stdout.decode('utf-8').replace('\r\n','\n'),encoding='utf-8')
    if parser.returncode:raise SystemExit(parser.returncode)
    with (E/'integration-tests.txt').open('w',encoding='utf-8') as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CaptureTests))
    report={'time':time.strftime('%Y-%m-%d %H:%M:%S %z'),'os':platform.platform(),
            'parser_tests':24,'integration_tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
            'duration_seconds':round(time.monotonic()-start,3),'metrics':METRICS}
    (E/'results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print((E/'integration-tests.txt').read_text(encoding='utf-8'));print(json.dumps(report,ensure_ascii=False,indent=2))
    sys.exit(not result.wasSuccessful())
