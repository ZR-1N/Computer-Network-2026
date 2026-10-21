"""Controlled, repeated window/loss study using the real C++ relay and peers."""
import csv
import hashlib
import json
from pathlib import Path
import random
import statistics
import time
import uuid
import integration as driver

ROOT=driver.ROOT; E=ROOT/'evidence'; B=E/'benchmark';B.mkdir(exist_ok=True)
driver.CASES=B

def run(window,loss,repeat,data):
    name=f'w{window}-loss{int(loss*100)}-run{repeat}'
    directory=driver.WORK/('bench-'+name+'-'+uuid.uuid4().hex[:8]);directory.mkdir()
    source=directory/'input.bin';output=directory/'output.bin';source.write_bytes(data)
    port=driver.free_port();relay_port=driver.free_port()
    receiver=driver.Process(name+'-receiver',['recv','--port',port,'--output',output,'--window',window,
        '--rto-ms',100,'--idle-ms',10000,'--retries',60])
    proxy=None;sender=None
    try:
        receiver.ready('STATE LISTEN')
        proxy=driver.Process(name+'-relay',['relay','--port',relay_port,'--target-port',port,'--loss',loss,
            '--delay-ms',8,'--seed',2026+repeat,'--seconds',60])
        proxy.ready('RELAY_READY')
        sender=driver.Process(name+'-sender',['send','--port',relay_port,'--file',source,'--window',window,
            '--chunk',1200,'--rto-ms',100,'--retries',60])
        sc=sender.wait(35);rc=receiver.wait(10)
        s=driver.read_json(sender.stats);r=driver.read_json(receiver.stats)
        assert sc==rc==0 and s['success'] and r['success'],(name,s,r)
        digest=hashlib.sha256(output.read_bytes()).hexdigest()
        assert digest==hashlib.sha256(data).hexdigest(),name
        assert proxy.stop()==0
        p=driver.read_json(proxy.stats)
        row=dict(window=window,loss=loss,repeat=repeat,seed=2026+repeat,bytes=len(data),
                 seconds=s['total_seconds'],data_seconds=s['data_seconds'],mib_s=s['throughput_mib_s'],
                 mbit_s=s['throughput_mbit_s'],retransmissions=s['retransmissions'],control_retries=s['control_retries'],
                 max_in_flight=s['max_in_flight'],max_buffered=r['max_buffered'],relay_received=p['received'],
                 relay_dropped=p['dropped'],output_sha256=digest)
        assert row['max_in_flight']<=window and row['max_buffered']<=window
        return row
    finally:
        for process in [sender,receiver,proxy]:
            if process and process.p.poll() is None:process.p.kill();process.wait()

if __name__=='__main__':
    begin=time.monotonic();data=random.Random(20261022).randbytes(128*1024)
    rows=[]
    csv_path=E/'performance.csv'
    for loss in (0.0,.1,.2):
        for window in (1,4,16,64):
            for repeat in range(3):
                row=run(window,loss,repeat,data);rows.append(row)
                with csv_path.open('w',newline='',encoding='utf-8') as f:
                    writer=csv.DictWriter(f,fieldnames=list(row));writer.writeheader();writer.writerows(rows)
                print(f"W={window:2d} loss={loss:.0%} repeat={repeat} time={row['seconds']:.4f}s goodput={row['mib_s']:.4f}MiB/s retry={row['retransmissions']}",flush=True)
    summary=[]
    for loss in (0.0,.1,.2):
        for window in (1,4,16,64):
            group=[r for r in rows if r['loss']==loss and r['window']==window]
            summary.append(dict(window=window,loss=loss,n=len(group),
                mean_seconds=statistics.mean(r['seconds'] for r in group),
                mean_mib_s=statistics.mean(r['mib_s'] for r in group),
                median_mib_s=statistics.median(r['mib_s'] for r in group),
                min_mib_s=min(r['mib_s'] for r in group),max_mib_s=max(r['mib_s'] for r in group),
                mean_retransmissions=statistics.mean(r['retransmissions'] for r in group)))
    report={'file_bytes':len(data),'input_sha256':hashlib.sha256(data).hexdigest(),
        'file_source':'deterministically generated binary, Python Random(20261022)',
        'chunk':1200,'rto_ms':100,'one_way_delay_ms':8,'loss_directions':'both, independently per datagram',
        'windows':[1,4,16,64],'loss_probabilities':[0,.1,.2],'repetitions':3,'runs':len(rows),
        'time':time.strftime('%Y-%m-%d %H:%M:%S %z'),'elapsed_seconds':round(time.monotonic()-begin,3),'summary':summary}
    (E/'performance-summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Benchmark complete: all',len(rows),'SHA256 checks passed.',flush=True)
