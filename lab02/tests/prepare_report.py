"""Derive all report numbers/tables from saved real capture evidence."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
import struct
from integration import read_pcap

ROOT=Path(__file__).resolve().parents[1]; E=ROOT/'evidence'; R=ROOT/'report'
def tex(text):
    escapes={'_':r'\_','&':r'\&','%':r'\%','#':r'\#','$':r'\$'}
    return ''.join(escapes.get(c,c) for c in text)
result=json.loads((E/'results.json').read_text(encoding='utf-8'))
assert result['failures']==result['errors']==0
metric=result['metrics']; live=metric['real_capture']; summary=live['summary']
rows=[json.loads(line) for line in (E/'live-capture.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
rows=[row for row in rows if row['event']=='packet']
raw=read_pcap(E/'real-capture.pcap')
assert len(rows)==len(raw)==live['packets']
values={'ParserTests':result['parser_tests'],'IntegrationTests':result['integration_tests'],
        'TestDuration':result['duration_seconds'],'TestTimestamp':result['time'],
        'PacketCount':live['packets'],'CaptureDuration':f"{summary['elapsed_seconds']:.3f}",
        'DriverReceived':summary['ps_recv'],'DriverDropped':summary['ps_drop'],
        'InterfaceDropped':summary['ps_ifdrop'],'ShortFrames':summary['short_frames'],
        'TruncatedFrames':summary['truncated']}
(R/'measurements.tex').write_text('\n'.join('\\newcommand{\\%s}{%s}'%(k,v) for k,v in values.items())+'\n',encoding='utf-8')

mandatory=[]; details=[]; decoded=[]; requests={}; rtts=[]
for row,(buf,wirelen) in zip(rows,raw):
    source=':'.join(f'{b:02X}' for b in buf[6:12]); destination=':'.join(f'{b:02X}' for b in buf[:6])
    assert source==row['source_mac'] and destination==row['destination_mac']
    assert int.from_bytes(buf[12:14],'big')==int(row['type_length'],16)
    assert buf[14]==int(row['after_type'],16) and wirelen==row['original_length']
    mandatory.append(' & '.join(map(str,[row['index'],source,destination,row['type_length'],row['after_type'],f'{len(buf)}/{wirelen}']))+r' \\')
    ip=buf[14:]; ihl=(ip[0]&15)*4; total=int.from_bytes(ip[2:4],'big')
    assert ip[0]>>4==4 and ip[9]==1
    icmp=ip[ihl:]; kind,code,checksum,identifier,sequence=struct.unpack_from('!BBHHH',icmp)
    assert kind in (0,8) and code==0
    src='.'.join(map(str,ip[12:16]));dst='.'.join(map(str,ip[16:20]))
    record={'index':row['index'],'source':src,'destination':dst,'icmp_type':kind,'icmp_code':code,
            'identifier':identifier,'sequence':sequence,'ip_header_bytes':ihl,'ip_total_bytes':total,
            'icmp_data_bytes':total-ihl-8,'captured_bytes':len(buf),'time':row['time']}
    decoded.append(record)
    details.append(' & '.join(map(str,[row['index'],src,dst,'Echo request (8)' if kind==8 else 'Echo reply (0)',sequence]))+r' \\')
    instant=datetime.strptime(row['time'],'%Y-%m-%d %H:%M:%S.%f')
    if kind==8:requests[(identifier,sequence)]=instant
    elif (identifier,sequence) in requests:rtts.append(round((instant-requests[(identifier,sequence)]).total_seconds()*1000,3))

def table(path,header,body,columns):
    (R/path).write_text('\\begin{tabular}{'+columns+'}\\toprule\n'+header+r' \\ \midrule'+'\n'+'\n'.join(body)+'\n\\bottomrule\\end{tabular}\n',encoding='utf-8')
table('mandatory-table.tex','序号 & 源 MAC & 目的 MAC & 类型 & 首字节 & 长度',mandatory,'rllllr')
table('icmp-table.tex','序号 & 源 IPv4 & 目的 IPv4 & ICMP 含义 & 序号字段',details,'rlllr')
(E/'frame-analysis.json').write_text(json.dumps({'capture_sha256':hashlib.sha256((E/'real-capture.pcap').read_bytes()).hexdigest(),
    'packets':decoded,'paired_rtt_ms':rtts},ensure_ascii=False,indent=2),encoding='utf-8')
hexlines=[]
for offset in range(0,len(raw[0][0]),16):
    part=raw[0][0][offset:offset+16]
    hexlines.append(f'{offset:04X}  '+' '.join(f'{byte:02X}' for byte in part))
(R/'first-frame-hex.txt').write_text('\n'.join(hexlines)+'\n',encoding='utf-8')
(R/'capture-screen.txt').write_text((E/'capture-screen.txt').read_text(encoding='utf-8'),encoding='utf-8')
(R/'runtime-info.tex').write_text(
    r'\begin{tabularx}{\textwidth}{lX}\toprule'+'\n'
    +'Npcap & '+tex(metric['runtime'])+r' \\'+'\n'
    +'网卡 & '+tex(metric['device']['description'])+r' \\'+'\n'
    +'枚举编号 & '+str(metric['device']['index'])+r'（仅对本次枚举有效） \\'+'\n'
    +'本机 IPv4 & '+decoded[0]['source']+r' \\'+'\n'
    +'默认网关 & '+decoded[0]['destination']+r' \\'+'\n'
    +'过滤器 & '+live['filter']+r' \\'+'\n'
    +r'\bottomrule\end{tabularx}'+'\n',encoding='utf-8')
print(f'Generated report from {len(rows)} verified real frames; paired RTT ms: {rtts}')
