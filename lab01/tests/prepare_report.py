"""Generate report tables only from saved test/capture evidence."""
import json
from pathlib import Path
import re
import socket
import struct

ROOT=Path(__file__).resolve().parents[1]
E=ROOT/'evidence'; R=ROOT/'report'
(R/'client-transcript.txt').write_text((E/'client-transcript.txt').read_text(encoding='utf-8'),encoding='utf-8')
data=json.loads((E/'results.json').read_text(encoding='utf-8'))
assert data['failures']==data['errors']==0, 'Do not publish a passing report for failing tests'
s=data['stress']
values=dict(TestCount=data['tests'],FailureCount=data['failures'],ErrorCount=data['errors'],
            TestDuration=data['duration_seconds'],TestTimestamp=data['time'],ClientCount=s['clients'],
            SentCount=s['messages_sent'],ExpectedCount=s['deliveries_expected'],ReceivedCount=s['deliveries_received'],
            MissingCount=s['missing'],DuplicateCount=s['duplicates'],StressDuration=s['elapsed_seconds'])
(R/'measurements.tex').write_text('\n'.join('\\newcommand{\\%s}{%s}'%(k,v) for k,v in values.items()),encoding='utf-8')
log=(E/'test_10_concurrent_integrity-server.txt').read_text(encoding='utf-8')
stats=re.findall(r'TCP_STATS peer=(User\d+) BytesOut=(\d+) BytesIn=(\d+) BytesRetrans=(\d+) DupAcksIn=(\d+) TimeoutEpisodes=(\d+)',log)
assert len(stats)==s['clients']
(R/'tcp-table.tex').write_text(
    '\\begin{tabular}{lrrrrr}\\toprule\n连接 & 发出字节 & 收到字节 & 重传字节 & 重复 ACK & 超时事件\\\\\\midrule\n'
    +'\n'.join(' & '.join(row)+r' \\' for row in stats)
    +'\n\\bottomrule\\end{tabular}\n',encoding='utf-8')

# Pktmon's all-components loopback recording contained only drop events.
# Decode the EPB's actual IP bytes, preserving the untouched original export.
capture=(E/'chat-drops.pcapng').read_bytes()
packets=[]; raw=[]; offset=0
while offset<len(capture):
    kind,length=struct.unpack_from('<II',capture,offset)
    assert length>=12 and offset+length<=len(capture)
    assert struct.unpack_from('<I',capture,offset+length-4)[0]==length
    if kind==6:
        iface,hi,lo,caplen,origlen=struct.unpack_from('<IIIII',capture,offset+8)
        buf=capture[offset+28:offset+28+caplen]
        # The exported record contains a raw IP datagram despite an Ethernet IDB.
        assert buf[0]>>4==4
        ihl=(buf[0]&15)*4; total=struct.unpack_from('!H',buf,2)[0]
        assert buf[9]==6 and len(buf)==origlen==total
        sport,dport,seq,ack=struct.unpack_from('!HHII',buf,ihl)
        tcp_len=(buf[ihl+12]>>4)*4; flags=buf[ihl+13]
        assert sport==9001 or dport==9001
        packets.append(dict(source=socket.inet_ntoa(buf[12:16]),source_port=sport,
                            destination=socket.inet_ntoa(buf[16:20]),destination_port=dport,
                            flags=f'0x{flags:02x}',seq=seq,ack=ack,ip_bytes=total,
                            payload_bytes=total-ihl-tcp_len))
        raw.append((((hi<<32)|lo),buf))
    offset+=length
text=(E/'chat-packets.txt').read_text(encoding='utf-16')
drop_lines=[line for line in text.splitlines() if 'DropReason ' in line]
assert len(packets)==len(drop_lines)==2
assert all(p['flags']=='0x10' and p['payload_bytes']==0 for p in packets)
assert all('INET: FIN-WAIT2' in line for line in drop_lines)
summary={'tool':'Windows Pktmon','filter':'TCP port 9001','scope':'127.0.0.1 loopback',
         'flow_packet_records':0,'drop_packet_records':len(packets),'drop_reason':'INET: FIN-WAIT2',
         'trace_events_lost':0,'workload_messages':20,'workload_deliveries':60,'packets':packets,
         'limitation':'Normal loopback flow was not exposed at this capture point; cannot infer a total packet loss rate.'}
(E/'capture-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
(E/'capture-excerpt.txt').write_text('\n'.join(drop_lines)+'\n',encoding='utf-8')
# Analysis copy: keep exactly the captured IP bytes, label LINKTYPE_RAW correctly.
# Timestamp units are the Pktmon default microseconds in this export.
with (E/'chat-drops-raw.pcap').open('wb') as f:
    f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101))
    for stamp,buf in raw:
        sec,usec=divmod(stamp,1_000_000)
        f.write(struct.pack('<IIII',sec,usec,len(buf),len(buf))); f.write(buf)
(R/'capture-observation.tex').write_text(r'''
在用户批准 Windows UAC 提升权限后，使用系统 Pktmon 对 TCP 9001 端口进行独立录制，
保存原始 \src{chat.etl}、原始转换结果 \src{chat.pcapng}、
仅丢弃事件的 \src{chat-drops.pcapng} 和文本 \src{chat-packets.txt}。
该次负载为 3 个用户、20 条消息、60 次经正文断言验证的投递，全部成功。
原始跟踪头的 EventsLost 和 BuffersLost 均为 0，表示跟踪系统未报告事件缓冲丢失。

\textbf{实际捕获并非“没有丢弃事件”。} 本次回环抓包点没有记录正常路径数据包，
但记录了 2 个 \src{INET: FIN-WAIT2} 丢弃事件。对保存的两个 IP 数据报逐字节解析后，
均为 127.0.0.1 上客户端临时端口发往服务器 9001 的 TCP 段，IP 总长度 40 字节，
TCP 标志为 \src{0x10}（仅 ACK），应用载荷为 0 字节。它们出现在 QUIT/BYE 关闭阶段，
所以这两条记录体现的是本机 TCP 状态处理对控制段的丢弃，不能直接等同于聊天正文丢失。
该次服务端三个连接的重传字节也均为 0。

默认 \src{etl2pcap} 不包含 drop 事件，因此其结果只有文件头；必须加
\src{--drop-only} 才能导出这两个真实数据报。本机导出器的接口描述标为 Ethernet，
而记录内容是原始 IPv4；提供的 \src{chat-drops-raw.pcap} 仅将相同原始字节放入
正确的 LINKTYPE\_RAW 分析容器，原始 ETL 与 PCAPNG 均保留，便于复核。
结构化逐包结果见 \src{capture-summary.json}，原始丢弃原因节选见 \src{capture-excerpt.txt}。

\textbf{观测限制：} 正常回环流量没有被本抓包点完整记录，因此不能用
“2 个丢弃记录 / 全部 TCP 段数”计算丢包率，也不能从空的普通 PCAPNG 推导零丢包。
本次结论分别保留“应用消息未缺失”“本端发送未记录重传”与“关闭阶段观察到两个无载荷 ACK 被丢弃”三项事实。
''',encoding='utf-8')
print('Report tables and capture analysis generated from raw evidence.')
