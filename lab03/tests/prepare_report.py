"""Generate tables, excerpts and scientific figures from saved evidence only."""
import json
from pathlib import Path
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parents[1];E=ROOT/'evidence';R=ROOT/'report'
tests=json.loads((E/'results.json').read_text(encoding='utf-8'))
perf=json.loads((E/'performance-summary.json').read_text(encoding='utf-8'))
assert tests['failures']==tests['errors']==0 and perf['runs']==36
for row in tests['transfers']:
    if row['success_expected']:assert row['input_sha256']==row['output_sha256']
values={'UnitCount':tests['protocol_tests'],'IntegrationCount':tests['integration_tests'],
    'TestTime':tests['elapsed_seconds'],'TestTimestamp':tests['time'],'BenchRuns':perf['runs'],
    'BenchBytes':perf['file_bytes'],'BenchTime':perf['elapsed_seconds']}
(R/'measurements.tex').write_text('\n'.join('\\newcommand{\\%s}{%s}'%(k,v) for k,v in values.items())+'\n',encoding='utf-8')
def table(name,columns,header,rows):
    (R/name).write_text('\\begin{tabular}{'+columns+'}\\toprule\n'+header+r' \\ \midrule'+'\n'
        +'\n'.join(' & '.join(map(str,row))+r' \\' for row in rows)+'\n\\bottomrule\\end{tabular}\n',encoding='utf-8')
table('performance-table.tex','rrrrrr','丢包概率 & 窗口 & 平均时间/s & 平均MiB/s & MiB/s范围 & 平均重传',[
    [f"{p['loss']:.0%}".replace('%',r'\%'),p['window'],f"{p['mean_seconds']:.3f}",f"{p['mean_mib_s']:.4f}",
     f"{p['min_mib_s']:.4f}--{p['max_mib_s']:.4f}",f"{p['mean_retransmissions']:.1f}"] for p in perf['summary']])
selected=['empty','large','selective','ack-loss','corrupt','reorder','duplicate','control-loss','random','mismatch','exhausted']
names={'empty':'空文件','large':'1 MiB二进制','selective':'只丢DATA 2','ack-loss':'末数据ACK丢失','corrupt':'DATA损坏',
       'reorder':'首段延迟','duplicate':'重复报文','control-loss':'握手/关闭丢失','random':'组合随机故障','mismatch':'窗口不一致','exhausted':'全部DATA丢失'}
rows=[]
for name in selected:
    row=next(p for p in tests['transfers'] if p['case']==name)
    s,r=row['sender'],row['receiver']
    rows.append([names[name],s['retransmissions'],r['checksum_errors'],r['out_of_order'],
                 '一致' if row['success_expected'] else '明确失败、无最终文件'])
table('reliability-table.tex','lrrrl','场景 & 重传 & 校验失败 & 乱序 & 文件结果',rows)

sender=(E/'cases/selective-sender.txt').read_text(encoding='utf-8')
excerpt=[line for line in sender.splitlines() if line.startswith('STATE ') or line.startswith('RECV ACK') or line.startswith('RETRANSMIT DATA')]
(R/'selective-excerpt.txt').write_text('\n'.join(excerpt)+'\n',encoding='utf-8')
close=(E/'cases/control-loss-sender.txt').read_text(encoding='utf-8')
(R/'close-excerpt.txt').write_text('\n'.join(line for line in close.splitlines() if line.startswith('STATE') or line.startswith('RETRANSMIT'))+'\n',encoding='utf-8')

plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False})
fig,axes=plt.subplots(1,2,figsize=(10,3.8),layout='constrained')
colors=['#255a8b','#d57724','#377d53']
for loss,color in zip([0,.1,.2],colors):
    rows=[p for p in perf['summary'] if p['loss']==loss]
    x=[p['window'] for p in rows]; y=[p['mean_mib_s'] for p in rows]
    axes[0].errorbar(x,y,yerr=[[p['mean_mib_s']-p['min_mib_s'] for p in rows],[p['max_mib_s']-p['mean_mib_s'] for p in rows]],
                     color=color,marker='o',capsize=3,label=f'{loss:.0%} loss per direction')
    axes[1].plot(x,[p['mean_retransmissions'] for p in rows],color=color,marker='o',label=f'{loss:.0%} loss per direction')
for ax in axes:
    ax.set_xscale('log',base=2);ax.set_xticks([1,4,16,64],['1','4','16','64'])
    ax.set_xlabel('Fixed sender/receiver window (segments)');ax.grid(alpha=.2)
axes[0].set_yscale('log');axes[0].set_ylabel('Mean useful throughput (MiB/s)')
axes[0].set_title('Goodput; bars show min/max of 3 runs')
axes[1].set_ylabel('Mean DATA retransmissions');axes[1].set_title('Selective retransmission count')
axes[0].legend(fontsize=8,loc='upper left');axes[1].legend(fontsize=8)
fig.savefig(R/'window-performance.pdf');fig.savefig(R/'window-performance.png',dpi=220);plt.close(fig)
print('Generated evidence tables and performance plots from 36 verified runs.')
