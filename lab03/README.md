# 实验三：基于 UDP 的可靠文件传输（RUDP-SR/1）

Windows x64、C++17、基础 Winsock API。程序自行实现三次握手、校验和、累计 ACK+64位SACK、选择重传、固定同大小窗口及连接关闭，不使用现成可靠传输框架。

## 直接运行

无需 Npcap、Python 或额外运行库即可运行 `bin/rudp.exe`。Python 仅用于自动测试和整理结果。
在本目录的两个 PowerShell 中分别执行：

```powershell
# 接收端，目标文件必须不存在
.\bin\rudp.exe recv --port 9002 --output received.txt --window 16

# 发送端
.\bin\rudp.exe send --peer 127.0.0.1 --port 9002 --file samples/hello_utf8.txt --window 16
```

双方 `--window` 必须相同，范围1–64；程序始终使用固定窗口。文件数据单向传输，控制报文双向交互。
支持中文路径和二进制内容，包括空文件。接收端先写 `.part`，完整长度和CRC32验证后才提交目标文件，默认不覆盖现有文件。

## 带丢包、损坏与乱序的演示

三个终端依次启动接收、转发、发送：

```powershell
.\bin\rudp.exe recv --port 9002 --output received.txt --window 8 --verbose
.\bin\rudp.exe relay --port 9001 --target-port 9002 --drop-data 2 --delay-ms 8 --verbose
.\bin\rudp.exe send --peer 127.0.0.1 --port 9001 --file samples/hello_utf8.txt --chunk 32 --window 8 --verbose
```

发送端改为指向转发器端口9001。`--drop-data 2` 仅丢弃第一次出现的DATA 2，日志可观察SACK位图和单段重传。
其他模拟参数：`--loss .1` 双向逐报文10%随机丢包，`--corrupt .04` 损坏，`--duplicate .1` 重复，`--jitter-ms 8` 抖动，`--delay-data 0 --reorder-ms 60` 首段延后，`--drop-type SYN:1,FIN_ACK:1` 控制丢失。
`--seed` 固定随机种子；随机样本随实际报文发送顺序推进，不承诺不同窗口会丢弃同一组序号。

收发结束会输出成功/失败、传输时间、平均有效吞吐率、重传、校验失败、最大在途与缓存等JSON统计。`--stats result.json` 另存统计。
发送端的总时间从首个SYN之前至有效FIN_ACK到达，包含握手、传输、重传和接收文件提交，不含发送端预扫描与TIME_WAIT；吞吐率为原文件字节数/该时间。

默认RTO150ms、40次重试，接收空闲时限10000ms；双方可一致设置 `--rto-ms`、`--retries` 和 `--idle-ms`。Ctrl+C 中断并清理；转发器可按q或输入quit退出。
连续丢失超过预算会明确失败；接收端在关闭确认超时前可能已经提交已验证文件，日志对此明确区分。有限重试不保证永久故障下双方对最终状态同时达成一致。

## 外部 Router / 跨主机

默认只绑定127.0.0.1。跨主机显式给出 `--bind 本机IPv4`；发送端使用实际对端或Router的 `--peer`、`--port`，需要固定源端口时加 `--local-port`。
接收端对回复目标使用实际收到SYN的来源地址。本项目转发器以同一UDP端口双向转发，独立于收发程序；可以不用它，按课堂Router拓扑调整地址和端口。

教师提供的《实验说明》只重申“规定测试环境、给定测试文件”，未附具体清单。本工程实测明确采用本机模拟链路和自生成文件，不能冒充尚未提供的课堂指定环境。补充材料后可直接用同一程序重测。

## 构建与复核

```powershell
.\build.ps1
.\bin\protocol_tests.exe
python -X utf8 tests/integration.py
python -X utf8 tests/benchmark.py
```

要求Visual Studio C++ Build Tools；`/W4 /WX /MT`。CMake备用：

```powershell
cmake -S . -B ../build/lab03
cmake --build ../build/lab03 --config Release
ctest --test-dir ../build/lab03 -C Release --output-on-failure
```

32项协议/窗口测试；20项真实UDP集成测试。性能实验为同一128KiB文件，W=1/4/16/64、双向丢包0/10/20%，每种3次，固定单向延迟8ms、RTO100ms、负载1200字节。全部接收文件逐字节及SHA256复核。
每次原始数据见 `evidence/performance.csv` 与 `evidence/benchmark/`，汇总见 `performance-summary.json`。

协议完整说明见 `PROTOCOL.md`；详细实验报告为 `report/main.pdf` 与 `report/main.tex`。
运行 `report/build-report.ps1` 从证据生成表图并编译，运行 `package.ps1` 生成提交ZIP。
展示指南、5–6分钟讲稿、问答与一键演示脚本放在仓库根目录被忽略的 `private-demo/`，不放进教师提交包。

本实验只提供教学可靠传输，不提供身份认证、加密、拥塞控制或断点续传。校验和与CRC32用于差错检测，不是抗恶意篡改机制。
