# 实验二：Npcap 数据帧捕获与分析

Windows x64、C++17；支持网卡列表、交互选择、实时捕获、BPF 过滤、正常退出和离线复核。

## 运行前提

先从 [Npcap 官网](https://npcap.com/#download) 安装运行库和驱动。仅把 exe 拷贝到一台没有 Npcap 的电脑上不能抓包。
本机验证版本为 Npcap 1.89。SDK 1.16 用于编译，不是运行时驱动。
如果安装时勾选了“仅管理员可访问”，请在管理员 PowerShell 中运行程序。
本项目不随提交包分发 Npcap DLL、驱动或安装程序。

## 最短使用流程

在本目录打开 PowerShell：

```powershell
.\bin\packet_capture.exe --list
.\bin\packet_capture.exe
```

第二条命令会再次列出网卡并询问编号。选择有实际流量的 Ethernet/Wi-Fi 网卡；不要选回环接口，回环没有以太网 MAC。
默认显示 20 帧或运行 30 秒后退出，按 Q（无需回车）或 Ctrl+C 可提前结束。默认不会保存数据包到硬盘。

```powershell
.\bin\packet_capture.exe --device 6 --count 10 --seconds 30 --filter "arp or icmp"
```

网卡编号是每次枚举结果，不应固定照抄示例的 6。可在另一个终端 `ping` 本机默认网关产生流量；默认网关可用 `Get-NetIPConfiguration` 查看。

屏幕主表列：`SRC-MAC` 源 MAC、`DST-MAC` 目的 MAC、`Type` 外层类型/长度字段、`After` 该字段之后第一个字节、`Cap/Wire` 捕获/原始字节数。所有必需字段都以十六进制明确显示。
Ethernet 偏移为目的 MAC 0–5、源 MAC 6–11、类型/长度 12–13、After 14。无足够字节时显示 N/A；VLAN 情况下 After 仍是原始偏移 14，解码后的内层类型另行显示。

## 可选复核

```powershell
.\bin\packet_capture.exe --device 6 --count 10 --seconds 30 --filter "icmp" --save sample.pcap
.\bin\packet_capture.exe --read sample.pcap --count 0
.\bin\packet_capture.exe --read sample.pcap --count 0 --json
```

`--save` 是显式选择，平时展示无需使用。`--json` 输出 JSON Lines 便于自动校验；`--read` 是离线复核，不会冒充实时抓包。
`--promisc` 可选打开混杂模式，默认关闭。程序不会自动打开无线监控模式。
所有参数见 `--help`。

## 编译

安装 Visual Studio 2019/2022 C++ Build Tools，下载官方 Npcap SDK：

```powershell
.\bootstrap-sdk.ps1
.\build.ps1
```

已有 SDK 时：`./build.ps1 -NpcapSdk C:\path\to\npcap-sdk`。
也支持 CMake（从本目录）：

```powershell
cmake -S . -B ../build/lab02 -DNPCAP_SDK=C:/path/to/npcap-sdk
cmake --build ../build/lab02 --config Release
ctest --test-dir ../build/lab02 -C Release --output-on-failure
```

Npcap API 直接通过 SDK 的函数类型调用；从系统 `Npcap/wpcap.dll` 显式加载，避免误用 WinPcap。程序采用静态 C++ 运行库。

## 验证与报告

- `bin/parser_tests.exe`：24 项纯 C++ 解析边界测试，无需驱动。
- 管理员 PowerShell 执行 `tests/run-elevated.ps1 -Python python`：11 项集成测试，含真实物理网卡捕获、逐字段对照、离线过滤、中文路径、限时与 Ctrl+Break 正常退出。
- `evidence/real-capture.pcap`：真实网卡上对默认网关发送 ICMP 的捕获记录；`synthetic-*.pcap` 明确为边界测试合成数据。
- `evidence/live-capture.jsonl`：实时捕获输出；`capture-screen.txt`：同一份真实捕获的离线屏幕输出。
- `report/main.tex`、`report/main.pdf`：使用本人南开模板的 LaTeX 源码和报告。
- `report/build-report.ps1`：从已保存证据更新表格并编译报告。
- `package.ps1`：创建 `dist/lab02_2412456_尚文轩.zip`，不包含私人展示指南或第三方安装程序。

Npcap 的 `ps_drop` 是驱动捕获丢弃统计，不能等同于端到端网络丢包率；`ps_ifdrop` 是否可用依赖平台。完整边界与架构见 `DESIGN.md`。
