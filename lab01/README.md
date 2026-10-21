# 实验一：TCP 多线程中英文聊天室

## 直接运行（Windows x64）

不需要 Python、CMake 或编译器即可运行 `bin/` 内的两个 exe。
在本目录打开 PowerShell，先启动服务器：

```powershell
.\bin\chat_server.exe 127.0.0.1 9001
```

在另外三个终端分别启动客户端：

```powershell
.\bin\chat_client.exe 127.0.0.1 9001 小明
.\bin\chat_client.exe 127.0.0.1 9001 Alice
.\bin\chat_client.exe 127.0.0.1 9001 小红
```

|操作|效果|
|---|---|
|直接输入文字并回车|群聊，包含发送者自己|
|`/msg Alice 你好 Hello`|私聊，仅发送者和 Alice 看见|
|`/list`|查看当前在线用户|
|`/help`|显示帮助|
|`/quit`|客户端正常退出；服务器中输入此命令则通知客户端并停机|

昵称 1–32 个 UTF-8 字节、不可含空格或 `/`；正文最多 4096 字节。消息含服务器本机时间。
默认端口 9001，可改为 1–65535 中未占用的端口。最多 64 个并发会话。
中文显示建议使用 Windows Terminal 和支持中文的字体。程序内设置 UTF-8，不必更改系统区域设置。

跨主机时将服务器监听地址和客户端目标地址改为服务器实际局域网 IPv4，按现场规则允许该端口通过防火墙。本次自动化数据来自本机回环，未冒充跨主机实测。

## 从源码编译

推荐 Visual Studio 2019/2022 C++ Build Tools：

```powershell
.\build.ps1
```

脚本自动通过 vswhere 查找 MSVC，使用 C++17、`/W4 /utf-8 /MT` 编译并链接 `ws2_32.lib`。静态运行库便于拷贝运行。
现代 MinGW-w64 可用 `./build.ps1 -Compiler MinGW`；不支持标准线程的旧版 MinGW 不适用。
也可在 Visual Studio 开发者终端通过 CMake 构建：

```powershell
cmake -S . -B ../build/lab01
cmake --build ../build/lab01 --config Release
```

## 复核实验

从仓库根目录运行 `python lab01/tests/integration.py`，驱动真实 C++ exe，生成 `evidence/results.json` 和逐项日志。Python 只是测试工具；聊天程序完全为 C++。

14 项测试包括拆包/粘包、中文私聊、64 会话容量、80 次重连、输入 EOF、服务器退出和异常帧。并发测试为 4 客户端 × 每人 300 条消息，共 4800 次预期投递。

`TCP_STATS` 来自 Windows 按连接 TCP 统计。本次服务端四条压力测试连接均记录重传字节 0；这不等同于所有链路永不丢包。

`tests/capture-admin.ps1` 提供独立抓包复现，需要管理员 PowerShell。先用 `-Mode Preflight` 检查，确认无其他抓包任务后再使用 `-Mode Capture -Python python`。脚本只捕获 TCP 9001，并在结束时恢复原本为空的筛选器；已有筛选器时拒绝修改。
本次 Pktmon 回环记录含两个关闭阶段 FIN-WAIT2 丢弃事件，均为无载荷 ACK；正常流量没有被该抓包点完整记录。`evidence/capture-summary.json`、ETL、PCAPNG 和正确标识原始 IP 类型的分析副本 `chat-drops-raw.pcap` 一并保留。

## 报告与打包

报告为 `report/main.pdf`，LaTeX 主文件为 `report/main.tex`，沿用作者提供的南开模板并保留模板许可。
执行 `./report/build-report.ps1` 从已保存实测结果重新生成表格并运行两次 XeLaTeX。
执行 `./package.ps1` 生成仓库根目录 `dist/` 下的提交 ZIP；只包含显式允许的实验文件，不包含私人展示指南、Git 元数据或编译临时文件。

完整协议见 `PROTOCOL.md`。本程序面向教学局域网环境，不提供账号认证、加密或离线消息。
