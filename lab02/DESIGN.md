# 实验二设计与验收映射

## 目标

使用 C++17 和 Npcap API 在 Windows 上获取网卡列表、打开选定网卡并捕获本机数据帧。逐帧显示源 MAC、目的 MAC、偏移 12–13 的类型/长度字段、该字段之后第一个字节（偏移 14），同时提供时间、捕获长度和原始长度。默认只显示，不写硬盘抓包文件。

## 链路类型和边界

- 首先查询 `pcap_datalink`。只对 `DLT_EN10MB` 按以太网头解析；回环的 `DLT_NULL` 没有以太网 MAC，明确拒绝并提示选择 Ethernet/Wi-Fi 网卡，不能伪造 MAC。
- 目的 MAC 在 0–5，源 MAC 在 6–11，外层类型/长度在 12–13，均使用捕获长度 `caplen` 做边界检查；不足 14 字节时标记短帧。
- 原始必显“字段后首字节”始终是偏移 14，即 VLAN 帧的首个 TCI 字节也照常显示。另行解码 802.1Q/802.1ad 标签后，单独显示内层 EtherType 和实际负载首字节，不混淆两者。
- 值 <=1500 是 IEEE 802.3 长度；>=1536 是 EtherType；1501–1535 为保留区间。没有捕获到首字节时显示 N/A，不越界读取。
- MAC 直接显示捕获头中的字节；Npcap 在普通 Wi-Fi 模式下提供的 Ethernet 视图不等同于原始 802.11 无线头，也通常不包含 FCS。

## API 与生命周期

安全加载系统 Npcap DLL → `pcap_findalldevs` 获取网卡与 IPv4 → 用户选择/命令行指定 → `pcap_create` → 设置 snaplen、非混杂/可选混杂、读取缓冲期限 → `pcap_activate` → `pcap_datalink` → 可选 `pcap_compile/pcap_setfilter` → `pcap_setnonblock` → 循环 `pcap_next_ex` → 输出和统计 → `pcap_stats` → `pcap_close`、`pcap_freealldevs`。

采用非阻塞读取加短暂等待，确保无流量时也可以按 Q、Ctrl+C 或达到时间上限退出，不依赖“读取超时一定会在空闲时返回”的假设。所有资源由本项目的小型 RAII 资源管理器释放，不替代 Npcap API 学习。

## 交付和测试

1. 网卡枚举、Ethernet 捕获、屏幕字段展示、按键退出和限时退出。
2. 解析器边界测试：短帧、恰好 14 字节、IPv4/IPv6/ARP、长度字段、保留值、单/双 VLAN、截断 VLAN。
3. Npcap 真实网卡抓包，记录控制台证据；可选 `--save` 只用于复核真实帧，不是默认必需步骤。
4. 使用同一原始捕获数据对照屏幕字段与原始十六进制位置，不以合成帧冒充真实捕获。
5. 提交源码、Windows x64 exe、沿用南开模板的 LaTeX 源码和 PDF；私人展示指南继续放入被忽略的 `private-demo/`，提交 ZIP 使用白名单。

## 资料

- [Npcap 开发指南](https://npcap.com/guide/npcap-devguide.html)
- [Npcap pcap_next_ex 文档](https://npcap.com/guide/wpcap/pcap_next_ex.html)
- [Npcap 非阻塞模式](https://npcap.com/guide/wpcap/pcap_setnonblock.html)
