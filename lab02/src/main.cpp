#include "npcap_api.hpp"
#include "ethernet.hpp"
#include <ws2tcpip.h>
#include <chrono>
#include <conio.h>
#include <ctime>
#include <iostream>
#include <io.h>
#include <limits>
#include <thread>

namespace {
using namespace lab02;
volatile LONG stopped = 0;
BOOL WINAPI on_console_event(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&stopped, 1);
        return TRUE;
    }
    return FALSE;
}

std::string json_string(const std::string& s) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 32) out << "\\u" << std::hex << std::setfill('0') << std::setw(4) << unsigned(c);
            else out << c;
        }
    }
    out << '"';
    return out.str();
}

template<class T> std::string nullable_hex(const std::optional<T>& value, unsigned width) {
    return value ? json_string(hex_value(*value, width)) : "null";
}

std::string timestamp(const timeval& value) {
    const std::time_t seconds = value.tv_sec;
    std::tm local{};
    localtime_s(&local, &seconds);
    char text[32];
    std::strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%S", &local);
    std::ostringstream out;
    out << text << '.' << std::setfill('0') << std::setw(6) << value.tv_usec;
    return out.str();
}

struct Options {
    bool list = false, json = false, promisc = false, help = false;
    std::string device, filter, read, save;
    unsigned count = 20, seconds = 30, snaplen = 65535;
};

unsigned number(const std::string& text, unsigned maximum) {
    if (text.empty() || text.find_first_not_of("0123456789") != text.npos)
        throw std::runtime_error("Expected nonnegative integer: " + text);
    const auto n = std::stoull(text);
    if (n > maximum) throw std::runtime_error("Number out of range: " + text);
    return static_cast<unsigned>(n);
}

Options options(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string key = argv[i];
        auto value = [&]() { if (++i >= argc) throw std::runtime_error("Missing value for " + key); return std::string(argv[i]); };
        if (key == "--help" || key == "-h") o.help = true;
        else if (key == "--list") o.list = true;
        else if (key == "--json") o.json = true;
        else if (key == "--promisc") o.promisc = true;
        else if (key == "--device" || key == "-i") o.device = value();
        else if (key == "--filter" || key == "-f") o.filter = value();
        else if (key == "--read") o.read = value();
        else if (key == "--save") o.save = value();
        else if (key == "--count" || key == "-c") o.count = number(value(), 1000000);
        else if (key == "--seconds") o.seconds = number(value(), 86400);
        else if (key == "--snaplen") o.snaplen = number(value(), 65535);
        else throw std::runtime_error("Unknown option: " + key);
    }
    if (o.snaplen < 14) throw std::runtime_error("snaplen must be 14..65535");
    if (!o.read.empty() && (!o.device.empty() || !o.save.empty() || o.promisc))
        throw std::runtime_error("--read cannot be combined with --device/--save/--promisc");
    return o;
}

void help() {
    std::cout << "实验02：Npcap 以太网帧捕获与分析（C++17）\n"
        "用法: packet_capture.exe [选项]\n"
        "  --list                 列出网卡编号、名称、IPv4\n"
        "  --device N|设备名称     选择网卡；省略时交互选择\n"
        "  --count N              捕获 N 帧后退出，默认20，0不限制\n"
        "  --seconds N            最长运行秒数，默认30，0不限制\n"
        "  --filter BPF           可选过滤器，如 \"arp or icmp\"\n"
        "  --snaplen N            捕获字节上限14..65535，默认65535\n"
        "  --promisc              可选混杂模式，默认关闭\n"
        "  --save FILE.pcap        可选保存原始帧，默认不写硬盘\n"
        "  --read FILE.pcap        从已保存帧复核解析\n"
        "  --json                 输出JSON Lines，供自动化复核\n"
        "  --help                 显示帮助\n"
        "运行中按 Q 或 Ctrl+C 正常停止。选择 Ethernet/Wi-Fi，回环无以太网MAC。\n";
}

void list_devices(pcap_if_t* head, bool json) {
    unsigned index = 0;
    for (auto* d = head; d; d = d->next) {
        ++index;
        std::vector<std::string> ips;
        for (auto* a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN]{};
                const auto* address = reinterpret_cast<sockaddr_in*>(a->addr);
                if (inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip))) ips.emplace_back(ip);
            }
        }
        if (json) {
            std::cout << "{\"event\":\"device\",\"index\":" << index
                << ",\"name\":" << json_string(d->name) << ",\"description\":"
                << json_string(d->description ? d->description : "") << ",\"ipv4\":[";
            for (size_t i = 0; i < ips.size(); ++i) {
                if (i) std::cout << ',';
                std::cout << json_string(ips[i]);
            }
            std::cout << "],\"flags\":" << d->flags << "}\n";
        } else {
            std::cout << '[' << index << "] " << (d->description ? d->description : "(no description)")
                << "\n    " << d->name << "\n    IPv4:";
            for (const auto& ip : ips) std::cout << ' ' << ip;
            if (ips.empty()) std::cout << " (none)";
            std::cout << ((d->flags & PCAP_IF_LOOPBACK) ? " [LOOPBACK: 无以太网MAC]" : "") << '\n';
        }
    }
}

pcap_if_t* select_device(pcap_if_t* head, const std::string& selection) {
    const bool numeric = !selection.empty() && selection.find_first_not_of("0123456789") == selection.npos;
    const unsigned wanted = numeric ? number(selection, 10000) : 0;
    unsigned index = 0;
    for (auto* d = head; d; d = d->next) {
        ++index;
        if ((numeric && index == wanted) || (!numeric && selection == d->name)) return d;
    }
    throw std::runtime_error("Device not found. Use --list and choose a valid index/name.");
}

void print_frame(unsigned index, const pcap_pkthdr& header, const uint8_t* data, bool json) {
    const auto f = parse_ethernet(data, header.caplen, header.len);
    const std::string time = timestamp(header.ts);
    if (json) {
        std::cout << "{\"event\":\"packet\",\"index\":" << index << ",\"time\":" << json_string(time)
            << ",\"source_mac\":" << (f.header_present ? json_string(f.source) : "null")
            << ",\"destination_mac\":" << (f.header_present ? json_string(f.destination) : "null")
            << ",\"type_length\":" << nullable_hex(f.outer_field, 4)
            << ",\"after_type\":" << nullable_hex(f.after_field, 2)
            << ",\"inner_type\":" << nullable_hex(f.inner_field, 4)
            << ",\"payload_first\":" << nullable_hex(f.payload_first, 2)
            << ",\"payload_offset\":" << f.payload_offset
            << ",\"captured_length\":" << header.caplen << ",\"original_length\":" << header.len
            << ",\"truncated\":" << (f.truncated ? "true" : "false")
            << ",\"protocol\":" << json_string(f.protocol) << ",\"detail\":" << json_string(f.detail)
            << ",\"vlans\":[";
        for (size_t i = 0; i < f.vlans.size(); ++i) {
            if (i) std::cout << ',';
            std::cout << "{\"tpid\":" << json_string(hex_value(f.vlans[i].tpid, 4))
                << ",\"tci\":" << json_string(hex_value(f.vlans[i].tci, 4))
                << ",\"vid\":" << (f.vlans[i].tci & 0x0fff) << '}';
        }
        std::cout << "]}\n";
    } else {
        std::cout << std::right << std::setw(4) << index << ' ' << time.substr(11)
            << ' ' << std::setw(17) << (f.header_present ? f.source : "N/A")
            << ' ' << std::setw(17) << (f.header_present ? f.destination : "N/A")
            << ' ' << std::setw(6) << (f.outer_field ? hex_value(*f.outer_field, 4) : "N/A")
            << ' ' << std::setw(4) << (f.after_field ? hex_value(*f.after_field, 2) : "N/A")
            << ' ' << header.caplen << '/' << header.len << ' ' << f.protocol;
        if (f.truncated) std::cout << " [TRUNCATED]";
        std::cout << '\n';
        if (!f.vlans.empty()) {
            std::cout << "     VLAN:";
            for (const auto& tag : f.vlans) std::cout << " VID=" << (tag.tci & 0x0fff);
            std::cout << " inner=" << (f.inner_field ? hex_value(*f.inner_field, 4) : "N/A")
                << " payload_first=" << (f.payload_first ? hex_value(*f.payload_first, 2) : "N/A") << '\n';
        }
        if (!f.detail.empty()) std::cout << "     " << f.detail << '\n';
    }
    std::cout.flush();
}

int run(int argc, char** argv) {
    const auto o = options(argc, argv);
    if (o.help) { help(); return 0; }
    NpcapApi api;
    if (o.json) std::cout << "{\"event\":\"runtime\",\"version\":" << json_string(api.pcap_lib_version()) << "}\n";
    else std::cout << api.pcap_lib_version() << '\n';

    if (o.list) { Devices devices(api); list_devices(devices.head, o.json); return 0; }
    Capture capture(api);
    char error[PCAP_ERRBUF_SIZE]{};
    std::string selected = o.device;
    if (!o.read.empty()) {
        capture.handle = api.pcap_open_offline(o.read.c_str(), error);
        if (!capture.handle) throw std::runtime_error(error);
    } else {
        Devices devices(api);
        if (selected.empty()) {
            if (o.json) throw std::runtime_error("--json capture requires --device or --read");
            list_devices(devices.head, false);
            std::cout << "请选择网卡编号（Ethernet/Wi-Fi）: " << std::flush;
            if (!std::getline(std::cin, selected)) throw std::runtime_error("No device selected");
        }
        auto* d = select_device(devices.head, selected);
        selected = d->name;
        capture.handle = api.pcap_create(d->name, error);
        if (!capture.handle) throw std::runtime_error(error);
        auto check = [&](int code) {
            if (code != 0) throw std::runtime_error(api.pcap_geterr(capture.handle));
        };
        check(api.pcap_set_snaplen(capture.handle, static_cast<int>(o.snaplen)));
        check(api.pcap_set_promisc(capture.handle, o.promisc ? 1 : 0));
        check(api.pcap_set_timeout(capture.handle, 100));
        check(api.pcap_set_buffer_size(capture.handle, 2 * 1024 * 1024));
        const int result = api.pcap_activate(capture.handle);
        if (result < 0) throw std::runtime_error(std::string("Activate failed: ") + api.pcap_geterr(capture.handle)
            + " (Check Npcap installation, adapter status, and administrator permissions.)");
        if (result > 0) std::cerr << "Npcap activation warning: " << api.pcap_geterr(capture.handle) << '\n';
    }
    const int linktype = api.pcap_datalink(capture.handle);
    if (linktype != DLT_EN10MB) throw std::runtime_error("Link type " + std::to_string(linktype)
        + " is not Ethernet (DLT_EN10MB=1). Loopback has no Ethernet MAC; choose Ethernet/Wi-Fi.");
    if (!o.filter.empty()) {
        bpf_program filter{};
        if (api.pcap_compile(capture.handle, &filter, o.filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
            throw std::runtime_error(std::string("BPF compile: ") + api.pcap_geterr(capture.handle));
        const int result = api.pcap_setfilter(capture.handle, &filter);
        api.pcap_freecode(&filter);
        if (result < 0) throw std::runtime_error(std::string("BPF setfilter: ") + api.pcap_geterr(capture.handle));
    }
    if (o.read.empty() && api.pcap_setnonblock(capture.handle, 1, error) < 0) throw std::runtime_error(error);
    Dump dump(api);
    if (!o.save.empty()) {
        dump.handle = api.pcap_dump_open(capture.handle, o.save.c_str());
        if (!dump.handle) throw std::runtime_error(api.pcap_geterr(capture.handle));
    }
    if (o.json) std::cout << "{\"event\":\"start\",\"device\":" << json_string(selected)
        << ",\"linktype\":" << linktype << ",\"offline\":" << (o.read.empty() ? "false" : "true") << "}\n";
    else std::cout << (o.read.empty() ? "实时捕获已开始" : "离线复核已开始")
        << "，按 Q 或 Ctrl+C 退出。Type字段为偏移12-13，After为偏移14。\n"
        " No. Time            SRC-MAC           DST-MAC           Type   After Cap/Wire Protocol\n";
    std::cout.flush();

    const auto start = std::chrono::steady_clock::now();
    unsigned received = 0, short_frames = 0, truncated = 0;
    std::string reason = "stopped";
    while (!InterlockedCompareExchange(&stopped, 0, 0)) {
        if (o.count && received >= o.count) { reason = "count"; break; }
        const auto elapsed = std::chrono::steady_clock::now() - start;
        if (o.seconds && elapsed >= std::chrono::seconds(o.seconds)) { reason = "time"; break; }
        if (_isatty(_fileno(stdin)) && _kbhit()) {
            const int key = _getch();
            if (key == 'q' || key == 'Q') { reason = "keyboard"; break; }
        }
        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;
        const int status = api.pcap_next_ex(capture.handle, &header, &packet);
        if (status == 1) {
            ++received;
            short_frames += header->caplen < 14 ? 1 : 0;
            truncated += header->caplen < header->len ? 1 : 0;
            print_frame(received, *header, packet, o.json);
            if (dump.handle) api.pcap_dump(reinterpret_cast<u_char*>(dump.handle), header, packet);
        } else if (status == 0) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        else if (status == PCAP_ERROR_BREAK) { reason = "eof"; break; }
        else throw std::runtime_error(std::string("Capture failed: ") + api.pcap_geterr(capture.handle));
    }
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    pcap_stat statistics{};
    const bool has_stats = o.read.empty() && api.pcap_stats(capture.handle, &statistics) == 0;
    if (o.json) {
        std::cout << "{\"event\":\"summary\",\"received\":" << received << ",\"short_frames\":" << short_frames
            << ",\"truncated\":" << truncated << ",\"elapsed_seconds\":" << elapsed
            << ",\"reason\":" << json_string(reason) << ",\"stats_available\":" << (has_stats ? "true" : "false")
            << ",\"ps_recv\":" << (has_stats ? std::to_string(statistics.ps_recv) : "null")
            << ",\"ps_drop\":" << (has_stats ? std::to_string(statistics.ps_drop) : "null")
            << ",\"ps_ifdrop\":" << (has_stats ? std::to_string(statistics.ps_ifdrop) : "null") << "}\n";
    } else {
        std::cout << "捕获结束: " << received << " 帧，短帧=" << short_frames << "，截断=" << truncated
            << "，耗时=" << elapsed << " 秒，原因=" << reason << '\n';
        if (has_stats) std::cout << "Npcap stats: ps_recv=" << statistics.ps_recv << " ps_drop=" << statistics.ps_drop
            << " ps_ifdrop=" << statistics.ps_ifdrop << " (driver counters, not end-to-end packet loss)\n";
        else std::cout << "Npcap stats: unavailable (offline captures have no live driver statistics)\n";
    }
    return 0;
}
}

int wmain(int argc, wchar_t** wide) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleCtrlHandler(on_console_event, TRUE);
    try {
        std::vector<std::string> args;
        for (int i = 0; i < argc; ++i) {
            const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide[i], -1, nullptr, 0, nullptr, nullptr);
            if (!size) throw std::runtime_error("Invalid UTF-16 argument");
            std::string text(size, '\0');
            WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, text.data(), size, nullptr, nullptr);
            text.pop_back(); args.push_back(std::move(text));
        }
        std::vector<char*> argv;
        for (auto& arg : args) argv.push_back(arg.data());
        return run(argc, argv.data());
    }
    catch (const std::exception& e) { std::cerr << "错误 / Error: " << e.what() << '\n'; return 1; }
}
