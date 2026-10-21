#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <pcap/pcap.h>
#include <cstring>
#include <stdexcept>
#include <string>

namespace lab02 {
// The SDK supplies all declarations. Runtime functions are resolved from the
// installed Npcap DLL, so --help and parser tests do not require the driver.
class NpcapApi {
    HMODULE module_ = nullptr;
    template<class Function>
    void resolve(Function& function, const char* name) {
        auto address = GetProcAddress(module_, name);
        if (!address) throw std::runtime_error(std::string("Npcap API missing: ") + name);
        // Windows defines GetProcAddress for resolving a function of this type.
        static_assert(sizeof(function) == sizeof(address), "Unexpected function pointer size");
        memcpy(&function, &address, sizeof(function));
    }
public:
#define NPCAP_FUNCTIONS(X) \
    X(pcap_init) X(pcap_lib_version) X(pcap_findalldevs) X(pcap_freealldevs) \
    X(pcap_create) X(pcap_set_snaplen) X(pcap_set_promisc) X(pcap_set_timeout) \
    X(pcap_set_buffer_size) X(pcap_activate) X(pcap_datalink) \
    X(pcap_compile) X(pcap_setfilter) X(pcap_freecode) X(pcap_setnonblock) \
    X(pcap_next_ex) X(pcap_geterr) X(pcap_stats) X(pcap_close) \
    X(pcap_open_offline) X(pcap_dump_open) X(pcap_dump) X(pcap_dump_close)
#define DECLARE_FUNCTION(name) decltype(&::name) name = nullptr;
    NPCAP_FUNCTIONS(DECLARE_FUNCTION)
#undef DECLARE_FUNCTION
    NpcapApi() {
        wchar_t system[MAX_PATH]{};
        const UINT length = GetSystemDirectoryW(system, MAX_PATH);
        if (!length || length >= MAX_PATH) throw std::runtime_error("GetSystemDirectory failed");
        std::wstring path = std::wstring(system) + L"\\Npcap\\wpcap.dll";
        module_ = LoadLibraryExW(path.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module_) throw std::runtime_error(
            "Npcap runtime not found/loadable in System32\\Npcap (Windows error "
            + std::to_string(GetLastError()) + "). Install Npcap from https://npcap.com/ .");
        try {
#define RESOLVE_FUNCTION(name) resolve(name, #name);
            NPCAP_FUNCTIONS(RESOLVE_FUNCTION)
#undef RESOLVE_FUNCTION
            char error[PCAP_ERRBUF_SIZE]{};
            if (pcap_init(PCAP_CHAR_ENC_UTF_8, error) != 0) throw std::runtime_error(error);
        } catch (...) { FreeLibrary(module_); module_ = nullptr; throw; }
    }
    ~NpcapApi() { if (module_) FreeLibrary(module_); }
    NpcapApi(const NpcapApi&) = delete;
    NpcapApi& operator=(const NpcapApi&) = delete;
};
#undef NPCAP_FUNCTIONS

struct Devices {
    NpcapApi& api;
    pcap_if_t* head = nullptr;
    explicit Devices(NpcapApi& instance) : api(instance) {
        char error[PCAP_ERRBUF_SIZE]{};
        if (api.pcap_findalldevs(&head, error) < 0) throw std::runtime_error(error);
    }
    ~Devices() { if (head) api.pcap_freealldevs(head); }
    Devices(const Devices&) = delete;
    Devices& operator=(const Devices&) = delete;
};
struct Capture {
    NpcapApi& api;
    pcap_t* handle = nullptr;
    explicit Capture(NpcapApi& instance) : api(instance) {}
    ~Capture() { if (handle) api.pcap_close(handle); }
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;
};
struct Dump {
    NpcapApi& api;
    pcap_dumper_t* handle = nullptr;
    explicit Dump(NpcapApi& instance) : api(instance) {}
    ~Dump() { if (handle) api.pcap_dump_close(handle); }
    Dump(const Dump&) = delete;
    Dump& operator=(const Dump&) = delete;
};
}
