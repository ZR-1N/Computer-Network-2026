#include "engine.hpp"

int wmain(int argc,wchar_t** wide) {
    using namespace rudp;
    SetConsoleCP(CP_UTF8);SetConsoleOutputCP(CP_UTF8);SetConsoleCtrlHandler(control,TRUE);
    Metrics metrics;
    std::string stats;
    int code=0;
    try {
        auto args=utf8_arguments(argc,wide);std::vector<char*> argv;
        for(auto& arg:args)argv.push_back(arg.data());
        Options options(argc,argv.data());stats=options.get("--stats");
        if(options.mode=="help" || options.mode=="--help") {
            log("实验03：RUDP-SR/1 固定窗口选择重传（Windows C++17）\n"
                "  rudp.exe recv --port 9002 --output received.bin --window 16\n"
                "  rudp.exe send --peer 127.0.0.1 --port 9002 --file input.bin --window 16\n"
                "  rudp.exe relay --port 9001 --target-port 9002 --loss 0.1 --delay-ms 8\n"
                "经过relay时，发送端目标端口改为9001。双方窗口必须相同（1..64）。\n"
                "收发参数：--bind IPv4 --rto-ms 150 --retries 40 --idle-ms 10000\n"
                "发送参数：--chunk 1200 --local-port 0；接收端禁止覆盖既有目标及.part。\n"
                "日志/统计：--verbose --stats result.json；Ctrl+C 正常中断并清理。\n"
                "relay参数：--target IPv4 --corrupt 0..1 --duplicate 0..1 --jitter-ms N\n"
                " --seed N --seconds 120 --drop-data 2,5 --corrupt-data 3 --delay-data 0\n"
                " --reorder-ms 60 --drop-type SYN:1,FIN_ACK:1；relay按q或输入quit退出。");
            return 0;
        }
        Winsock winsock;
        if(options.mode=="relay"){relay(options);return 0;}
        if(options.mode=="send")sender(options,metrics);
        else if(options.mode=="recv")receiver(options,metrics);
        else throw std::runtime_error("Mode must be send, recv or relay");
    } catch(const std::exception& e) {metrics.error=e.what();metrics.success=false;code=1;std::cerr<<"ERROR "<<e.what()<<std::endl;}
    log("RESULT "+metrics.json());
    if(!stats.empty()) {
        std::ofstream out(std::filesystem::u8path(stats));out<<metrics.json()<<'\n';
        if(!out){std::cerr<<"ERROR cannot write stats"<<std::endl;return 1;}
    }
    return code;
}
