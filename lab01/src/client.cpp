#include "common.hpp"
using namespace chat;
int run(int argc,char** argv) {
    try {
        Winsock ws;
        if(argc!=4) { std::cout<<"用法: chat_client.exe IPv4 端口 昵称\n示例: chat_client.exe 127.0.0.1 9001 小明\n"; return 1; }
        if(!name_ok(argv[3])) throw std::runtime_error("Invalid nickname (1..32 UTF-8 bytes)");
        auto a=address(argv[1],std::stoi(argv[2])); SOCKET fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(fd==INVALID_SOCKET) throw std::runtime_error("socket failed");
        if(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))) { closesocket(fd); throw std::runtime_error("连接失败，请检查服务器地址和端口"); }
        timeout(fd,SO_SNDTIMEO,2000); timeout(fd,SO_RCVTIMEO,6000);
        uint32_t seq=1; Frame f{};
        if(!send_frame(fd,Hello,seq++,argv[3]) || !recv_frame(fd,f) || f.type!=Welcome) {
            std::cerr<<"登录失败: "<<f.body<<std::endl; closesocket(fd); return 1; }
        timeout(fd,SO_RCVTIMEO,0); std::cout<<f.body<<std::endl; help();
        std::atomic<bool> running{true};
        std::thread receiver([&] {
            try { Frame event{}; while(recv_frame(fd,event)) {
                const char* label=event.type==Message?"群聊":event.type==Direct?"私聊":event.type==Users?"在线":event.type==Error?"错误":"系统";
                std::string display=event.body; for(char& c:display) if(c=='\n') c=' ';
                std::cout<<"["<<label<<" #"<<event.seq<<"] "<<display<<std::endl;
                if(event.type==Bye) break;
            } } catch(const std::exception& e) { std::cerr<<e.what()<<std::endl; }
            running=false;
        });
        try {
            std::string input;
            while(running) {
                if(!line(input,running)) { if(running) send_frame(fd,Quit,seq++,""); break; }
                if(input.empty()) continue;
                if(input=="/help") { help(); continue; }
                uint16_t type=Chat; std::string body=input;
                if(input=="/quit") { type=Quit; body.clear(); }
                else if(input=="/list") { type=List; body.clear(); }
                else if(input.rfind("/msg ",0)==0) {
                    auto p=input.find(' ',5); if(p==input.npos) { std::cout<<"用法 /msg 昵称 内容\n"; continue; }
                    type=Private; body=input.substr(5,p-5)+"\n"+input.substr(p+1);
                } else if(input[0]=='/') { std::cout<<"未知命令，输入 /help\n"; continue; }
                if(!send_frame(fd,type,seq++,body)) { shutdown(fd,SD_BOTH); break; }
                if(type==Quit) break;
            }
        } catch(...) { shutdown(fd,SD_BOTH); receiver.join(); closesocket(fd); throw; }
        // Bound the wait for BYE even if a peer stops responding after QUIT.
        auto until=std::chrono::steady_clock::now()+std::chrono::seconds(3);
        while(running && std::chrono::steady_clock::now()<until) std::this_thread::sleep_for(std::chrono::milliseconds(20));
        shutdown(fd,SD_BOTH); receiver.join(); closesocket(fd); std::cout<<"客户端已退出"<<std::endl;
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<std::endl; return 1; }
}
// Windows command lines are UTF-16; converting explicitly preserves Chinese nicknames.
int wmain(int argc,wchar_t** wide) {
    std::vector<std::string> args;
    for(int i=0;i<argc;++i) {
        int n=WideCharToMultiByte(CP_UTF8,0,wide[i],-1,nullptr,0,nullptr,nullptr);
        std::string s(n,'\0'); WideCharToMultiByte(CP_UTF8,0,wide[i],-1,s.data(),n,nullptr,nullptr);
        s.pop_back(); args.push_back(std::move(s));
    }
    std::vector<char*> argv; for(auto& s:args) argv.push_back(s.data());
    return run(argc,argv.data());
}
