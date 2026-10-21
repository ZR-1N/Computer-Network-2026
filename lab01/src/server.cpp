#include "common.hpp"
#include <algorithm>
#include <memory>
using namespace chat;
namespace {
struct Session { SOCKET socket; std::string name; bool active=false; std::atomic<bool> done{false}; std::thread thread; };
std::mutex room;
std::vector<std::shared_ptr<Session>> sessions;
uint32_t event_seq=0;
std::atomic<bool> running{true};
void emit(Session& s,uint16_t type,const std::string& payload) {
    if(!send_frame(s.socket,type,++event_seq,now()+"\n"+payload)) shutdown(s.socket,SD_BOTH);
}
void broadcast(uint16_t type,const std::string& payload,Session* except=nullptr) {
    for(auto& s:sessions) if(s->active && s.get()!=except) emit(*s,type,payload);
}
void serve(std::shared_ptr<Session> s) {
    uint32_t expected=1;
    try {
        Frame f{};
        // A deadline limits total handshake time even if bytes arrive very slowly.
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        std::atomic<bool> handshake_done{false};
        std::thread guard([&] { while(!handshake_done && running && std::chrono::steady_clock::now()<deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            if(!handshake_done) shutdown(s->socket,SD_BOTH); });
        bool first=false;
        try { first=recv_frame(s->socket,f); } catch(...) { handshake_done=true; guard.join(); throw; }
        handshake_done=true; guard.join();
        if(!first) throw std::runtime_error("Handshake EOF/timeout");
        {
            std::lock_guard<std::mutex> lock(room);
            if(!running) throw std::runtime_error("Server stopping");
            if(f.type!=Hello || f.seq!=expected++ || !name_ok(f.body)) throw std::runtime_error("Expected HELLO with valid nickname");
            for(auto& p:sessions) if(p->active && p->name==f.body) throw std::runtime_error("Nickname already in use");
            s->name=f.body; s->active=true;
            emit(*s,Welcome,"欢迎 "+s->name); broadcast(Notice,s->name+" 上线",s.get());
            std::cout<<"["<<now()<<"] JOIN "<<s->name<<std::endl;
        }
        while(running && recv_frame(s->socket,f)) {
            std::lock_guard<std::mutex> lock(room);
            if(f.seq!=expected++) throw std::runtime_error("Request sequence must increase from 1");
            if(f.type==Chat) {
                if(!text_ok(f.body)) { emit(*s,Error,"正文应为 1..4096 字节 UTF-8 单行文本"); continue; }
                broadcast(Message,s->name+"\n"+f.body);
                std::cout<<"["<<now()<<"] CHAT "<<s->name<<": "<<f.body<<std::endl;
            } else if(f.type==Private) {
                auto p=f.body.find('\n'); std::string target=f.body.substr(0,p);
                if(p==f.body.npos || !name_ok(target) || !text_ok(f.body.substr(p+1))) { emit(*s,Error,"私聊格式错误"); continue; }
                auto it=std::find_if(sessions.begin(),sessions.end(),[&](const auto& x){ return x->active && x->name==target; });
                if(it==sessions.end()) { emit(*s,Error,"目标用户不在线"); continue; }
                std::string body=s->name+"\n"+target+"\n"+f.body.substr(p+1);
                emit(*s,Direct,body); if(it->get()!=s.get()) emit(**it,Direct,body);
            } else if(f.type==List && f.body.empty()) {
                std::string names; for(auto& p:sessions) if(p->active) names+=(names.empty()?"":" ")+p->name;
                emit(*s,Users,names);
            } else if(f.type==Quit && f.body.empty()) { emit(*s,Bye,"正常退出"); break; }
            else throw std::runtime_error("Unexpected request type or payload");
        }
    } catch(const std::exception& e) {
        std::lock_guard<std::mutex> lock(room); emit(*s,Error,e.what());
    }
    {
        std::lock_guard<std::mutex> lock(room);
        if(s->active) { s->active=false; broadcast(Notice,s->name+" 离线");
            std::cout<<"["<<now()<<"] LEAVE "<<s->name<<std::endl; }
        tcp_stats(s->socket,s->name);
        shutdown(s->socket,SD_BOTH); closesocket(s->socket); s->done=true;
    }
}
}
int main(int argc,char** argv) {
    try {
        Winsock ws; auto a=address(argc>1?argv[1]:"127.0.0.1",argc>2?std::stoi(argv[2]):9001);
        SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(listener==INVALID_SOCKET) throw std::runtime_error("socket failed");
        BOOL exclusive=TRUE; setsockopt(listener,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<char*>(&exclusive),sizeof(exclusive));
        if(bind(listener,reinterpret_cast<sockaddr*>(&a),sizeof(a)) || listen(listener,SOMAXCONN)) {
            closesocket(listener); throw std::runtime_error("bind/listen failed; check address and port"); }
        std::cout<<"TCP 聊天服务器 "<<(argc>1?argv[1]:"127.0.0.1")<<":"<<(argc>2?argv[2]:"9001")<<" | /quit 停止服务器"<<std::endl;
        std::thread acceptor([&] {
            while(running) {
                fd_set set; FD_ZERO(&set); FD_SET(listener,&set); timeval tv{0,100000};
                int ready=select(0,&set,nullptr,nullptr,&tv); if(ready<=0) continue;
                SOCKET fd=accept(listener,nullptr,nullptr); if(fd==INVALID_SOCKET) continue;
                std::lock_guard<std::mutex> lock(room);
                // Only completed workers are joined here; done is set after releasing all resources.
                for(auto it=sessions.begin();it!=sessions.end();) {
                    if((*it)->done) { (*it)->thread.join(); it=sessions.erase(it); } else ++it;
                }
                if(!running || sessions.size()>=64) { closesocket(fd); continue; }
                try { timeout(fd,SO_SNDTIMEO,2000); } catch(...) { closesocket(fd); continue; }
                auto s=std::make_shared<Session>(); s->socket=fd; sessions.push_back(s); s->thread=std::thread(serve,s);
            }
        });
        try {
            std::string input; while(line(input,running)) { if(input=="/quit") break; std::cout<<"输入 /quit 停止服务器"<<std::endl; }
        } catch(const std::exception& e) { std::cerr<<e.what()<<std::endl; }
        running=false; acceptor.join(); closesocket(listener);
        { std::lock_guard<std::mutex> lock(room); for(auto& s:sessions) if(!s->done) {
            if(s->active) emit(*s,Bye,"服务器关闭");
            shutdown(s->socket,SD_BOTH); } }
        for(auto& s:sessions) if(s->thread.joinable()) s->thread.join();
        std::cout<<"服务器已正常退出"<<std::endl;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
