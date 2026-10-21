#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include "wire.hpp"

namespace rudp {
using Clock=std::chrono::steady_clock;
inline volatile LONG stopping=0;
inline BOOL WINAPI control(DWORD event) {
    if(event==CTRL_C_EVENT || event==CTRL_BREAK_EVENT || event==CTRL_CLOSE_EVENT) {
        InterlockedExchange(&stopping,1);return TRUE;
    } return FALSE;
}
inline void check_stop() {
    if(InterlockedCompareExchange(&stopping,0,0)) throw std::runtime_error("Interrupted by user");
}
struct Winsock {
    Winsock() { WSADATA d{};if(WSAStartup(MAKEWORD(2,2),&d))throw std::runtime_error("WSAStartup failed"); }
    ~Winsock(){WSACleanup();}
};
struct SocketGuard {
    SOCKET value=INVALID_SOCKET;
    ~SocketGuard(){if(value!=INVALID_SOCKET)closesocket(value);}
    SocketGuard()=default;
    SocketGuard(const SocketGuard&)=delete;
    SocketGuard& operator=(const SocketGuard&)=delete;
};
inline sockaddr_in address(const std::string& ip,unsigned port) {
    sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(static_cast<u_short>(port));
    if(port>65535 || inet_pton(AF_INET,ip.c_str(),&a.sin_addr)!=1)throw std::runtime_error("Use IPv4 and port 0..65535");
    return a;
}
inline bool same_peer(const sockaddr_in& a,const sockaddr_in& b) {
    return a.sin_family==b.sin_family && a.sin_port==b.sin_port && a.sin_addr.s_addr==b.sin_addr.s_addr;
}
inline SOCKET udp_socket(const sockaddr_in& local) {
    SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(s==INVALID_SOCKET)throw std::runtime_error("socket failed");
    BOOL exclusive=TRUE;
    setsockopt(s,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<char*>(&exclusive),sizeof(exclusive));
    int buffer=4*1024*1024;
    setsockopt(s,SOL_SOCKET,SO_RCVBUF,reinterpret_cast<char*>(&buffer),sizeof(buffer));
    if(bind(s,reinterpret_cast<const sockaddr*>(&local),sizeof(local))==SOCKET_ERROR) {
        const int error=WSAGetLastError();closesocket(s);throw std::runtime_error("bind failed WSA="+std::to_string(error));
    } return s;
}
inline void send_raw(SOCKET s,const sockaddr_in& peer,const Bytes& bytes) {
    const int n=sendto(s,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),0,
        reinterpret_cast<const sockaddr*>(&peer),sizeof(peer));
    if(n!=static_cast<int>(bytes.size()))throw std::runtime_error("sendto failed WSA="+std::to_string(WSAGetLastError()));
}
inline bool receive_raw(SOCKET s,Bytes& bytes,sockaddr_in& peer,unsigned wait_ms) {
    check_stop();fd_set set;FD_ZERO(&set);FD_SET(s,&set);
    timeval timeout{static_cast<long>(wait_ms/1000),static_cast<long>((wait_ms%1000)*1000)};
    const int ready=select(0,&set,nullptr,nullptr,&timeout);
    if(ready==SOCKET_ERROR)throw std::runtime_error("select failed");
    if(!ready)return false;
    std::array<char,65536> buffer{};int size=sizeof(peer);
    const int n=recvfrom(s,buffer.data(),static_cast<int>(buffer.size()),0,reinterpret_cast<sockaddr*>(&peer),&size);
    if(n==SOCKET_ERROR) {
        if(WSAGetLastError()==WSAECONNRESET)return false;
        throw std::runtime_error("recvfrom failed WSA="+std::to_string(WSAGetLastError()));
    }
    bytes.assign(buffer.begin(),buffer.begin()+n);return true;
}
inline std::string quote(const std::string& s) {
    std::string out="\"";
    for(unsigned char c:s) {
        if(c=='"'||c=='\\'){out+='\\';out+=c;}
        else if(c=='\n')out+="\\n";
        else if(c=='\r')out+="\\r";
        else if(c<32)out+='?';else out+=c;
    } return out+'"';
}
struct Options {
    std::string mode;
    std::map<std::string,std::string> values;
    Options(int argc,char** argv) {
        if(argc<2) { mode="help";return; }
        mode=argv[1];
        for(int i=2;i<argc;++i) {
            const std::string key=argv[i];
            if(key=="--verbose")values[key]="1";
            else {
                if(key.rfind("--",0)!=0 || i+1>=argc)throw std::runtime_error("Invalid/missing option value: "+key);
                if(values.count(key))throw std::runtime_error("Duplicate option: "+key);
                values[key]=argv[++i];
            }
        }
    }
    std::string get(const std::string& key,const std::string& fallback="")const {
        auto it=values.find(key);return it==values.end()?fallback:it->second;
    }
    uint64_t number(const std::string& key,uint64_t fallback,uint64_t maximum)const {
        const auto text=get(key,std::to_string(fallback));
        if(text.empty() || text.find_first_not_of("0123456789")!=text.npos)throw std::runtime_error("Expected unsigned integer: "+key);
        const auto n=std::stoull(text);if(n>maximum)throw std::runtime_error("Option out of range: "+key);return n;
    }
    void allow(const std::vector<std::string>& names)const {
        for(const auto& item:values)if(std::find(names.begin(),names.end(),item.first)==names.end())
            throw std::runtime_error("Unknown option: "+item.first);
    }
};
inline void log(const std::string& message) {std::cout<<message<<std::endl;}
inline double seconds(Clock::time_point start,Clock::time_point end=Clock::now()) {
    return std::chrono::duration<double>(end-start).count();
}
inline std::string hex64(uint64_t n) {std::ostringstream s;s<<std::hex<<n;return s.str();}
inline std::vector<std::string> utf8_arguments(int argc,wchar_t** wide) {
    std::vector<std::string> args;
    for(int i=0;i<argc;++i) {
        const int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide[i],-1,nullptr,0,nullptr,nullptr);
        if(!n)throw std::runtime_error("Invalid UTF-16 argument");
        std::string s(n,'\0');WideCharToMultiByte(CP_UTF8,0,wide[i],-1,s.data(),n,nullptr,nullptr);
        s.pop_back();args.push_back(std::move(s));
    } return args;
}
}
