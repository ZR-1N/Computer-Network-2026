#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000003
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mstcpip.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace chat {
enum Type : uint16_t { Hello=1, Welcome, Chat, Message, Private, Direct,
    List, Users, Quit, Bye, Notice, Error };
struct Frame { uint16_t type; uint32_t seq; std::string body; };
struct Winsock {
    Winsock() { WSADATA d{}; if (WSAStartup(MAKEWORD(2,2), &d)) throw std::runtime_error("WSAStartup failed");
        SetConsoleCP(CP_UTF8); SetConsoleOutputCP(CP_UTF8); }
    ~Winsock() { WSACleanup(); }
};
inline bool utf8(const std::string& s) {
    return s.empty() || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        s.data(), static_cast<int>(s.size()), nullptr, 0) > 0;
}
inline bool clean(const std::string& s) {
    return utf8(s) && s.find('\0')==s.npos && s.find('\r')==s.npos;
}
inline bool name_ok(const std::string& s) {
    if (s.empty() || s.size()>32 || !clean(s)) return false;
    for (unsigned char c : s) if(c<=32 || c==127 || c=='/') return false;
    return true;
}
inline bool text_ok(const std::string& s) {
    return !s.empty() && s.size()<=4096 && clean(s) && s.find('\n')==s.npos;
}
inline std::string now() {
    std::time_t t=std::time(nullptr); std::tm tm{}; localtime_s(&tm,&t);
    char out[32]; std::strftime(out,sizeof(out),"%Y-%m-%d %H:%M:%S",&tm); return out;
}
inline bool send_all(SOCKET s, const char* p, size_t n) {
    while(n) { int k=send(s,p,static_cast<int>(n),0); if(k<=0) return false; p+=k; n-=k; } return true;
}
inline bool recv_all(SOCKET s, char* p, size_t n) {
    while(n) { int k=recv(s,p,static_cast<int>(n),0); if(k<=0) return false; p+=k; n-=k; } return true;
}
inline bool send_frame(SOCKET s,uint16_t type,uint32_t seq,const std::string& body) {
    uint32_t h[4]={htonl(0x434e4554),htonl((1u<<16)|type),
        htonl(static_cast<uint32_t>(body.size())),htonl(seq)};
    return send_all(s,reinterpret_cast<char*>(h),sizeof(h)) && send_all(s,body.data(),body.size());
}
// Untrusted lengths are checked before allocating memory.
inline bool recv_frame(SOCKET s,Frame& f) {
    uint32_t h[4]; if(!recv_all(s,reinterpret_cast<char*>(h),sizeof(h))) return false;
    for(auto& x:h) x=ntohl(x);
    if(h[0]!=0x434e4554 || (h[1]>>16)!=1 || (h[1]&65535)<1 || (h[1]&65535)>12 || h[2]>16384)
        throw std::runtime_error("Invalid frame header");
    f.type=static_cast<uint16_t>(h[1]&65535); f.seq=h[3]; f.body.resize(h[2]);
    if(!recv_all(s,f.body.data(),f.body.size())) return false;
    if(!clean(f.body)) throw std::runtime_error("Invalid UTF-8 or control byte");
    return true;
}
inline sockaddr_in address(const std::string& ip,int port) {
    sockaddr_in a{}; a.sin_family=AF_INET; a.sin_port=htons(static_cast<u_short>(port));
    if(port<1 || port>65535 || inet_pton(AF_INET,ip.c_str(),&a.sin_addr)!=1)
        throw std::runtime_error("Use an IPv4 address and port 1..65535");
    return a;
}
inline void timeout(SOCKET s,int opt,DWORD ms) {
    if(setsockopt(s,SOL_SOCKET,opt,reinterpret_cast<const char*>(&ms),sizeof(ms))==SOCKET_ERROR)
        throw std::runtime_error("setsockopt failed");
}
inline void help() {
    std::cout<<"输入文字群聊 | /msg 昵称 内容 私聊 | /list 在线列表 | /help 帮助 | /quit 正常退出\n";
}
inline void tcp_stats(SOCKET socket,const std::string& peer) {
#ifdef SIO_TCP_INFO
    DWORD version=0, size=0; TCP_INFO_v0 info{};
    if(WSAIoctl(socket,SIO_TCP_INFO,&version,sizeof(version),&info,sizeof(info),&size,nullptr,nullptr)==0) {
        std::cout<<"TCP_STATS peer="<<peer<<" BytesOut="<<info.BytesOut<<" BytesIn="<<info.BytesIn
            <<" BytesRetrans="<<info.BytesRetrans<<" DupAcksIn="<<info.DupAcksIn
            <<" TimeoutEpisodes="<<info.TimeoutEpisodes<<std::endl;
    } else std::cout<<"TCP_STATS unavailable WSA="<<WSAGetLastError()<<std::endl;
#else
    (void)socket; (void)peer;
    std::cout<<"TCP_STATS unavailable in this SDK"<<std::endl;
#endif
}
// Poll console input so remote shutdown never leaves main blocked in getline.
// Redirected pipes are supported for repeatable integration tests.
inline bool line(std::string& result,const std::atomic<bool>& running) {
    HANDLE h=GetStdHandle(STD_INPUT_HANDLE); DWORD mode{}; result.clear();
    if(GetConsoleMode(h,&mode)) {
        std::wstring w;
        while(running) {
            if(WaitForSingleObject(h,100)!=WAIT_OBJECT_0) continue;
            INPUT_RECORD rec{}; DWORD n{};
            if(!ReadConsoleInputW(h,&rec,1,&n)) return false;
            if(rec.EventType!=KEY_EVENT || !rec.Event.KeyEvent.bKeyDown) continue;
            wchar_t c=rec.Event.KeyEvent.uChar.UnicodeChar;
            if(c==L'\r') {
                std::cout<<'\n'; int k=WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);
                result.resize(k); WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),result.data(),k,nullptr,nullptr); return true;
            }
            if(c==L'\b') { if(!w.empty()) { w.pop_back(); std::cout<<"\b \b"<<std::flush; } }
            else if(c>=32 && w.size()<4096) { w+=c; DWORD written; WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE),&c,1,&written,nullptr); }
        } return false;
    }
    while(running) {
        if(GetFileType(h)==FILE_TYPE_PIPE) {
            DWORD avail{}; if(!PeekNamedPipe(h,nullptr,0,nullptr,&avail,nullptr)) return !result.empty();
            if(!avail) { std::this_thread::sleep_for(std::chrono::milliseconds(20)); continue; }
        }
        char c; DWORD n{}; if(!ReadFile(h,&c,1,&n,nullptr) || !n) return !result.empty();
        if(c=='\n') return true;
        if(c!='\r') result+=c;
        if(result.size()>16384) throw std::runtime_error("Input line too long");
    } return false;
}
}
