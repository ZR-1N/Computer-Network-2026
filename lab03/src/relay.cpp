#include "engine.hpp"
#include <conio.h>
#include <io.h>
#include <cmath>

namespace rudp {
namespace {
double probability(const Options& o,const std::string& key) {
    const auto text=o.get(key,"0");size_t end=0;
    const double p=std::stod(text,&end);
    if(end!=text.size() || !std::isfinite(p) || p<0 || p>1)throw std::runtime_error(key+" must be 0..1");
    return p;
}
std::set<uint32_t> sequence_set(const std::string& text) {
    std::set<uint32_t> result;std::istringstream stream(text);std::string item;
    while(std::getline(stream,item,',')) {
        if(item.empty() || item.find_first_not_of("0123456789")!=item.npos)throw std::runtime_error("Invalid DATA sequence list");
        const auto n=std::stoull(item);if(n>UINT32_MAX)throw std::runtime_error("Sequence too large");
        result.insert(static_cast<uint32_t>(n));
    } return result;
}
bool quit_input() {
    HANDLE input=GetStdHandle(STD_INPUT_HANDLE);DWORD available=0;
    if(GetFileType(input)==FILE_TYPE_PIPE && PeekNamedPipe(input,nullptr,0,nullptr,&available,nullptr) && available) {
        char buffer[64];DWORD read=0;
        if(ReadFile(input,buffer,std::min<DWORD>(available,sizeof(buffer)),&read,nullptr)) {
            static std::string text;text.append(buffer,read);
            if(text.find("quit\n")!=text.npos || text.find("quit\r\n")!=text.npos)return true;
        }
    }
    return _isatty(_fileno(stdin)) && _kbhit() && (_getch()=='q');
}
}
void relay(const Options& o) {
    o.allow({"--bind","--port","--target","--target-port","--loss","--corrupt","--duplicate","--delay-ms",
        "--jitter-ms","--seed","--seconds","--drop-data","--corrupt-data","--delay-data","--reorder-ms",
        "--drop-type","--drop-ack-base","--verbose","--stats"});
    const auto target=address(o.get("--target","127.0.0.1"),static_cast<unsigned>(o.number("--target-port",9002,65535)));
    if(!target.sin_port)throw std::runtime_error("Target port cannot be zero");
    const unsigned delay=static_cast<unsigned>(o.number("--delay-ms",0,60000));
    const unsigned jitter=static_cast<unsigned>(o.number("--jitter-ms",0,60000));
    const unsigned reorder=static_cast<unsigned>(o.number("--reorder-ms",60,60000));
    const unsigned duration=static_cast<unsigned>(o.number("--seconds",120,86400));
    const double loss=probability(o,"--loss"),corrupt=probability(o,"--corrupt"),duplicate=probability(o,"--duplicate");
    const bool verbose=o.get("--verbose")=="1";
    auto drop_seq=sequence_set(o.get("--drop-data")),bad_seq=sequence_set(o.get("--corrupt-data")),delay_seq=sequence_set(o.get("--delay-data"));
    auto drop_ack=sequence_set(o.get("--drop-ack-base"));
    std::map<Type,unsigned> drop_types;
    std::istringstream drop_stream(o.get("--drop-type"));std::string item;
    while(std::getline(drop_stream,item,',')) {
        const auto colon=item.find(':');const auto name=item.substr(0,colon);
        unsigned count=1;
        if(colon!=item.npos) {
            const auto value=item.substr(colon+1);
            if(value.empty() || value.find_first_not_of("0123456789")!=value.npos)throw std::runtime_error("Invalid drop-type count");
            const auto n=std::stoull(value);if(n>10000)throw std::runtime_error("Drop count too large");count=static_cast<unsigned>(n);
        }
        bool found=false;
        for(unsigned type=1;type<=9;++type)if(name==type_name(static_cast<Type>(type))) {
            drop_types[static_cast<Type>(type)]=count;found=true;break;
        }
        if(!found)throw std::runtime_error("Unknown drop-type: "+name);
    }
    SocketGuard socket;socket.value=udp_socket(address(o.get("--bind","127.0.0.1"),static_cast<unsigned>(o.number("--port",9001,65535))));
    sockaddr_in sender_peer{};bool known_sender=false;
    struct Delivery { Bytes bytes;sockaddr_in peer; };
    std::multimap<Clock::time_point,Delivery> queue;
    std::mt19937 random(static_cast<uint32_t>(o.number("--seed",2026,UINT32_MAX)));
    std::uniform_real_distribution<double> chance(0,1);
    std::uniform_int_distribution<unsigned> variation(0,jitter);
    uint64_t received=0,forwarded=0,dropped=0,corrupted=0,duplicated=0,max_queue=0;
    const auto begin=Clock::now();
    log("RELAY_READY UDP bidirectional loss="+std::to_string(loss)+" one_way_delay_ms="+std::to_string(delay));
    try {
        while(!InterlockedCompareExchange(&stopping,0,0)) {
            if((duration && seconds(begin)>=duration) || quit_input())break;
            const auto now=Clock::now();
            while(!queue.empty() && queue.begin()->first<=now) {
                auto it=queue.begin();send_raw(socket.value,it->second.peer,it->second.bytes);queue.erase(it);++forwarded;
            }
            Bytes raw;sockaddr_in source{};
            if(!receive_raw(socket.value,raw,source,1))continue;
            ++received;
            const bool backward=same_peer(source,target);
            if(!backward && !known_sender){sender_peer=source;known_sender=true;}
            if(!known_sender || (!backward && !same_peer(source,sender_peer)))continue;
            if(raw.size()<header_size || read_be(raw.data(),4)!=0x52554450)continue;
            const auto type=static_cast<Type>(raw[5]);
            const auto seq=static_cast<uint32_t>(read_be(raw.data()+16,4));
            bool forced_drop=false;
            auto drop=drop_types.find(type);
            if(drop!=drop_types.end() && drop->second){--drop->second;forced_drop=true;}
            if(!backward && type==Type::Data && drop_seq.erase(seq))forced_drop=true;
            if(backward && type==Type::Ack && drop_ack.erase(static_cast<uint32_t>(read_be(raw.data()+20,4))))forced_drop=true;
            if(forced_drop || chance(random)<loss) {
                ++dropped;if(verbose)log(std::string("RELAY_DROP ")+type_name(type)+" seq="+std::to_string(seq));continue;
            }
            const bool forced_bad=!backward && type==Type::Data && bad_seq.erase(seq)!=0;
            if(forced_bad || chance(random)<corrupt) {
                raw.back()^=1;++corrupted;
                if(verbose)log(std::string("RELAY_CORRUPT ")+type_name(type)+" seq="+std::to_string(seq));
            }
            unsigned extra=0;
            if(!backward && type==Type::Data && delay_seq.erase(seq))extra=reorder;
            const auto due=Clock::now()+std::chrono::milliseconds(delay+variation(random)+extra);
            const auto destination=backward?sender_peer:target;
            queue.emplace(due,Delivery{raw,destination});
            if(chance(random)<duplicate) {
                queue.emplace(due+std::chrono::milliseconds(2),Delivery{raw,destination});++duplicated;
            }
            max_queue=std::max<uint64_t>(max_queue,queue.size());
            if(queue.size()>100000)throw std::runtime_error("Relay queue safety limit");
        }
    } catch(...) {if(!InterlockedCompareExchange(&stopping,0,0))throw;}
    std::ostringstream result;
    result<<"{\"role\":\"relay\",\"received\":"<<received<<",\"forwarded\":"<<forwarded
        <<",\"dropped\":"<<dropped<<",\"corrupted\":"<<corrupted<<",\"duplicated\":"<<duplicated
        <<",\"max_queue\":"<<max_queue<<",\"pending_at_stop\":"<<queue.size()<<'}';
    log("RESULT "+result.str());
    if(!o.get("--stats").empty()) {
        std::ofstream out(std::filesystem::u8path(o.get("--stats")));out<<result.str()<<'\n';
        if(!out)throw std::runtime_error("Cannot write relay stats");
    }
}
}
