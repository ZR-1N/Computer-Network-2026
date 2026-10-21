#include "engine.hpp"

namespace rudp {
std::string Metrics::json()const {
    std::ostringstream out;
    out<<"{\"role\":"<<quote(role)<<",\"success\":"<<(success?"true":"false")
        <<",\"error\":"<<quote(error)<<",\"session\":"<<quote(session)
        <<",\"file_size\":"<<file_size<<",\"crc32\":"<<crc
        <<",\"window\":"<<window<<",\"chunk\":"<<chunk
        <<",\"total_seconds\":"<<total_seconds<<",\"data_seconds\":"<<data_seconds
        <<",\"throughput_mib_s\":"<<(total_seconds>0?double(file_size)/1048576.0/total_seconds:0)
        <<",\"throughput_mbit_s\":"<<(total_seconds>0?double(file_size)*8/1000000.0/total_seconds:0)
        <<",\"data_sent\":"<<data_sent<<",\"data_received\":"<<data_received
        <<",\"retransmissions\":"<<retransmissions<<",\"control_retries\":"<<control_retries
        <<",\"ack_sent\":"<<ack_sent<<",\"ack_received\":"<<ack_received
        <<",\"checksum_errors\":"<<checksum_errors<<",\"invalid_packets\":"<<invalid_packets
        <<",\"foreign_packets\":"<<foreign_packets<<",\"duplicates\":"<<duplicates
        <<",\"out_of_order\":"<<out_of_order<<",\"max_in_flight\":"<<max_in_flight
        <<",\"max_buffered\":"<<max_buffered<<",\"close_confirmed\":"<<(close_confirmed?"true":"false")<<'}';
    return out.str();
}
Settings::Settings(const Options& o) {
    window=static_cast<uint16_t>(o.number("--window",16,64));
    chunk=static_cast<uint16_t>(o.number("--chunk",1200,1400));
    rto=static_cast<unsigned>(o.number("--rto-ms",150,60000));
    retries=static_cast<unsigned>(o.number("--retries",40,1000));
    idle=static_cast<unsigned>(o.number("--idle-ms",10000,3600000));
    verbose=o.get("--verbose")=="1";
    if(!window || !chunk || rto<10 || idle<100)throw std::runtime_error("window/chunk positive, RTO>=10ms, idle>=100ms required");
}
namespace {
const std::vector<std::string> shared_options={"--bind","--port","--window","--chunk","--rto-ms","--retries","--idle-ms","--verbose","--stats"};
struct Connection {
    uint64_t session=0,size=0;
    uint16_t window=0,chunk=0;
    uint32_t crc=0,count=0;
    Packet packet(Type type)const {
        Packet p;p.type=type;p.session=session;p.file_size=size;p.window=window;return p;
    }
    Bytes meta()const{return metadata(chunk,crc);}
    bool matches(const Packet& p)const{return p.session==session && p.file_size==size && p.window==window;}
};
void transmit(SOCKET s,const sockaddr_in& peer,const Packet& p,const Settings& settings,bool repeat=false) {
    send_raw(s,peer,encode(p));
    if(settings.verbose)log(std::string(repeat?"RETRANSMIT ":"SEND ")+type_name(p.type)+" seq="+std::to_string(p.seq)
        +" ack_base="+std::to_string(p.ack_base)+" sack=0x"+hex64(p.sack));
}
bool read_packet(SOCKET s,Packet& p,sockaddr_in& peer,Metrics& m,unsigned wait_ms=5) {
    Bytes raw;
    if(!receive_raw(s,raw,peer,wait_ms))return false;
    std::string reason;
    if(!decode(raw,p,reason)) {
        if(reason=="checksum")++m.checksum_errors;else ++m.invalid_packets;
        return false;
    } return true;
}
void reset(SOCKET s,const sockaddr_in& peer,const Connection& c,const std::string& message) {
    Packet p=c.packet(Type::Reset);p.payload.assign(message.begin(),message.end());
    try{send_raw(s,peer,encode(p));}catch(...){}
}
void require_peer_packet(const Packet& p) {
    if(p.type==Type::Reset)throw std::runtime_error("Peer RESET: "+std::string(p.payload.begin(),p.payload.end()));
}
Packet exchange(SOCKET socket,const sockaddr_in& peer,const Connection& c,Packet request,Type wanted,
                const Settings& settings,Metrics& metrics) {
    for(unsigned attempt=0;attempt<=settings.retries;++attempt) {
        if(attempt)++metrics.control_retries;
        transmit(socket,peer,request,settings,attempt!=0);
        const auto deadline=Clock::now()+std::chrono::milliseconds(settings.rto);
        while(Clock::now()<deadline) {
            Packet response;sockaddr_in from{};
            if(!read_packet(socket,response,from,metrics))continue;
            if(!same_peer(peer,from) || response.session!=c.session){++metrics.foreign_packets;continue;}
            require_peer_packet(response);
            if(!c.matches(response) || response.type!=wanted)continue;
            if(wanted==Type::SynAck && response.payload!=c.meta())continue;
            if(wanted==Type::Ack && (!response.payload.empty() || response.ack_base || response.sack))continue;
            if(wanted==Type::FinAck && !response.payload.empty())continue;
            return response;
        }
    }
    throw std::runtime_error(std::string("Retry limit in ")+type_name(request.type));
}
class ReceiveFile {
    std::filesystem::path target_,part_;
    HANDLE handle_=INVALID_HANDLE_VALUE;
    bool created_=false,committed_=false;
public:
    Crc32 crc;
    uint64_t written=0;
    explicit ReceiveFile(const std::string& name):target_(std::filesystem::u8path(name)),part_(target_.wstring()+L".part") {
        if(std::filesystem::exists(target_))throw std::runtime_error("Output already exists; refusing to overwrite");
        handle_=CreateFileW(part_.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
        if(handle_==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create new .part file");
        created_=true;
    }
    ~ReceiveFile() {
        if(handle_!=INVALID_HANDLE_VALUE)CloseHandle(handle_);
        if(created_ && !committed_)DeleteFileW(part_.c_str());
    }
    void append(const Bytes& data) {
        DWORD count=0;
        if(!WriteFile(handle_,data.data(),static_cast<DWORD>(data.size()),&count,nullptr) || count!=data.size())
            throw std::runtime_error("File write failed");
        crc.update(data.data(),data.size());written+=data.size();
    }
    void commit() {
        if(!FlushFileBuffers(handle_))throw std::runtime_error("File flush failed");
        CloseHandle(handle_);handle_=INVALID_HANDLE_VALUE;
        if(!MoveFileExW(part_.c_str(),target_.c_str(),MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("Atomic output rename failed (target may already exist)");
        committed_=true;
    }
};
}

void sender(const Options& o,Metrics& m) {
    auto allowed=shared_options;allowed.insert(allowed.end(),{"--peer","--file","--local-port"});o.allow(allowed);
    Settings settings(o);
    const std::string input=o.get("--file");
    if(input.empty())throw std::runtime_error("send requires --file");
    std::ifstream file(std::filesystem::u8path(input),std::ios::binary);
    if(!file)throw std::runtime_error("Cannot open input file");
    file.seekg(0,std::ios::end);const auto end=file.tellg();
    if(end<0)throw std::runtime_error("Cannot determine input length");
    Connection c;c.size=static_cast<uint64_t>(end);c.window=settings.window;c.chunk=settings.chunk;
    c.count=segment_count(c.size,c.chunk);
    std::random_device random;c.session=(uint64_t(random())<<32)^random();if(!c.session)c.session=1;
    file.seekg(0);Crc32 crc;std::array<uint8_t,65536> scan{};
    while(file){file.read(reinterpret_cast<char*>(scan.data()),scan.size());crc.update(scan.data(),static_cast<size_t>(file.gcount()));}
    if(!file.eof())throw std::runtime_error("Input scan failed");
    c.crc=crc.value();file.clear();file.seekg(0);
    m.role="sender";m.session=hex64(c.session);m.file_size=c.size;m.crc=c.crc;m.window=c.window;m.chunk=c.chunk;
    SocketGuard socket;socket.value=udp_socket(address(o.get("--bind","127.0.0.1"),static_cast<unsigned>(o.number("--local-port",0,65535))));
    const auto peer=address(o.get("--peer","127.0.0.1"),static_cast<unsigned>(o.number("--port",9002,65535)));
    if(!peer.sin_port)throw std::runtime_error("Peer port cannot be zero");
    const auto begin=Clock::now();
    try {
        log("STATE SYN_SENT session="+m.session+" bytes="+std::to_string(c.size)+" W="+std::to_string(c.window));
        Packet syn=c.packet(Type::Syn);syn.payload=c.meta();exchange(socket.value,peer,c,syn,Type::SynAck,settings,m);
        Packet start=c.packet(Type::Start);start.payload=c.meta();exchange(socket.value,peer,c,start,Type::Ack,settings,m);
        log("STATE ESTABLISHED pipeline/selective-repeat");
        const auto data_begin=Clock::now();
        SendWindow window(c.window);
        struct Flight { Packet packet;Clock::time_point sent;unsigned retries=0; };
        std::map<uint32_t,Flight> flights;
        while(window.base()<c.count) {
            check_stop();
            while(window.next()<c.count && window.can_send()) {
                Packet data=c.packet(Type::Data);data.seq=window.next();
                const uint64_t offset=uint64_t(data.seq)*c.chunk;
                const size_t size=static_cast<size_t>(std::min<uint64_t>(c.chunk,c.size-offset));
                data.payload.resize(size);file.read(reinterpret_cast<char*>(data.payload.data()),static_cast<std::streamsize>(size));
                if(static_cast<size_t>(file.gcount())!=size)throw std::runtime_error("Input changed or read failed");
                transmit(socket.value,peer,data,settings);++m.data_sent;
                flights.emplace(data.seq,Flight{std::move(data),Clock::now(),0});window.sent();
                m.max_in_flight=std::max<uint64_t>(m.max_in_flight,flights.size());
            }
            Packet ack;sockaddr_in from{};
            if(read_packet(socket.value,ack,from,m)) {
                if(!same_peer(peer,from) || ack.session!=c.session)++m.foreign_packets;
                else {
                    require_peer_packet(ack);
                    if(c.matches(ack) && ack.type==Type::Ack && ack.payload.empty() && window.valid_ack(ack.ack_base,ack.sack)) {
                        ++m.ack_received;
                        if(settings.verbose)log("RECV ACK base="+std::to_string(ack.ack_base)+" sack=0x"+hex64(ack.sack));
                        for(uint32_t seq:window.acknowledge(ack.ack_base,ack.sack))flights.erase(seq);
                    } else ++m.invalid_packets;
                }
            }
            const auto now=Clock::now();
            for(auto& item:flights)if(now-item.second.sent>=std::chrono::milliseconds(settings.rto)) {
                if(item.second.retries>=settings.retries)throw std::runtime_error("DATA retry limit seq="+std::to_string(item.first));
                ++item.second.retries;++m.retransmissions;++m.data_sent;
                transmit(socket.value,peer,item.second.packet,settings,true);item.second.sent=Clock::now();
            }
        }
        m.data_seconds=seconds(data_begin);
        log("STATE FIN_WAIT data complete; retransmissions="+std::to_string(m.retransmissions));
        Packet fin=c.packet(Type::Fin);fin.seq=c.count;fin.payload.resize(8);
        write_be(fin.payload.data(),c.crc,4);write_be(fin.payload.data()+4,c.count,4);
        exchange(socket.value,peer,c,fin,Type::FinAck,settings,m);
        m.total_seconds=seconds(begin);m.close_confirmed=true;
        Packet close=c.packet(Type::CloseAck);transmit(socket.value,peer,close,settings);
        log("STATE TIME_WAIT receiver committed file, CRC32 verified");
        const auto linger=Clock::now()+std::chrono::milliseconds(3*settings.rto);
        while(Clock::now()<linger) {
            Packet p;sockaddr_in from{};
            if(read_packet(socket.value,p,from,m) && same_peer(peer,from) && c.matches(p) && p.type==Type::FinAck) {
                transmit(socket.value,peer,close,settings,true);++m.control_retries;
            }
        }
        m.success=true;log("STATE CLOSED transfer successful");
    } catch(const std::exception& e) {reset(socket.value,peer,c,e.what());throw;}
}

void receiver(const Options& o,Metrics& m) {
    auto allowed=shared_options;allowed.push_back("--output");o.allow(allowed);
    Settings settings(o);const auto output=o.get("--output");
    if(output.empty())throw std::runtime_error("recv requires --output");
    const auto target=std::filesystem::u8path(output);
    if(std::filesystem::exists(target) || std::filesystem::exists(target.wstring()+L".part"))
        throw std::runtime_error("Output or .part already exists; refusing to overwrite");
    m.role="receiver";m.window=settings.window;
    SocketGuard socket;socket.value=udp_socket(address(o.get("--bind","127.0.0.1"),static_cast<unsigned>(o.number("--port",9002,65535))));
    Connection c;sockaddr_in peer{};bool connected=false,established=false,closing=false;
    ReceiveWindow window(settings.window);std::unique_ptr<ReceiveFile> file;
    auto last_activity=Clock::now(),begin=last_activity,data_begin=begin,last_fin=begin;
    unsigned close_retries=0;
    log("STATE LISTEN fixed-window="+std::to_string(settings.window));
    auto ack=[&] {
        Packet p=c.packet(Type::Ack);p.ack_base=window.base();p.sack=window.bitmap();
        transmit(socket.value,peer,p,settings);++m.ack_sent;
    };
    try {
        while(true) {
            check_stop();const auto now=Clock::now();
            if(closing && now-last_fin>=std::chrono::milliseconds(settings.rto)) {
                if(close_retries++>=settings.retries)throw std::runtime_error("Close confirmation timeout; verified output already committed");
                transmit(socket.value,peer,c.packet(Type::FinAck),settings,true);last_fin=now;++m.control_retries;
            }
            if(!closing && now-last_activity>=std::chrono::milliseconds(settings.idle))throw std::runtime_error("Receiver idle/handshake timeout");
            Packet p;sockaddr_in from{};
            if(!read_packet(socket.value,p,from,m))continue;
            if(!connected) {
                if(p.type!=Type::Syn || !p.session || p.seq || p.ack_base || p.sack || p.payload.size()!=8 || read_be(p.payload.data()+2,2)) {
                    ++m.invalid_packets;continue;
                }
                c.session=p.session;c.size=p.file_size;c.window=p.window;
                c.chunk=static_cast<uint16_t>(read_be(p.payload.data(),2));c.crc=static_cast<uint32_t>(read_be(p.payload.data()+4,4));
                peer=from;connected=true;begin=Clock::now();
                if(c.window!=settings.window)throw std::runtime_error("Sender/receiver fixed window mismatch");
                c.count=segment_count(c.size,c.chunk);
                m.session=hex64(c.session);m.file_size=c.size;m.crc=c.crc;m.chunk=c.chunk;
                log("STATE SYN_RECEIVED session="+m.session+" W="+std::to_string(c.window));
            }
            if(!same_peer(peer,from) || p.session!=c.session){++m.foreign_packets;continue;}
            require_peer_packet(p);
            if(!c.matches(p)){++m.invalid_packets;continue;}
            if(closing) {
                if(p.type==Type::CloseAck && p.payload.empty()) {
                    m.close_confirmed=true;m.success=true;log("STATE CLOSED close acknowledged");return;
                }
                if(p.type==Type::Fin && p.seq==c.count && p.payload.size()==8 && read_be(p.payload.data(),4)==c.crc
                    && read_be(p.payload.data()+4,4)==c.count) {
                    transmit(socket.value,peer,c.packet(Type::FinAck),settings,true);last_fin=Clock::now();++m.control_retries;
                }
                continue;
            }
            if(p.type==Type::Syn && p.payload==c.meta()) {
                Packet response=c.packet(Type::SynAck);response.payload=c.meta();transmit(socket.value,peer,response,settings);
                last_activity=Clock::now();continue;
            }
            if(p.type==Type::Start && p.payload==c.meta()) {
                if(!established) {
                    file=std::make_unique<ReceiveFile>(output);established=true;data_begin=Clock::now();
                    log("STATE ESTABLISHED receiving into .part");
                }
                ack();last_activity=Clock::now();continue;
            }
            if(!established){++m.invalid_packets;continue;}
            if(p.type==Type::Data) {
                if(p.seq>=c.count || p.ack_base || p.sack){++m.invalid_packets;continue;}
                const size_t expected=static_cast<size_t>(std::min<uint64_t>(c.chunk,c.size-uint64_t(p.seq)*c.chunk));
                if(p.payload.size()!=expected){++m.invalid_packets;continue;}
                ++m.data_received;
                if(p.seq>window.base())++m.out_of_order;
                const auto result=window.insert(p.seq,std::move(p.payload));
                if(result==InsertResult::Old || result==InsertResult::Duplicate)++m.duplicates;
                m.max_buffered=std::max<uint64_t>(m.max_buffered,window.buffered());
                if(settings.verbose)log("RECV DATA seq="+std::to_string(p.seq)+" base="+std::to_string(window.base()));
                window.drain([&](const Bytes& bytes){file->append(bytes);});ack();last_activity=Clock::now();
            } else if(p.type==Type::Fin) {
                if(p.seq!=c.count || p.payload.size()!=8 || read_be(p.payload.data(),4)!=c.crc || read_be(p.payload.data()+4,4)!=c.count) {
                    ++m.invalid_packets;continue;
                }
                if(window.base()!=c.count){ack();continue;}
                if(file->written!=c.size || file->crc.value()!=c.crc)throw std::runtime_error("Final file length/CRC32 mismatch");
                file->commit();m.total_seconds=seconds(begin);m.data_seconds=seconds(data_begin);
                log("FILE_COMMITTED bytes="+std::to_string(file->written)+" CRC32=0x"+hex64(c.crc));
                closing=true;last_fin=Clock::now();transmit(socket.value,peer,c.packet(Type::FinAck),settings);
            } else ++m.invalid_packets;
        }
    } catch(const std::exception& e) {if(connected)reset(socket.value,peer,c,e.what());throw;}
}
}
