#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace rudp {
using Bytes = std::vector<uint8_t>;
constexpr size_t header_size = 48;
constexpr size_t max_payload = 1400;
enum class Type : uint8_t { Syn=1, SynAck, Start, Data, Ack, Fin, FinAck, CloseAck, Reset };
inline const char* type_name(Type t) {
    switch(t) {
    case Type::Syn:return "SYN"; case Type::SynAck:return "SYN_ACK";
    case Type::Start:return "START"; case Type::Data:return "DATA";
    case Type::Ack:return "ACK"; case Type::Fin:return "FIN";
    case Type::FinAck:return "FIN_ACK"; case Type::CloseAck:return "CLOSE_ACK";
    case Type::Reset:return "RESET";
    } return "UNKNOWN";
}
inline uint64_t read_be(const uint8_t* p, size_t n) {
    uint64_t value=0;
    for(size_t i=0;i<n;++i) value=(value<<8)|p[i];
    return value;
}
inline void write_be(uint8_t* p, uint64_t value, size_t n) {
    for(size_t i=n;i>0;--i) { p[i-1]=static_cast<uint8_t>(value); value>>=8; }
}
// RFC 1071 one's-complement checksum, with a zero-padded final odd octet.
inline uint16_t checksum(const uint8_t* p, size_t n) {
    uint32_t sum=0;
    while(n>=2) { sum+=(uint32_t(p[0])<<8)|p[1]; p+=2; n-=2; }
    if(n) sum+=uint32_t(p[0])<<8;
    while(sum>>16) sum=(sum&0xffff)+(sum>>16);
    return static_cast<uint16_t>(~sum);
}
struct Packet {
    Type type=Type::Ack;
    uint64_t session=0;
    uint32_t seq=0, ack_base=0;
    uint64_t sack=0;
    uint16_t window=0;
    uint64_t file_size=0;
    Bytes payload;
};
inline Bytes encode(const Packet& p) {
    if(p.payload.size()>max_payload) throw std::runtime_error("Payload too large");
    Bytes out(header_size+p.payload.size(),0);
    write_be(out.data(),0x52554450,4); out[4]=1;out[5]=static_cast<uint8_t>(p.type);
    write_be(out.data()+6,header_size,2);write_be(out.data()+8,p.session,8);
    write_be(out.data()+16,p.seq,4);write_be(out.data()+20,p.ack_base,4);
    write_be(out.data()+24,p.sack,8);write_be(out.data()+32,p.payload.size(),2);
    write_be(out.data()+34,p.window,2);write_be(out.data()+40,p.file_size,8);
    std::copy(p.payload.begin(),p.payload.end(),out.begin()+header_size);
    write_be(out.data()+36,checksum(out.data(),out.size()),2);
    return out;
}
inline bool decode(const Bytes& raw, Packet& p, std::string& reason) {
    if(raw.size()<header_size || raw.size()>header_size+max_payload) { reason="length";return false; }
    if(checksum(raw.data(),raw.size())!=0) { reason="checksum";return false; }
    if(read_be(raw.data(),4)!=0x52554450 || raw[4]!=1 || raw[5]<1 || raw[5]>9 ||
        read_be(raw.data()+6,2)!=header_size || read_be(raw.data()+38,2)!=0 ||
        read_be(raw.data()+32,2)!=raw.size()-header_size) { reason="header";return false; }
    p.type=static_cast<Type>(raw[5]);p.session=read_be(raw.data()+8,8);
    p.seq=static_cast<uint32_t>(read_be(raw.data()+16,4));
    p.ack_base=static_cast<uint32_t>(read_be(raw.data()+20,4));p.sack=read_be(raw.data()+24,8);
    p.window=static_cast<uint16_t>(read_be(raw.data()+34,2));p.file_size=read_be(raw.data()+40,8);
    p.payload.assign(raw.begin()+header_size,raw.end());
    const bool metadata_type=p.type==Type::Syn || p.type==Type::SynAck || p.type==Type::Start || p.type==Type::Fin;
    const bool empty_type=p.type==Type::Ack || p.type==Type::FinAck || p.type==Type::CloseAck;
    if(!p.session || !p.window || p.window>64 || (metadata_type && p.payload.size()!=8) ||
        (empty_type && !p.payload.empty()) || (p.type==Type::Data && p.payload.empty()) ||
        (p.type==Type::Reset && p.payload.empty()) ||
        (p.type!=Type::Data && p.type!=Type::Fin && p.seq!=0) ||
        (p.type!=Type::Ack && (p.ack_base || p.sack))) {reason="semantics";return false;}
    return true;
}
class Crc32 {
    uint32_t value_=0xffffffff;
public:
    void update(const uint8_t* p,size_t n) {
        static const auto table=[] {
            std::array<uint32_t,256> t{};
            for(uint32_t i=0;i<256;++i) {
                uint32_t c=i;
                for(int bit=0;bit<8;++bit) c=(c>>1)^((c&1)?0xedb88320u:0u);
                t[i]=c;
            } return t;
        }();
        for(size_t i=0;i<n;++i) value_=(value_>>8)^table[(value_^p[i])&255];
    }
    uint32_t value() const { return value_^0xffffffff; }
};
inline uint32_t segment_count(uint64_t size,uint16_t chunk) {
    if(!chunk || chunk>max_payload) throw std::runtime_error("chunk must be 1..1400");
    const uint64_t count=size/chunk+(size%chunk?1:0);
    if(count>std::numeric_limits<uint32_t>::max()) throw std::runtime_error("File has too many segments");
    return static_cast<uint32_t>(count);
}
inline Bytes metadata(uint16_t chunk,uint32_t crc) {
    Bytes data(8,0);write_be(data.data(),chunk,2);write_be(data.data()+4,crc,4);return data;
}
}
