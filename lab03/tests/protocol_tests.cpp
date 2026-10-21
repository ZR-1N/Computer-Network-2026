#include "window.hpp"
#include <iostream>
#include <random>
using namespace rudp;
void expect(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
Packet example(Type type=Type::Data) {
    Packet p;p.type=type;p.session=0x0102030405060708;p.window=16;p.file_size=12345;
    if(type==Type::Data)p.payload={1,2,3};
    return p;
}
bool valid(const Bytes& bytes) {Packet p;std::string reason;return decode(bytes,p,reason);}
int main() {
    std::vector<std::pair<std::string,std::function<void()>>> tests{
        {"checksum_rfc_vector",[]{Bytes b{0,1,0xf2,3,0xf4,0xf5,0xf6,0xf7};expect(checksum(b.data(),b.size())==0x220d,"RFC vector");}},
        {"checksum_odd_octet",[]{uint8_t b=1;expect(checksum(&b,1)==0xfeff,"odd pad");}},
        {"checksum_empty",[]{expect(checksum(nullptr,0)==0xffff,"empty checksum");}},
        {"crc32_standard",[]{const std::string s="123456789";Crc32 c;c.update(reinterpret_cast<const uint8_t*>(s.data()),s.size());expect(c.value()==0xcbf43926,"CRC reference");}},
        {"crc32_streaming",[]{Bytes b(5000,0xa5);Crc32 a,c;a.update(b.data(),b.size());for(uint8_t x:b)c.update(&x,1);expect(a.value()==c.value(),"incremental CRC");}},
        {"crc32_empty",[]{expect(Crc32().value()==0,"empty CRC");}},
        {"wire_round_trip",[]{auto p=example();auto b=encode(p);Packet q;std::string e;expect(decode(b,q,e)&&q.session==p.session&&q.payload==p.payload&&q.file_size==p.file_size,"wire round trip");}},
        {"network_order_offsets",[]{auto b=encode(example());expect(b[0]=='R'&&b[3]=='P'&&b[8]==1&&b[15]==8&&b[6]==0&&b[7]==48&&b[33]==3,"offsets");}},
        {"all_single_bit_errors",[]{auto b=encode(example());for(size_t i=0;i<b.size();++i)for(unsigned bit=0;bit<8;++bit){auto x=b;x[i]^=uint8_t(1u<<bit);expect(!valid(x),"single bit not detected");}}},
        {"short_datagrams",[]{for(size_t i=0;i<48;++i)expect(!valid(Bytes(i)),"short packet");}},
        {"oversize_datagram",[]{expect(!valid(Bytes(1449)),"maximum UDP application frame");}},
        {"payload_length_mismatch",[]{auto b=encode(example());b.push_back(0);write_be(b.data()+36,0,2);write_be(b.data()+36,checksum(b.data(),b.size()),2);expect(!valid(b),"length mismatch");}},
        {"reserved_nonzero",[]{auto b=encode(example());b[39]=1;write_be(b.data()+36,0,2);write_be(b.data()+36,checksum(b.data(),b.size()),2);expect(!valid(b),"reserved");}},
        {"reject_zero_session",[]{auto p=example();p.session=0;expect(!valid(encode(p)),"zero session");}},
        {"reject_bad_window",[]{auto p=example();p.window=65;expect(!valid(encode(p)),"window range");}},
        {"control_payload_rules",[]{auto p=example(Type::Syn);expect(!valid(encode(p)),"SYN metadata needed");p.payload=metadata(1200,0);expect(valid(encode(p)),"SYN metadata");p.type=Type::Ack;expect(!valid(encode(p)),"ACK must be empty");}},
        {"segment_count_boundaries",[]{expect(segment_count(0,1200)==0&&segment_count(1200,1200)==1&&segment_count(1201,1200)==2,"segments");}},
        {"segment_overflow",[]{bool failed=false;try{segment_count(uint64_t(UINT32_MAX)+1,1);}catch(...){failed=true;}expect(failed,"sequence overflow");}},
        {"window_sizes",[]{for(unsigned n:{0u,65u}){bool failed=false;try{SendWindow w(n);}catch(...){failed=true;}expect(failed,"invalid W");}}},
        {"sender_fixed_range",[]{SendWindow w(4);for(int i=0;i<4;++i)w.sent();expect(!w.can_send(),"full window");w.acknowledge(0,14);expect(w.base()==0&&!w.can_send(),"SACK holes must not slide window");w.acknowledge(4,0);expect(w.base()==4&&w.can_send(),"slide contiguous prefix");}},
        {"ack_unsent_base",[]{SendWindow w(4);w.sent();expect(!w.valid_ack(2,0),"future ACK");}},
        {"ack_unsent_sack",[]{SendWindow w(4);w.sent();expect(!w.valid_ack(0,2),"unsent SACK");}},
        {"ack_bit_zero_rejected",[]{SendWindow w(4);w.sent();expect(!w.valid_ack(0,1),"first missing cannot be SACKed");}},
        {"sack_width_rejected",[]{SendWindow w(2);w.sent();w.sent();expect(!w.valid_ack(0,4),"SACK outside W");}},
        {"selective_ack_only",[]{SendWindow w(4);for(int i=0;i<4;++i)w.sent();auto acked=w.acknowledge(0,10);expect(acked==std::vector<uint32_t>({1,3})&&w.base()==0,"selective ACK set");}},
        {"receiver_reorder_drain",[]{ReceiveWindow w(4);Bytes out;w.insert(2,{2});w.insert(1,{1});expect(w.bitmap()==6,"SACK bit mapping");w.insert(0,{0});w.drain([&](const Bytes& b){out.insert(out.end(),b.begin(),b.end());});expect(out==Bytes({0,1,2})&&w.base()==3&&w.bitmap()==0,"ordered delivery");}},
        {"duplicate_and_old",[]{ReceiveWindow w(4);expect(w.insert(0,{1})==InsertResult::Accepted,"insert");expect(w.insert(0,{2})==InsertResult::Duplicate,"duplicate");w.drain([](const Bytes&){});expect(w.insert(0,{3})==InsertResult::Old,"old");}},
        {"receiver_outside_window",[]{ReceiveWindow w(4);expect(w.insert(4,{4})==InsertResult::Outside&&w.buffered()==0,"outside");}},
        {"sack_bit_63",[]{ReceiveWindow w(64);w.insert(63,{1});expect(w.bitmap()==(uint64_t(1)<<63),"64bit SACK");}},
        {"stale_ack_idempotent",[]{SendWindow w(4);w.sent();w.sent();w.acknowledge(2,0);expect(w.acknowledge(1,0).empty()&&w.base()==2,"stale ACK");}},
        {"receiver_write_failure",[]{ReceiveWindow w(4);w.insert(0,{1});try{w.drain([](const Bytes&){throw std::runtime_error("disk full");});}catch(...){}expect(w.base()==0&&w.buffered()==1,"do not acknowledge failed write");}},
        {"randomized_window_model",[]{std::mt19937 rng(2026);for(unsigned width:{1u,4u,16u,64u}){SendWindow s(width);ReceiveWindow r(width);Bytes out;unsigned guard=0;while(s.base()<200&&++guard<100000){while(s.next()<200&&s.can_send())s.sent();for(uint32_t seq=s.base();seq<s.next();++seq)if(rng()%3){r.insert(seq,{static_cast<uint8_t>(seq)});r.drain([&](const Bytes& b){out.insert(out.end(),b.begin(),b.end());});expect(s.valid_ack(r.base(),r.bitmap()),"model ACK validation");s.acknowledge(r.base(),r.bitmap());}expect(r.buffered()<=width&&uint64_t(s.next())<=uint64_t(s.base())+width,"window invariant");}expect(out.size()==200&&s.base()==200,"model completion");for(unsigned i=0;i<200;++i)expect(out[i]==static_cast<uint8_t>(i),"model byte order");}}}
    };
    unsigned failures=0;
    for(const auto& test:tests){try{test.second();std::cout<<"PASS "<<test.first<<'\n';}catch(const std::exception& e){++failures;std::cout<<"FAIL "<<test.first<<" "<<e.what()<<'\n';}}
    std::cout<<"SUMMARY tests="<<tests.size()<<" failures="<<failures<<'\n';return failures?1:0;
}
