#include "ethernet.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>
using namespace lab02;
using Bytes = std::vector<uint8_t>;

void expect(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
Bytes ethernet(uint16_t field, Bytes payload = {}) {
    Bytes data{0,1,2,3,4,5,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        static_cast<uint8_t>(field >> 8),static_cast<uint8_t>(field)};
    data.insert(data.end(), payload.begin(), payload.end());
    return data;
}
EthernetFrame parse(const Bytes& data, size_t original = 0) {
    return parse_ethernet(data.data(), data.size(), original ? original : data.size());
}

int main() {
    const std::vector<std::pair<std::string,std::function<void()>>> tests{
        {"empty", [] { expect(!parse({}).header_present, "empty"); }},
        {"short_1_to_13", [] { for(size_t n=1;n<14;++n) expect(!parse(Bytes(n)).header_present,"short"); }},
        {"exact_header", [] { auto f=parse(ethernet(0x0800)); expect(f.header_present&&!f.after_field,"14 byte boundary"); }},
        {"mac_order", [] { auto f=parse(ethernet(0x0800)); expect(f.source=="AA:BB:CC:DD:EE:FF"&&f.destination=="00:01:02:03:04:05","source/destination offsets"); }},
        {"ipv4_first_byte", [] { auto f=parse(ethernet(0x0800,{0x45})); expect(f.outer_field==0x0800&&f.after_field==0x45&&f.protocol=="IPv4","IPv4"); }},
        {"ipv6_first_byte", [] { auto f=parse(ethernet(0x86dd,{0x60})); expect(f.after_field==0x60&&f.protocol=="IPv6","IPv6"); }},
        {"arp_first_byte", [] { auto f=parse(ethernet(0x0806,{0x00})); expect(f.after_field.has_value()&&f.after_field==0&&f.protocol=="ARP","zero byte is present"); }},
        {"network_byte_order", [] { expect(parse(ethernet(0x1234)).outer_field==0x1234,"BE16"); }},
        {"length_1500", [] { expect(parse(ethernet(1500)).protocol=="IEEE802.3(length=1500)","802.3 length"); }},
        {"length_zero", [] { expect(parse(ethernet(0)).protocol=="IEEE802.3(length=0)","zero length"); }},
        {"reserved_1501", [] { expect(parse(ethernet(1501)).protocol=="Reserved(1501..1535)","reserved start"); }},
        {"reserved_1535", [] { expect(parse(ethernet(1535)).protocol=="Reserved(1501..1535)","reserved end"); }},
        {"ethertype_1536", [] { expect(parse(ethernet(1536)).protocol=="EtherType","type threshold"); }},
        {"vlan_raw_vs_payload", [] { auto f=parse(ethernet(0x8100,{0xa0,0x64,0x08,0x00,0x45})); expect(f.after_field==0xa0&&f.inner_field==0x0800&&f.payload_first==0x45&&f.payload_offset==18,"VLAN offsets"); expect(f.vlans.size()==1&&(f.vlans[0].tci&0xfff)==100,"VLAN ID"); }},
        {"double_vlan", [] { auto f=parse(ethernet(0x88a8,{0,1,0x81,0,0,2,0x86,0xdd,0x60})); expect(f.vlans.size()==2&&f.inner_field==0x86dd&&f.after_field==0&&f.payload_first==0x60&&f.payload_offset==22,"QinQ"); }},
        {"vlan_truncated_0_to_3", [] { for(size_t n=0;n<4;++n) expect(parse(ethernet(0x8100,Bytes(n))).protocol=="TRUNCATED_VLAN","truncated VLAN"); }},
        {"vlan_without_payload", [] { auto f=parse(ethernet(0x8100,{0,1,8,0})); expect(f.inner_field==0x0800&&!f.payload_first,"no payload"); }},
        {"snaplen_truncation", [] { auto f=parse(ethernet(0x0800,{0x45}),1500); expect(f.truncated&&f.after_field==0x45,"caplen not wirelen"); }},
        {"broadcast_mac", [] { auto b=ethernet(0x0806); for(size_t i=0;i<6;++i)b[i]=0xff; expect(parse(b).destination=="FF:FF:FF:FF:FF:FF","broadcast"); }},
        {"ipv4_detail", [] { Bytes ip(20);ip[0]=0x45;ip[9]=1;ip[12]=10;ip[15]=1;ip[16]=10;ip[19]=2; expect(parse(ethernet(0x0800,ip)).detail=="10.0.0.1 -> 10.0.0.2 IP.protocol=1","IPv4 detail"); }},
        {"arp_opcode", [] { expect(parse(ethernet(0x0806,{0,1,8,0,6,4,0,2})).detail=="ARP htype=1 ptype=0x0800 op=2","ARP op"); }},
        {"all_prefixes_nested_vlan", [] { auto b=ethernet(0x88a8,{0,1,0x81,0,0,2,8,0,0x45}); for(size_t n=0;n<=b.size();++n){ auto f=parse_ethernet(b.data(),n,b.size()); if(n<15)expect(!f.after_field,"prefix after field"); if(n<14)expect(!f.header_present,"prefix header"); } }},
        {"repeated_vlan_bounded", [] { auto b=ethernet(0x8100);for(int i=0;i<1000;++i)b.insert(b.end(),{0,1,0x81,0});auto f=parse(b);expect(f.vlans.size()==1000&&f.protocol=="TRUNCATED_VLAN","nested loop bound"); }},
        {"unaligned_input", [] { auto b=ethernet(0x0800,{0x45});b.insert(b.begin(),0);auto f=parse_ethernet(b.data()+1,b.size()-1,b.size()-1);expect(f.source=="AA:BB:CC:DD:EE:FF"&&f.after_field==0x45,"unaligned"); }}
    };
    unsigned failures=0;
    for (const auto& test:tests) {
        try { test.second(); std::cout<<"PASS "<<test.first<<'\n'; }
        catch(const std::exception& e) { ++failures;std::cout<<"FAIL "<<test.first<<": "<<e.what()<<'\n'; }
    }
    std::cout<<"SUMMARY tests="<<tests.size()<<" failures="<<failures<<'\n';
    return failures ? 1 : 0;
}
