#pragma once
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace lab02 {
struct VlanTag {
    uint16_t tpid;
    uint16_t tci;
};

struct EthernetFrame {
    bool header_present = false;
    bool truncated = false;
    std::string source;
    std::string destination;
    std::optional<uint16_t> outer_field;
    std::optional<uint8_t> after_field;
    std::optional<uint16_t> inner_field;
    std::optional<uint8_t> payload_first;
    size_t payload_offset = 14;
    std::vector<VlanTag> vlans;
    std::string protocol;
    std::string detail;
};

// Explicit byte operations avoid unaligned reads and structure padding.
inline uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline std::string hex_value(unsigned value, unsigned width) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setfill('0')
        << std::setw(static_cast<int>(width)) << value;
    return out.str();
}

inline std::string mac_address(const uint8_t* p) {
    std::ostringstream out;
    for (size_t i = 0; i < 6; ++i) {
        if (i) out << ':';
        out << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(p[i]);
    }
    return out.str();
}

inline std::string field_description(uint16_t field) {
    if (field <= 1500) return "IEEE802.3(length=" + std::to_string(field) + ")";
    if (field < 1536) return "Reserved(1501..1535)";
    switch (field) {
    case 0x0800: return "IPv4";
    case 0x0806: return "ARP";
    case 0x86dd: return "IPv6";
    case 0x8100: return "802.1Q";
    case 0x88a8: return "802.1ad";
    default: return "EtherType";
    }
}

inline std::string ipv4_address(const uint8_t* p) {
    return std::to_string(p[0]) + "." + std::to_string(p[1]) + "." +
        std::to_string(p[2]) + "." + std::to_string(p[3]);
}

inline EthernetFrame parse_ethernet(const uint8_t* data, size_t captured, size_t original) {
    EthernetFrame frame;
    frame.truncated = captured < original;
    if (captured < 14) {
        frame.protocol = "SHORT_ETHERNET";
        frame.detail = "Need at least 14 captured bytes";
        return frame;
    }
    frame.header_present = true;
    frame.destination = mac_address(data);
    frame.source = mac_address(data + 6);
    frame.outer_field = read_be16(data + 12);
    if (captured > 14) frame.after_field = data[14];

    uint16_t field = *frame.outer_field;
    size_t offset = 14;
    while (field == 0x8100 || field == 0x88a8) {
        if (captured - offset < 4) {
            frame.protocol = "TRUNCATED_VLAN";
            frame.detail = "VLAN tag needs TCI(2) and next type(2)";
            return frame;
        }
        frame.vlans.push_back({field, read_be16(data + offset)});
        field = read_be16(data + offset + 2);
        offset += 4;
    }
    frame.payload_offset = offset;
    frame.inner_field = field;
    if (captured > offset) frame.payload_first = data[offset];
    frame.protocol = field_description(field);

    // Optional interpretations never change the mandatory raw offset-14 byte.
    if (field == 0x0800 && captured - offset >= 20) {
        const uint8_t* ip = data + offset;
        const size_t ihl = static_cast<size_t>(ip[0] & 0x0f) * 4;
        if ((ip[0] >> 4) == 4 && ihl >= 20 && ihl <= captured - offset) {
            frame.detail = ipv4_address(ip + 12) + " -> " + ipv4_address(ip + 16)
                + " IP.protocol=" + std::to_string(ip[9]);
        } else frame.detail = "Invalid/truncated IPv4 header";
    } else if (field == 0x0806 && captured - offset >= 8) {
        frame.detail = "ARP htype=" + std::to_string(read_be16(data + offset))
            + " ptype=" + hex_value(read_be16(data + offset + 2), 4)
            + " op=" + std::to_string(read_be16(data + offset + 6));
    } else if (field == 0x86dd && captured > offset) {
        frame.detail = "IPv6 version=" + std::to_string(data[offset] >> 4);
    }
    return frame;
}
}
