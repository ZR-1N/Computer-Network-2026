#pragma once
#include "platform.hpp"
#include "window.hpp"
#include <memory>

namespace rudp {
struct Metrics {
    std::string role,error,session;
    bool success=false,close_confirmed=false;
    uint64_t file_size=0;
    uint32_t crc=0;
    unsigned window=0,chunk=0;
    uint64_t data_sent=0,data_received=0,retransmissions=0,control_retries=0;
    uint64_t ack_sent=0,ack_received=0,checksum_errors=0,invalid_packets=0,foreign_packets=0;
    uint64_t duplicates=0,out_of_order=0,max_in_flight=0,max_buffered=0;
    double total_seconds=0,data_seconds=0;
    std::string json()const;
};
struct Settings {
    uint16_t window=16,chunk=1200;
    unsigned rto=150,retries=40,idle=10000;
    bool verbose=false;
    explicit Settings(const Options& options);
};
void sender(const Options& options,Metrics& metrics);
void receiver(const Options& options,Metrics& metrics);
void relay(const Options& options);
}
