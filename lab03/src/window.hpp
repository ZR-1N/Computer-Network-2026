#pragma once
#include "wire.hpp"
#include <functional>
#include <map>
#include <set>

namespace rudp {
class SendWindow {
    uint32_t base_=0,next_=0;
    unsigned width_;
    std::set<uint32_t> pending_;
public:
    explicit SendWindow(unsigned width):width_(width) {
        if(!width || width>64) throw std::runtime_error("window must be 1..64");
    }
    uint32_t base() const { return base_; }
    uint32_t next() const { return next_; }
    bool can_send() const { return uint64_t(next_)<uint64_t(base_)+width_; }
    void sent() {
        if(!can_send()) throw std::runtime_error("Sender exceeded fixed window");
        pending_.insert(next_++);
    }
    bool valid_ack(uint32_t base,uint64_t mask) const {
        if(base>next_ || (mask&1)) return false;
        for(unsigned i=0;i<64;++i) if((mask>>i)&1) {
            if(i>=width_ || uint64_t(base)+i>=next_) return false;
        }
        return true;
    }
    std::vector<uint32_t> acknowledge(uint32_t base,uint64_t mask) {
        if(!valid_ack(base,mask)) throw std::runtime_error("ACK confirms unsent data or invalid SACK bits");
        std::vector<uint32_t> acknowledged;
        for(auto it=pending_.begin();it!=pending_.end();) {
            const uint32_t seq=*it;
            const bool cumulative=seq<base;
            const uint64_t distance=seq>=base?uint64_t(seq)-base:64;
            const bool selective=distance<64 && ((mask>>distance)&1);
            if(cumulative || selective) { acknowledged.push_back(seq);it=pending_.erase(it); }
            else ++it;
        }
        while(base_<next_ && !pending_.count(base_)) ++base_;
        return acknowledged;
    }
};
enum class InsertResult { Accepted, Duplicate, Old, Outside };
class ReceiveWindow {
    uint32_t base_=0;
    unsigned width_;
    std::map<uint32_t,Bytes> buffered_;
public:
    explicit ReceiveWindow(unsigned width):width_(width) {
        if(!width || width>64) throw std::runtime_error("window must be 1..64");
    }
    uint32_t base() const { return base_; }
    size_t buffered() const { return buffered_.size(); }
    InsertResult insert(uint32_t seq,Bytes payload) {
        if(seq<base_) return InsertResult::Old;
        if(uint64_t(seq)>=uint64_t(base_)+width_) return InsertResult::Outside;
        if(buffered_.count(seq)) return InsertResult::Duplicate;
        buffered_.emplace(seq,std::move(payload));return InsertResult::Accepted;
    }
    void drain(const std::function<void(const Bytes&)>& write) {
        while(true) {
            auto it=buffered_.find(base_);
            if(it==buffered_.end()) break;
            write(it->second);buffered_.erase(it);++base_;
        }
    }
    uint64_t bitmap() const {
        uint64_t mask=0;
        for(const auto& item:buffered_) mask|=uint64_t(1)<<(item.first-base_);
        return mask;
    }
};
}
