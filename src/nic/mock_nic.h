#pragma once
#include "nic_interface.h"
#include <vector>
#include <atomic>
#include <chrono>
#include <cstring>

namespace nids {

/**
 * @brief Synthetic NIC that plays back a pre-loaded corpus of raw packets.
 * Used by unit and integration tests — does not require root.
 */
class MockNic : public INic {
public:
    void add_packet(std::vector<uint8_t> pkt) {
        packets_.push_back(std::move(pkt));
    }

    bool open(const std::string& iface) override {
        iface_ = iface;
        idx_   = 0;
        return true;
    }

    void close() override { iface_.clear(); }

    bool receive(PacketSlot* slot, int /*timeout_ms*/) override {
        if (!slot || !slot->data) return false;
        size_t i = idx_.fetch_add(1, std::memory_order_relaxed);
        if (i >= packets_.size()) return false;

        const auto& pkt = packets_[i];
        uint32_t len = static_cast<uint32_t>(
            pkt.size() < slot->capacity ? pkt.size() : slot->capacity);
        std::memcpy(slot->data, pkt.data(), len);
        slot->length = len;

        using namespace std::chrono;
        slot->timestamp = static_cast<uint64_t>(
            duration_cast<nanoseconds>(
                system_clock::now().time_since_epoch()).count());
        return true;
    }

    const std::string& iface() const override { return iface_; }

    size_t total_injected() const { return packets_.size(); }
    size_t consumed() const {
        size_t i = idx_.load();
        return i < packets_.size() ? i : packets_.size();
    }

private:
    std::string iface_;
    std::vector<std::vector<uint8_t>> packets_;
    std::atomic<size_t> idx_{0};
};

} // namespace nids
