#pragma once
#include "nic_interface.h"

namespace nids {

/**
 * @brief Linux AF_PACKET raw socket based NIC.
 *
 * Captures all Ethernet frames on the given interface at ring buffer level.
 * Requires CAP_NET_RAW capability (or root).
 */
class AfPacketNic : public INic {
public:
    AfPacketNic() = default;
    ~AfPacketNic() override { close(); }

    bool open(const std::string& iface) override;
    void close() override;
    bool receive(PacketSlot* slot, int timeout_ms = 10) override;
    const std::string& iface() const override { return iface_; }

private:
    std::string iface_;
    int sock_fd_ = -1;
};

} // namespace nids
