#pragma once
#include "../core/packet.h"
#include <string>
#include <cstdint>

namespace nids {

/**
 * @brief Abstract NIC interface.
 *
 * Concrete implementations:
 *   - AfPacketNic   — Linux AF_PACKET raw socket (used in production)
 *   - MockNic       — Injects synthetic packets (used in unit tests)
 */
class INic {
public:
    virtual ~INic() = default;

    /**
     * @brief Open the NIC for packet capture.
     * @param iface  Network interface name (e.g., "eth0").
     * @return true on success.
     */
    virtual bool open(const std::string& iface) = 0;

    /**
     * @brief Close and release resources.
     */
    virtual void close() = 0;

    /**
     * @brief Receive the next packet into the provided slot.
     *
     * Blocks at most `timeout_ms` milliseconds.
     *
     * @param slot       Pre-allocated slot with slot->data pointing to a buffer.
     * @param timeout_ms Receive timeout in milliseconds (0 = non-blocking).
     * @return true if a packet was received (slot->length > 0).
     */
    virtual bool receive(PacketSlot* slot, int timeout_ms = 10) = 0;

    /** @brief NIC name this interface is attached to. */
    virtual const std::string& iface() const = 0;
};

} // namespace nids
