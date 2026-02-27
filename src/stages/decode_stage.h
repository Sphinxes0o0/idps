#pragma once
#include "../core/stage.h"

namespace nids {

/**
 * @brief DecodeStage — parse Ethernet/IP/TCP/UDP headers.
 *
 * Populates PacketSlot offset fields (net_offset, transport_offset,
 * payload_offset, ip_proto) and computes the 5-tuple flow_hash.
 * VLAN (802.1Q) stripping is supported.
 */
class DecodeStage : public IStage {
public:
    bool init()                        override { return true; }
    bool process(PipelineContext& ctx)  override;
    std::string name() const           override { return "Decode"; }
};

} // namespace nids
