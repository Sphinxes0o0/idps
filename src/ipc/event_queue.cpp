#include "sec_event.h"
#include <arpa/inet.h>
#include <cstdio>
#include <string>

namespace nids {

std::string SecEvent::to_json() const {
    char src[INET_ADDRSTRLEN] = {};
    char dst[INET_ADDRSTRLEN] = {};
    uint32_t src_n = htonl(src_ip);
    uint32_t dst_n = htonl(dst_ip);
    inet_ntop(AF_INET, &src_n, src, sizeof(src));
    inet_ntop(AF_INET, &dst_n, dst, sizeof(dst));

    char buf[512];
    int len = std::snprintf(buf, sizeof(buf),
        R"({"type":%d,"ts":%llu,"src":"%s:%u","dst":"%s:%u","proto":%u,"rule_id":%d,"msg":"%s"})",
        static_cast<int>(type),
        static_cast<unsigned long long>(timestamp),
        src, static_cast<unsigned>(src_port),
        dst, static_cast<unsigned>(dst_port),
        static_cast<unsigned>(ip_proto),
        rule_id,
        message);

    return len > 0 ? std::string(buf, static_cast<size_t>(len)) : "{}";
}

} // namespace nids
