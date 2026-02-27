#include "af_packet_nic.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <chrono>
#include <ctime>

namespace nids {

bool AfPacketNic::open(const std::string& iface) {
    close();  // Ensure previous fd closed

    // ETH_P_ALL = receive all protocol types (raw L2)
    sock_fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd_ < 0) {
        return false;  // Caller should check errno
    }

    // Bind to specific interface
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (::ioctl(sock_fd_, SIOCGIFINDEX, &ifr) < 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    struct sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if (::bind(sock_fd_, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    // Set socket receive buffer to 8 MB
    int rcvbuf = 8 * 1024 * 1024;
    ::setsockopt(sock_fd_, SOL_SOCKET, SO_RCVBUF,
                 &rcvbuf, static_cast<socklen_t>(sizeof(rcvbuf)));

    iface_ = iface;
    return true;
}

void AfPacketNic::close() {
    if (sock_fd_ >= 0) {
        ::close(sock_fd_);
        sock_fd_ = -1;
    }
    iface_.clear();
}

bool AfPacketNic::receive(PacketSlot* slot, int timeout_ms) {
    if (sock_fd_ < 0 || !slot || !slot->data) return false;

    // Wait for data with poll()
    struct pollfd pfd{ sock_fd_, POLLIN, 0 };
    int nfds = ::poll(&pfd, 1, timeout_ms);
    if (nfds <= 0) return false;  // timeout or error

    ssize_t n = ::recv(sock_fd_, slot->data, slot->capacity, MSG_DONTWAIT);
    if (n <= 0) return false;

    slot->length = static_cast<uint32_t>(n);

    // Timestamp: nanoseconds since epoch
    using namespace std::chrono;
    slot->timestamp = static_cast<uint64_t>(
        duration_cast<nanoseconds>(
            system_clock::now().time_since_epoch()).count());

    return true;
}

} // namespace nids
