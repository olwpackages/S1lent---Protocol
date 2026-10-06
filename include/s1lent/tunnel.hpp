#pragma once

#include "ip_interface.hpp"
#include "route.hpp"
#include "session.hpp"
#include "udp_transport.hpp"
#include <mutex>
#include <optional>

namespace s1lent {

enum class TunnelRole { client, server };

bool isValidIpPacket(std::span<const Byte> packet);

class TunnelPacketPump {
public:
    TunnelPacketPump(Route route, Session& session, UdpTransport& udp,
                     IpInterface& interface, TunnelRole role);

    bool sendIpPacket(std::span<const Byte> packet, std::string* error = nullptr);
    bool receiveDatagram(const Bytes& wire, const Endpoint& peer,
                         std::string* error = nullptr);

private:
    Route route_;
    Session& session_;
    UdpTransport& udp_;
    IpInterface& interface_;
    TunnelRole role_;
    std::mutex mutex_;
    std::optional<Endpoint> returnPeer_;
};

} // namespace s1lent
