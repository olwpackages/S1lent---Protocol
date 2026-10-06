#include "s1lent/tunnel.hpp"

namespace s1lent {

bool isValidIpPacket(std::span<const Byte> packet) {
    if (packet.empty()) return false;
    const auto version = packet[0] >> 4;
    if (version == 4) {
        if (packet.size() < 20) return false;
        const auto headerSize = static_cast<std::size_t>(packet[0] & 0x0f) * 4;
        const auto totalSize = (static_cast<std::size_t>(packet[2]) << 8) | packet[3];
        return headerSize >= 20 && headerSize <= packet.size() && totalSize == packet.size();
    }
    if (version == 6) {
        if (packet.size() < 40) return false;
        const auto payloadSize = (static_cast<std::size_t>(packet[4]) << 8) | packet[5];
        return payloadSize + 40 == packet.size();
    }
    return false;
}

TunnelPacketPump::TunnelPacketPump(Route route, Session& session, UdpTransport& udp,
                                   IpInterface& interface, TunnelRole role)
    : route_(std::move(route)), session_(session), udp_(udp), interface_(interface), role_(role) {}

bool TunnelPacketPump::sendIpPacket(std::span<const Byte> bytes, std::string* error) {
    if (!isValidIpPacket(bytes)) {
        if (error) *error = "invalid IP packet";
        return false;
    }
    if (route_.nodes.empty() || route_.nodes.size() > 255 ||
        bytes.size() > kMaxDatagramSize - kPacketHeaderSize - kPacketTagSize) {
        if (error) *error = "IP packet cannot fit in one S1lent DATA datagram";
        return false;
    }

    Packet packet;
    packet.routeId = route_.id;
    packet.sessionId = session_.id();
    packet.hop = role_ == TunnelRole::client ? 0 : static_cast<Byte>(route_.nodes.size() - 1);
    const auto direction = role_ == TunnelRole::client ? Direction::outbound : Direction::inbound;
    Endpoint destination;
    {
        std::lock_guard lock(mutex_);
        if (role_ == TunnelRole::server) {
            if (!returnPeer_) {
                if (error) *error = "no authenticated client return path is available";
                return false;
            }
            destination = *returnPeer_;
        } else {
            destination = route_.nodes.front().endpoint;
        }
        if (!session_.seal(packet, bytes, direction)) {
            if (error) *error = "could not encrypt IP packet";
            return false;
        }
    }
    const auto wire = encodePacket(packet);
    if (wire.empty()) {
        if (error) *error = "could not encode IP packet";
        return false;
    }
    return udp_.sendTo(destination, wire, error);
}

bool TunnelPacketPump::receiveDatagram(const Bytes& wire, const Endpoint& peer, std::string* error) {
    if (route_.nodes.empty() || route_.nodes.size() > 255) {
        if (error) *error = "route has an unsupported hop count";
        return false;
    }
    const auto packet = decodePacket(wire, error);
    if (!packet || packet->type != PacketType::data || packet->routeId != route_.id ||
        packet->sessionId != session_.id()) return false;
    const auto expectedDirection = role_ == TunnelRole::client ? Direction::inbound : Direction::outbound;
    const auto expectedHop = role_ == TunnelRole::client ? 0 : route_.nodes.size();
    if (packet->direction != expectedDirection || packet->hop != expectedHop) return false;

    Bytes plaintext;
    {
        std::lock_guard lock(mutex_);
        if (!session_.open(*packet, plaintext)) return false;
        if (role_ == TunnelRole::server) returnPeer_ = peer;
    }
    if (!isValidIpPacket(plaintext)) {
        if (error) *error = "decrypted DATA does not contain a valid IP packet";
        return false;
    }
    return interface_.write(plaintext, error);
}

} // namespace s1lent
