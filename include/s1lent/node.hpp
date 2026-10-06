#pragma once
#include "route.hpp"
#include "packet.hpp"
#include "udp_transport.hpp"
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace s1lent {
class ForwardingNode {
public:
    ForwardingNode(Route route, std::size_t index);
    bool start(const Endpoint& listen, std::string* error = nullptr);
    void run(const std::atomic_bool& stop);
    bool forwardDatagram(const Bytes& wire, const Endpoint& peer, std::string* error = nullptr);
private:
    Route route_;
    std::size_t index_{};
    UdpTransport transport_;
    std::mutex peersMutex_;
    std::unordered_map<SessionId, Endpoint> upstream_;
};
} // namespace s1lent
