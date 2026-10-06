#pragma once
#include "crypto.hpp"
#include "packet.hpp"
#include <memory>
#include <unordered_set>

namespace s1lent {
enum class SessionState { created, established, closing, closed };
class Session {
public:
    Session(SessionId id, RouteId route, std::shared_ptr<CryptoContext> crypto);
    bool establish();
    void close();
    SessionState state() const noexcept { return state_; }
    SessionId id() const noexcept { return id_; }
    RouteId routeId() const noexcept { return route_; }
    bool seal(Packet& packet, std::span<const Byte> plaintext, Direction direction);
    bool open(const Packet& packet, Bytes& plaintext);
private:
    SessionId id_{};
    RouteId route_{};
    std::shared_ptr<CryptoContext> crypto_;
    SessionState state_{SessionState::created};
    std::uint64_t sendCounters_[2]{};
    std::uint64_t highest_[2]{};
    std::unordered_set<std::uint64_t> received_[2];
};
} // namespace s1lent
