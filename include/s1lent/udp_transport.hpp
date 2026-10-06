#pragma once
#include "types.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>

namespace s1lent {
class UdpTransport {
public:
    UdpTransport();
    ~UdpTransport();
    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;
    bool bind(const Endpoint&, std::string* error = nullptr);
    bool sendTo(const Endpoint&, const Bytes&, std::string* error = nullptr) const;
    void receiveLoop(const std::function<bool(const Bytes&, const Endpoint&)>& handler,
                    const std::atomic_bool& stop,
                    std::chrono::milliseconds timeout = std::chrono::milliseconds::max()) const;
    std::optional<Endpoint> localEndpoint() const;
private:
    std::intptr_t socket_{-1};
};
} // namespace s1lent
