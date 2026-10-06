#pragma once
#include "route.hpp"
#include <openssl/ssl.h>
#include <array>
#include <atomic>
#include <functional>

namespace s1lent {
using SessionKey = std::array<Byte, 32>;
std::optional<SessionKey> establishClientSessionKey(const Endpoint& controlServer,
    const std::string& expectedServerName, const std::string& trustedCaFile,
    RouteId route, SessionId session, std::string* error = nullptr);

class TlsControlServer {
public:
    TlsControlServer();
    ~TlsControlServer();
    TlsControlServer(const TlsControlServer&) = delete;
    TlsControlServer& operator=(const TlsControlServer&) = delete;
    bool start(const Endpoint& listen, const std::string& certificateFile,
               const std::string& privateKeyFile, std::string* error = nullptr);
    std::optional<Endpoint> localEndpoint() const;
    void run(const std::atomic_bool& stop, const RouteEngine& routes,
             const std::function<bool(SessionId, RouteId, const SessionKey&)>& acceptSession);
private:
    std::intptr_t socket_{-1};
    SSL_CTX* context_{};
};
SessionId randomSessionId();
} // namespace s1lent
