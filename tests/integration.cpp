#include "s1lent/node.hpp"
#include "s1lent/tunnel.hpp"
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

using namespace s1lent;

namespace {
Endpoint reserveEndpoint() {
    UdpTransport transport;
    if (!transport.bind({"127.0.0.1", 0})) throw std::runtime_error("bind failed");
    return *transport.localEndpoint();
}

class FakeIpInterface final : public IpInterface {
public:
    bool open(const std::wstring&, std::string*) override { return true; }
    bool read(Bytes&, std::chrono::milliseconds) override { return false; }
    bool write(std::span<const Byte> packet, std::string*) override {
        std::lock_guard lock(mutex_);
        delivered_.emplace_back(packet.begin(), packet.end());
        ready_.notify_all();
        return true;
    }
    bool waitForPacket(Bytes& packet, std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        if (!ready_.wait_for(lock, timeout, [&] { return !delivered_.empty(); })) return false;
        packet = std::move(delivered_.front());
        delivered_.erase(delivered_.begin());
        return true;
    }
private:
    std::mutex mutex_;
    std::condition_variable ready_;
    std::vector<Bytes> delivered_;
};

Bytes makeIpv4Packet(Byte marker) {
    Bytes packet(20, 0);
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = static_cast<Byte>(packet.size());
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 10;
    packet[15] = marker;
    packet[16] = 10;
    packet[19] = static_cast<Byte>(marker + 1);
    return packet;
}
} // namespace

int main() {
    try {
        auto a = reserveEndpoint();
        auto b = reserveEndpoint();
        auto serverAddress = reserveEndpoint();
        Route route{7, 1, {{"A", a, "udp"}, {"B", b, "udp"}}, serverAddress, 0, 2000};
        ForwardingNode nodeA(route, 0), nodeB(route, 1);
        if (!nodeA.start(a) || !nodeB.start(b)) throw std::runtime_error("node bind failed");

        UdpTransport server, client;
        if (!server.bind(serverAddress)) throw std::runtime_error("server bind failed");
        const auto clientAddress = reserveEndpoint();
        if (!client.bind(clientAddress)) throw std::runtime_error("client bind failed");

        std::array<Byte, 32> key{};
        for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<Byte>(i + 1);
        auto clientCrypto = std::make_shared<Aes256GcmContext>(key);
        auto serverCrypto = std::make_shared<Aes256GcmContext>(key);
        Session clientSession(99, 7, clientCrypto), serverSession(99, 7, serverCrypto);
        if (!clientSession.establish() || !serverSession.establish()) throw std::runtime_error("session setup failed");

        FakeIpInterface clientIp, serverIp;
        TunnelPacketPump clientPump(route, clientSession, client, clientIp, TunnelRole::client);
        TunnelPacketPump serverPump(route, serverSession, server, serverIp, TunnelRole::server);
        std::atomic_bool stop{false};
        std::thread nodeAThread([&] { nodeA.run(stop); });
        std::thread nodeBThread([&] { nodeB.run(stop); });
        std::thread serverThread([&] {
            server.receiveLoop([&](const Bytes& wire, const Endpoint& peer) {
                (void)serverPump.receiveDatagram(wire, peer);
                return true;
            }, stop);
        });
        std::thread clientThread([&] {
            client.receiveLoop([&](const Bytes& wire, const Endpoint& peer) {
                (void)clientPump.receiveDatagram(wire, peer);
                return true;
            }, stop);
        });

        std::string failure;
        std::string error;
        Bytes received;
        const auto outbound = makeIpv4Packet(1);
        if (!clientPump.sendIpPacket(outbound, &error)) failure = "client tunnel send failed: " + error;
        else if (!serverIp.waitForPacket(received, std::chrono::seconds(5))) failure = "client to server IP path timed out";
        else if (received != outbound) failure = "server received a different IP packet";

        if (failure.empty()) {
            const auto inbound = makeIpv4Packet(17);
            if (!serverPump.sendIpPacket(inbound, &error)) failure = "server tunnel send failed: " + error;
            else if (!clientIp.waitForPacket(received, std::chrono::seconds(5))) failure = "server to client IP path timed out";
            else if (received != inbound) failure = "client received a different IP packet";
        }

        stop = true;
        client.sendTo(clientAddress, Bytes{0});
        server.sendTo(serverAddress, Bytes{0});
        clientThread.join();
        serverThread.join();
        nodeAThread.join();
        nodeBThread.join();
        if (!failure.empty()) throw std::runtime_error(failure);
        std::cout << "bidirectional IPv4 tunnel passed: client -> node A -> node B -> server -> node B -> node A -> client\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
