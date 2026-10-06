#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace s1lent {
using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using RouteId = std::uint32_t;
using SessionId = std::uint64_t;
struct Endpoint {
    std::string host;
    std::uint16_t port{};
    friend bool operator==(const Endpoint&, const Endpoint&) = default;
};
enum class PacketType : Byte { data = 1, ping = 2, pong = 3 };
enum class Direction : Byte { outbound = 0, inbound = 1 };
struct Packet {
    Byte version{1};
    PacketType type{PacketType::data};
    Direction direction{Direction::outbound};
    Byte hop{};
    RouteId routeId{};
    SessionId sessionId{};
    std::uint64_t packetNumber{};
    Bytes payload; // Ciphertext followed by the 16-byte AEAD tag for DATA.
};
struct Node {
    std::string id;
    Endpoint endpoint;
    std::string transport{"udp"};
};
struct Route {
    RouteId id{};
    Byte version{1};
    std::vector<Node> nodes;
    Endpoint destination;
    int priority{};
    std::uint32_t timeoutMs{3000};
};
struct Destination { std::string host; std::uint16_t port{}; };
} // namespace s1lent
