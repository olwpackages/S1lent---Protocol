#pragma once
#include "types.hpp"
#include <optional>

namespace s1lent {
inline constexpr std::size_t kPacketHeaderSize = 28;
inline constexpr std::size_t kPacketTagSize = 16;
inline constexpr std::size_t kMaxDatagramSize = 1200;
Bytes encodePacket(const Packet& packet);
std::optional<Packet> decodePacket(const Bytes& wire, std::string* error = nullptr);
Bytes packetAssociatedData(const Packet& packet);
}
