#include "s1lent/packet.hpp"
#include <limits>

namespace s1lent {
namespace {
constexpr std::uint16_t kMagic = 0x5331;
void put16(Bytes& b, std::uint16_t v) { b.push_back(static_cast<Byte>(v >> 8)); b.push_back(static_cast<Byte>(v)); }
void put32(Bytes& b, std::uint32_t v) { for (int i=3;i>=0;--i) b.push_back(static_cast<Byte>(v >> (i*8))); }
void put64(Bytes& b, std::uint64_t v) { for (int i=7;i>=0;--i) b.push_back(static_cast<Byte>(v >> (i*8))); }
std::uint16_t get16(const Bytes& b, std::size_t p) { return static_cast<std::uint16_t>((static_cast<unsigned>(b[p])<<8)|b[p+1]); }
std::uint32_t get32(const Bytes& b, std::size_t p) { std::uint32_t v=0; for(int i=0;i<4;++i) v=(v<<8)|b[p+static_cast<std::size_t>(i)]; return v; }
std::uint64_t get64(const Bytes& b, std::size_t p) { std::uint64_t v=0; for(int i=0;i<8;++i) v=(v<<8)|b[p+static_cast<std::size_t>(i)]; return v; }
}

Bytes packetAssociatedData(const Packet& p) {
    Bytes b; b.reserve(27); put16(b,kMagic); b.push_back(p.version); b.push_back(static_cast<Byte>(p.type));
    b.push_back(static_cast<Byte>(p.direction)); put32(b,p.routeId); put64(b,p.sessionId); put64(b,p.packetNumber);
    put16(b,static_cast<std::uint16_t>(p.payload.size())); return b;
}

Bytes encodePacket(const Packet& p) {
    if (p.version != 1 || static_cast<Byte>(p.type)<1 || static_cast<Byte>(p.type)>3 ||
        static_cast<Byte>(p.direction)>1 || p.routeId==0 || p.sessionId==0 || p.packetNumber==0 ||
        p.payload.size()>kMaxDatagramSize-kPacketHeaderSize || p.payload.size()>std::numeric_limits<std::uint16_t>::max() ||
        (p.type==PacketType::data && p.payload.size()<kPacketTagSize)) return {};
    Bytes b; b.reserve(kPacketHeaderSize+p.payload.size()); put16(b,kMagic); b.push_back(p.version);
    b.push_back(static_cast<Byte>(p.type)); b.push_back(static_cast<Byte>(p.direction)); b.push_back(p.hop);
    put32(b,p.routeId); put64(b,p.sessionId); put64(b,p.packetNumber); put16(b,static_cast<std::uint16_t>(p.payload.size()));
    b.insert(b.end(),p.payload.begin(),p.payload.end()); return b;
}

std::optional<Packet> decodePacket(const Bytes& b, std::string* error) {
    const auto fail=[&](const char* why)->std::optional<Packet>{ if(error)*error=why; return std::nullopt; };
    if(b.size()<kPacketHeaderSize) return fail("truncated header");
    if(get16(b,0)!=kMagic) return fail("bad magic");
    if(b[2]!=1) return fail("unsupported version");
    if(b[3]<1||b[3]>3) return fail("unknown packet type");
    if(b[4]>1) return fail("invalid direction");
    const auto n=get16(b,26);
    if(static_cast<std::size_t>(n)!=b.size()-kPacketHeaderSize) return fail("payload length mismatch");
    if(b.size()>kMaxDatagramSize) return fail("datagram exceeds maximum");
    Packet p; p.version=b[2]; p.type=static_cast<PacketType>(b[3]); p.direction=static_cast<Direction>(b[4]); p.hop=b[5];
    p.routeId=get32(b,6); p.sessionId=get64(b,10); p.packetNumber=get64(b,18);
    if(p.routeId==0||p.sessionId==0||p.packetNumber==0) return fail("zero route, session, or packet number");
    p.payload.assign(b.begin()+static_cast<std::ptrdiff_t>(kPacketHeaderSize),b.end());
    if(p.type==PacketType::data && p.payload.size()<kPacketTagSize) return fail("encrypted DATA is shorter than tag");
    return p;
}
} // namespace s1lent
