#include "s1lent/session.hpp"
#include <algorithm>

namespace s1lent {
Session::Session(SessionId id,RouteId route,std::shared_ptr<CryptoContext> c):id_(id),route_(route),crypto_(std::move(c)){}
bool Session::establish(){ if(state_!=SessionState::created||!crypto_||id_==0||route_==0)return false; state_=SessionState::established; return true; }
void Session::close(){ if(state_==SessionState::established)state_=SessionState::closing; state_=SessionState::closed; }
bool Session::seal(Packet& p,std::span<const Byte> plain,Direction d){
    if(state_!=SessionState::established||p.routeId!=route_||p.sessionId!=id_||plain.size()>kMaxDatagramSize-kPacketHeaderSize-kPacketTagSize)return false;
    const auto i=static_cast<std::size_t>(d); if(sendCounters_[i]==UINT64_MAX)return false;
    p.type=PacketType::data; p.direction=d; p.packetNumber=++sendCounters_[i]; p.payload.assign(plain.size()+16,0);
    const auto aad=packetAssociatedData(p); Bytes encrypted; if(!crypto_->encrypt(plain,aad,p.packetNumber,d,encrypted)){p.payload.clear();return false;}
    p.payload=std::move(encrypted); return true;
}
bool Session::open(const Packet& p,Bytes& plain){
    if(state_!=SessionState::established||p.type!=PacketType::data||p.routeId!=route_||p.sessionId!=id_)return false;
    const auto i=static_cast<std::size_t>(p.direction); auto& seen=received_[i]; const auto high=highest_[i];
    if(seen.contains(p.packetNumber)||(high>1024&&p.packetNumber<=high-1024))return false;
    const auto aad=packetAssociatedData(p); if(!crypto_->decrypt(p.payload,aad,p.packetNumber,p.direction,plain))return false;
    seen.insert(p.packetNumber); if(p.packetNumber>high)highest_[i]=p.packetNumber;
    const auto threshold=highest_[i]>1024?highest_[i]-1024:0;
    std::erase_if(seen,[&](std::uint64_t n){return n<=threshold;}); return true;
}
} // namespace s1lent
