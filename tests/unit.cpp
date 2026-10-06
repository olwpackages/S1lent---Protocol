#include "s1lent/packet.hpp"
#include "s1lent/route.hpp"
#include "s1lent/session.hpp"
#include "s1lent/tunnel.hpp"
#include "common.hpp"
#include <iostream>
#include <stdexcept>
using namespace s1lent;
static void require(bool value,const char* message){if(!value)throw std::runtime_error(message);}
int main(){try{
 Packet p;p.routeId=3;p.sessionId=42;p.packetNumber=1;p.payload=Bytes(16,0x5a);auto encoded=encodePacket(p);
 require(encoded.size()==44,"wire encoding size");auto decoded=decodePacket(encoded);require(decoded.has_value(),"decode valid packet");
 require(decoded->routeId==3&&decoded->sessionId==42,"header fields");auto bad=encoded;bad.pop_back();require(!decodePacket(bad),"truncated payload");
 bad=encoded;bad[0]=0;require(!decodePacket(bad),"bad magic");bad=encoded;bad[26]=0;bad[27]=1;require(!decodePacket(bad),"length mismatch");
 bad=encoded;bad[2]=2;require(!decodePacket(bad),"unsupported version");
 bad=encoded;bad[9]=0;bad[8]=0;bad[7]=0;bad[6]=0;require(!decodePacket(bad),"reject zero route id");
 bad=encoded;for(std::size_t i=10;i<18;++i)bad[i]=0;require(!decodePacket(bad),"reject zero session id");
 std::array<Byte,32> key{};key[0]=7;auto crypto=std::make_shared<Aes256GcmContext>(key);Session sender(42,3,crypto),receiver(42,3,crypto);
 require(sender.establish()&&receiver.establish(),"session establish");Packet data;data.routeId=3;data.sessionId=42;Bytes message{'s','e','c','r','e','t'};
 require(sender.seal(data,message,Direction::outbound),"encrypt DATA");Bytes plain;require(receiver.open(data,plain)&&plain==message,"decrypt DATA");
 Packet wrongSession=data;wrongSession.sessionId=77;require(!receiver.open(wrongSession,plain),"reject invalid session");
 require(!receiver.open(data,plain),"reject replay");Packet altered=data;altered.payload[0]^=1;altered.packetNumber=2;require(!receiver.open(altered,plain),"reject auth failure");
 StaticRouteEngine routes;Route route{1,1,{{"n1",{"127.0.0.1",4001},"udp"}},{"127.0.0.1",5000},2,1000};
 require(routes.validateRoute(route)&&routes.addRoute(route),"route create");require(routes.selectRoute({"127.0.0.1",5000}).has_value(),"route select");
 auto updated=route;updated.priority=3;require(routes.addRoute(updated),"route update");require(routes.removeRoute(1)&&!routes.find(1),"route delete");
 const auto parsed=loadRouteConfigText("route_id: 8\npriority: 1\ntimeout_ms: 99\ndestination: 127.0.0.1:5555\nnodes:\n  - hop@127.0.0.1:4444\n");
 require(parsed&&parsed->nodes.size()==1&&parsed->destination.port==5555,"route config parse");
 require(!loadRouteConfigText("route_id: 1\ndestination: invalid\nnodes:\n"),"reject malformed route config");
 Bytes ipv4(20,0);ipv4[0]=0x45;ipv4[2]=0;ipv4[3]=20;require(isValidIpPacket(ipv4),"accept valid IPv4 packet");
 ipv4[3]=19;require(!isValidIpPacket(ipv4),"reject inconsistent IPv4 length");Bytes ipv6(40,0);ipv6[0]=0x60;require(isValidIpPacket(ipv6),"accept valid IPv6 packet");
 std::cout<<"packet, validation, AEAD, replay, and route tests passed\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
