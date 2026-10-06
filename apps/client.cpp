#include "common.hpp"
#include "s1lent/handshake.hpp"
#include "s1lent/ip_interface.hpp"
#include "s1lent/session.hpp"
#include "s1lent/tunnel.hpp"
#include "s1lent/udp_transport.hpp"
#include <openssl/crypto.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

int main(int argc,char** argv){
    const bool tunMode=argc==10&&std::string(argv[8])=="--tun";
    if(argc!=9&&!tunMode){std::cerr<<"usage: s1lent-client <route.conf> <udp-bind-host> <udp-bind-port> <control-host> <control-port> <trusted-ca.pem> <session-id-hex|auto> <message|--tun adapter-name>\n";return 2;}
    try{
        std::string error;auto configured=s1lent::loadRouteConfig(argv[1],&error);if(!configured){std::cerr<<error<<'\n';return 1;}
        s1lent::StaticRouteEngine engine;if(!engine.addRoute(*configured)){std::cerr<<"invalid static route\n";return 1;}
        auto route=engine.selectRoute({configured->destination.host,configured->destination.port});if(!route){std::cerr<<"no matching route\n";return 1;}
        const auto sid=std::string(argv[7])=="auto"?s1lent::randomSessionId():std::stoull(argv[7],nullptr,16);if(!sid)throw std::invalid_argument("session id must be nonzero");
        const s1lent::Endpoint control{argv[4],static_cast<std::uint16_t>(std::stoul(argv[5]))};
        auto key=s1lent::establishClientSessionKey(control,argv[4],argv[6],route->id,sid,&error);if(!key){std::cerr<<error<<'\n';return 1;}
        auto crypto=std::make_shared<s1lent::Aes256GcmContext>(*key);OPENSSL_cleanse(key->data(),key->size());s1lent::Session session(sid,route->id,crypto);
        if(!session.establish()){std::cerr<<"session creation failed\n";return 1;}
        s1lent::UdpTransport udp;if(!udp.bind(endpoint(argv[2],argv[3]),&error)){std::cerr<<error<<'\n';return 1;}
        std::unique_ptr<s1lent::WindowsTunInterface> tun;std::atomic_bool stop{false};
        if(tunMode){tun=std::make_unique<s1lent::WindowsTunInterface>();if(!tun->open(std::wstring(argv[9],argv[9]+std::strlen(argv[9])),&error)){std::cerr<<error<<'\n';return 1;}}
        else{const std::string message=argv[8];s1lent::Packet request;request.routeId=route->id;request.sessionId=sid;request.hop=0;
            if(!session.seal(request,std::span<const s1lent::Byte>(reinterpret_cast<const s1lent::Byte*>(message.data()),message.size()),s1lent::Direction::outbound)){std::cerr<<"could not encrypt request\n";return 1;}
            const auto next=route->nodes.front().endpoint;if(!udp.sendTo(next,s1lent::encodePacket(request),&error)){std::cerr<<error<<'\n';return 1;}}
        std::unique_ptr<s1lent::TunnelPacketPump> tunnelPump;
        if(tunMode)tunnelPump=std::make_unique<s1lent::TunnelPacketPump>(*route,session,udp,*tun,s1lent::TunnelRole::client);
        std::thread tunReader;
        if(tunMode)tunReader=std::thread([&]{while(!stop.load()){s1lent::Bytes ip;if(!tun->read(ip,std::chrono::milliseconds(200)))continue;(void)tunnelPump->sendIpPacket(ip);}});
        bool received=false;
        udp.receiveLoop([&](const s1lent::Bytes& wire,const s1lent::Endpoint& peer){if(tunMode){(void)tunnelPump->receiveDatagram(wire,peer);return true;}
            auto p=s1lent::decodePacket(wire);s1lent::Bytes plain;if(!p||p->sessionId!=sid||p->direction!=s1lent::Direction::inbound)return true;
            if(!session.open(*p,plain))return true;
            std::cout<<std::string(plain.begin(),plain.end())<<'\n';received=true;stop=true;return false;},stop,tunMode?std::chrono::milliseconds::max():std::chrono::milliseconds(route->timeoutMs));
        stop=true;if(tunReader.joinable())tunReader.join();
        return received?0:1;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
