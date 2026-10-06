#include "common.hpp"
#include "s1lent/handshake.hpp"
#include "s1lent/ip_interface.hpp"
#include "s1lent/session.hpp"
#include "s1lent/tunnel.hpp"
#include "s1lent/udp_transport.hpp"
#include <iostream>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>

int main(int argc,char** argv){
    const bool tunMode=argc==10&&std::string(argv[8])=="--tun";
    if(argc!=8&&!tunMode){std::cerr<<"usage: s1lent-server <route.conf> <udp-bind-host> <udp-bind-port> <tls-bind-host> <tls-port> <certificate.pem> <private-key.pem> [--tun adapter-name]\n";return 2;}
    try{
        std::string error;auto route=s1lent::loadRouteConfig(argv[1],&error);if(!route){std::cerr<<error<<'\n';return 1;}
        s1lent::StaticRouteEngine routes;if(!routes.addRoute(*route)){std::cerr<<"invalid route configuration\n";return 1;}
        s1lent::TlsControlServer control;if(!control.start(endpoint(argv[4],argv[5]),argv[6],argv[7],&error)){std::cerr<<error<<'\n';return 1;}
        const std::wstring adapterName=tunMode?std::wstring(argv[9],argv[9]+std::strlen(argv[9])):std::wstring{};
        std::unique_ptr<s1lent::WindowsTunInterface> tun;if(tunMode){tun=std::make_unique<s1lent::WindowsTunInterface>();if(!tun->open(adapterName,&error)){std::cerr<<error<<'\n';return 1;}}
        s1lent::UdpTransport udp;if(!udp.bind(endpoint(argv[2],argv[3]),&error)){std::cerr<<error<<'\n';return 1;}
        std::mutex mutex;std::unordered_map<s1lent::SessionId,std::unique_ptr<s1lent::Session>> sessions;
        std::unique_ptr<s1lent::TunnelPacketPump> tunnelPump;s1lent::SessionId activeTunnelSession{};std::atomic_bool stop{false};
        std::thread controlThread([&]{control.run(stop,routes,[&](s1lent::SessionId id,s1lent::RouteId routeId,const s1lent::SessionKey& key){
            std::lock_guard lock(mutex);if(sessions.contains(id)||sessions.size()>=4096||(tunMode&&!sessions.empty()))return false;
            auto crypto=std::make_shared<s1lent::Aes256GcmContext>(key);auto session=std::make_unique<s1lent::Session>(id,routeId,std::move(crypto));if(!session->establish())return false;
            auto* sessionPtr=session.get();sessions.emplace(id,std::move(session));
            if(tunMode){activeTunnelSession=id;tunnelPump=std::make_unique<s1lent::TunnelPacketPump>(*route,*sessionPtr,udp,*tun,s1lent::TunnelRole::server);}
            return true;
        });});
        std::thread tunReader;
        if(tunMode)tunReader=std::thread([&]{while(!stop.load()){s1lent::Bytes ip;if(!tun->read(ip,std::chrono::milliseconds(200)))continue;
            std::lock_guard lock(mutex);if(tunnelPump)(void)tunnelPump->sendIpPacket(ip);}});
        std::cout<<"S1lent experimental TLS 1.3 control + UDP server"<<(tunMode?" + Wintun":"")<<" listening\n";
        udp.receiveLoop([&](const s1lent::Bytes& wire,const s1lent::Endpoint& peer){
            auto p=s1lent::decodePacket(wire);if(!p||p->routeId!=route->id||p->direction!=s1lent::Direction::outbound)return true;
            std::lock_guard lock(mutex);auto it=sessions.find(p->sessionId);if(it==sessions.end())return true;
            if(tunMode){if(activeTunnelSession!=p->sessionId||!tunnelPump)return true;(void)tunnelPump->receiveDatagram(wire,peer);return true;}
            s1lent::Bytes plain;if(!it->second->open(*p,plain))return true;
            s1lent::Packet response;response.routeId=p->routeId;response.sessionId=p->sessionId;response.hop=static_cast<s1lent::Byte>(route->nodes.size()-1);
            const std::string prefix="echo:";s1lent::Bytes reply(prefix.begin(),prefix.end());reply.insert(reply.end(),plain.begin(),plain.end());
            if(!it->second->seal(response,reply,s1lent::Direction::inbound))return true;
            udp.sendTo(peer,s1lent::encodePacket(response));return true;
        },stop);stop=true;if(tunReader.joinable())tunReader.join();if(controlThread.joinable())controlThread.join();return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
