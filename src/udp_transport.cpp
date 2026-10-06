#include "s1lent/udp_transport.hpp"
#include <array>
#include <cstring>
#include <stdexcept>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace s1lent {
namespace {
#ifdef _WIN32
using NativeSocket=SOCKET; constexpr NativeSocket badSocket=INVALID_SOCKET;
void closeSocket(NativeSocket s){closesocket(s);}
struct Startup { Startup(){WSADATA d{};if(WSAStartup(MAKEWORD(2,2),&d)!=0)throw std::runtime_error("WSAStartup failed");}~Startup(){WSACleanup();} };
#else
using NativeSocket=int; constexpr NativeSocket badSocket=-1;
void closeSocket(NativeSocket s){::close(s);}
struct Startup {};
#endif
NativeSocket native(std::intptr_t h){return static_cast<NativeSocket>(h);}
bool resolve(const Endpoint& e,addrinfo*& result,int flags){addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_DGRAM;hints.ai_protocol=IPPROTO_UDP;hints.ai_flags=flags;return getaddrinfo(e.host.c_str(),std::to_string(e.port).c_str(),&hints,&result)==0;}
Endpoint fromAddress(const sockaddr* a){char host[NI_MAXHOST]{},serv[NI_MAXSERV]{};if(getnameinfo(a,a->sa_family==AF_INET?sizeof(sockaddr_in):sizeof(sockaddr_in6),host,sizeof(host),serv,sizeof(serv),NI_NUMERICHOST|NI_NUMERICSERV)!=0)return {};return {host,static_cast<std::uint16_t>(std::stoi(serv))};}
}
UdpTransport::UdpTransport(){static Startup startup;(void)startup;}
UdpTransport::~UdpTransport(){if(socket_!=-1)closeSocket(native(socket_));}
bool UdpTransport::bind(const Endpoint& e,std::string* error){
    addrinfo* list=nullptr;if(!resolve(e,list,AI_PASSIVE)){if(error)*error="address resolution failed";return false;}
    for(auto* ai=list;ai;ai=ai->ai_next){auto s=::socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);if(s==badSocket)continue;
        if(::bind(s,ai->ai_addr,static_cast<int>(ai->ai_addrlen))==0){socket_=static_cast<std::intptr_t>(s);break;}closeSocket(s);}
    freeaddrinfo(list);if(socket_==-1&&error)*error="UDP bind failed";return socket_!=-1;
}
bool UdpTransport::sendTo(const Endpoint& e,const Bytes& b,std::string* error)const{
    if(socket_==-1||b.size()>65507){if(error)*error="invalid socket or datagram size";return false;}addrinfo* list=nullptr;if(!resolve(e,list,0)){if(error)*error="address resolution failed";return false;}bool sent=false;
    for(auto* ai=list;ai;ai=ai->ai_next){const auto n=::sendto(native(socket_),reinterpret_cast<const char*>(b.data()),static_cast<int>(b.size()),0,ai->ai_addr,static_cast<int>(ai->ai_addrlen));if(n==static_cast<int>(b.size())){sent=true;break;}}
    freeaddrinfo(list);if(!sent&&error)*error="UDP send failed";return sent;
}
void UdpTransport::receiveLoop(const std::function<bool(const Bytes&,const Endpoint&)>& fn,const std::atomic_bool& stop,std::chrono::milliseconds timeout)const{
    const bool finite=timeout!=std::chrono::milliseconds::max();
    const auto deadline=finite?std::chrono::steady_clock::now()+timeout:std::chrono::steady_clock::time_point::max();
    std::array<Byte,65535> buffer{};while(!stop.load()){
        if(finite&&std::chrono::steady_clock::now()>=deadline)break;
#ifdef _WIN32
        fd_set readSet;FD_ZERO(&readSet);FD_SET(native(socket_),&readSet);timeval wait{0,200000};if(select(0,&readSet,nullptr,nullptr,&wait)<=0)continue;
#else
        fd_set readSet;FD_ZERO(&readSet);FD_SET(native(socket_),&readSet);timeval wait{0,200000};if(select(native(socket_)+1,&readSet,nullptr,nullptr,&wait)<=0)continue;
#endif
        sockaddr_storage addr{};int len=sizeof(addr);auto n=::recvfrom(native(socket_),reinterpret_cast<char*>(buffer.data()),static_cast<int>(buffer.size()),0,reinterpret_cast<sockaddr*>(&addr),&len);if(n<=0)continue;
        Bytes b(buffer.begin(),buffer.begin()+n);if(!fn(b,fromAddress(reinterpret_cast<sockaddr*>(&addr))))break;
    }
}
std::optional<Endpoint> UdpTransport::localEndpoint()const{if(socket_==-1)return std::nullopt;sockaddr_storage a{};int len=sizeof(a);if(getsockname(native(socket_),reinterpret_cast<sockaddr*>(&a),&len)!=0)return std::nullopt;return fromAddress(reinterpret_cast<sockaddr*>(&a));}
} // namespace s1lent
