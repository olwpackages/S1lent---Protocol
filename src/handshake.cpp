#include "s1lent/handshake.hpp"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <array>
#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
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
using NativeSocket=SOCKET;constexpr NativeSocket badSocket=INVALID_SOCKET;
void closeSocket(NativeSocket s){closesocket(s);}
struct Winsock { Winsock(){WSADATA d{};if(WSAStartup(MAKEWORD(2,2),&d)!=0)throw std::runtime_error("WSAStartup failed");}~Winsock(){WSACleanup();} };
#else
using NativeSocket=int;constexpr NativeSocket badSocket=-1;
void closeSocket(NativeSocket s){::close(s);}
struct Winsock {};
#endif
NativeSocket native(std::intptr_t s){return static_cast<NativeSocket>(s);}
void put32(Byte* b,std::uint32_t v){for(int i=3;i>=0;--i)b[3-i]=static_cast<Byte>(v>>(i*8));}
void put64(Byte* b,std::uint64_t v){for(int i=7;i>=0;--i)b[7-i]=static_cast<Byte>(v>>(i*8));}
std::uint32_t get32(const Byte* b){std::uint32_t v=0;for(int i=0;i<4;++i)v=(v<<8)|b[i];return v;}
std::uint64_t get64(const Byte* b){std::uint64_t v=0;for(int i=0;i<8;++i)v=(v<<8)|b[i];return v;}
constexpr std::array<Byte,4> magic{'S','1','C','H'};
constexpr char exporterLabel[]="EXPORTER-S1lent-Session-v1";
Bytes contextFor(RouteId route,SessionId session){Bytes c(12);put32(c.data(),route);put64(c.data()+4,session);return c;}
void makeHello(Byte* b,RouteId route,SessionId session){std::copy(magic.begin(),magic.end(),b);b[4]=1;b[5]=1;put32(b+6,route);put64(b+10,session);}
bool verifyHello(const Byte* b,RouteId& route,SessionId& session){if(!std::equal(magic.begin(),magic.end(),b)||b[4]!=1||b[5]!=1)return false;route=get32(b+6);session=get64(b+10);return route&&session;}
bool verifyReply(const Byte* b,RouteId& route,SessionId& session){if(!std::equal(magic.begin(),magic.end(),b)||b[4]!=1||b[5]!=2||b[18]!=1)return false;route=get32(b+6);session=get64(b+10);return route&&session;}
bool readExact(SSL* ssl,Byte* data,int size){int done=0;while(done<size){int n=SSL_read(ssl,data+done,size-done);if(n<=0)return false;done+=n;}return true;}
bool writeExact(SSL* ssl,const Byte* data,int size){int done=0;while(done<size){int n=SSL_write(ssl,data+done,size-done);if(n<=0)return false;done+=n;}return true;}
NativeSocket connectTcp(const Endpoint& e){addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;hints.ai_protocol=IPPROTO_TCP;addrinfo* list=nullptr;if(getaddrinfo(e.host.c_str(),std::to_string(e.port).c_str(),&hints,&list)!=0)return badSocket;NativeSocket s=badSocket;for(auto* ai=list;ai;ai=ai->ai_next){s=::socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);if(s==badSocket)continue;if(::connect(s,ai->ai_addr,static_cast<int>(ai->ai_addrlen))==0)break;closeSocket(s);s=badSocket;}freeaddrinfo(list);return s;}
void setIoTimeout(NativeSocket s){
#ifdef _WIN32
    DWORD timeout=5000;setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
#else
    timeval timeout{5,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
#endif
}
std::string sslError(const char* prefix){unsigned long code=ERR_get_error();char buffer[256]{};if(code)ERR_error_string_n(code,buffer,sizeof(buffer));return std::string(prefix)+(code?": "+std::string(buffer):"");}
bool derive(SSL* ssl,RouteId route,SessionId session,SessionKey& key){auto ctx=contextFor(route,session);return SSL_export_keying_material(ssl,key.data(),key.size(),exporterLabel,sizeof(exporterLabel)-1,ctx.data(),ctx.size(),1)==1;}
SSL_CTX* makeTlsContext(bool server){SSL_CTX* c=SSL_CTX_new(server?TLS_server_method():TLS_client_method());if(!c)return nullptr;SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION);SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION);SSL_CTX_set_options(c,SSL_OP_NO_RENEGOTIATION);return c;}
}
SessionId randomSessionId(){SessionId id{};do{if(RAND_bytes(reinterpret_cast<unsigned char*>(&id),sizeof(id))!=1)throw std::runtime_error("OpenSSL random generator failed");}while(id==0);return id;}

std::optional<SessionKey> establishClientSessionKey(const Endpoint& server,const std::string& name,const std::string& ca,RouteId route,SessionId session,std::string* error){
    static Winsock winsock;(void)winsock;
    auto fail=[&](const std::string& s)->std::optional<SessionKey>{if(error)*error=s;return std::nullopt;};
    SSL_CTX* raw=makeTlsContext(false);if(!raw)return fail(sslError("TLS context creation failed"));std::unique_ptr<SSL_CTX,decltype(&SSL_CTX_free)> ctx(raw,SSL_CTX_free);
    SSL_CTX_set_verify(ctx.get(),SSL_VERIFY_PEER,nullptr);if(SSL_CTX_load_verify_locations(ctx.get(),ca.c_str(),nullptr)!=1)return fail(sslError("trusted CA load failed"));
    NativeSocket sock=connectTcp(server);if(sock==badSocket)return fail("TCP connection to control endpoint failed");
    setIoTimeout(sock);SSL* sslRaw=SSL_new(ctx.get());if(!sslRaw){closeSocket(sock);return fail(sslError("TLS session allocation failed"));}
    std::unique_ptr<SSL,decltype(&SSL_free)> ssl(sslRaw,SSL_free);SSL_set_fd(ssl.get(),static_cast<int>(sock));
    addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_flags=AI_NUMERICHOST;addrinfo* numeric=nullptr;
    const bool isIp=getaddrinfo(name.c_str(),nullptr,&hints,&numeric)==0;if(numeric)freeaddrinfo(numeric);
    if(name.empty()||(isIp?X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl.get()),name.c_str())!=1:SSL_set1_host(ssl.get(),name.c_str())!=1)){closeSocket(sock);return fail("invalid expected TLS server identity");}
    if(!isIp)SSL_set_tlsext_host_name(ssl.get(),name.c_str());
    if(SSL_connect(ssl.get())!=1){closeSocket(sock);return fail(sslError("TLS 1.3 server authentication failed"));}
    std::array<Byte,18> hello{};makeHello(hello.data(),route,session);
    std::array<Byte,19> reply{};const bool exchanged=writeExact(ssl.get(),hello.data(),static_cast<int>(hello.size()))&&readExact(ssl.get(),reply.data(),static_cast<int>(reply.size()));
    closeSocket(sock);if(!exchanged)return fail("TLS route setup exchange failed");
    RouteId acceptedRoute{};SessionId acceptedSession{};if(!verifyReply(reply.data(),acceptedRoute,acceptedSession)||acceptedRoute!=route||acceptedSession!=session)return fail("server rejected route/session setup");
    SessionKey key{};if(!derive(ssl.get(),route,session,key)){OPENSSL_cleanse(key.data(),key.size());return fail(sslError("TLS session key export failed"));}
    const SessionKey result=key;OPENSSL_cleanse(key.data(),key.size());return result;
}

TlsControlServer::TlsControlServer(){static Winsock winsock;(void)winsock;}
TlsControlServer::~TlsControlServer(){if(socket_!=-1)closeSocket(native(socket_));if(context_)SSL_CTX_free(context_);}
bool TlsControlServer::start(const Endpoint& listen,const std::string& cert,const std::string& privateKey,std::string* error){
    context_=makeTlsContext(true);if(!context_){if(error)*error=sslError("TLS context creation failed");return false;}
    if(SSL_CTX_use_certificate_chain_file(context_,cert.c_str())!=1||SSL_CTX_use_PrivateKey_file(context_,privateKey.c_str(),SSL_FILETYPE_PEM)!=1||SSL_CTX_check_private_key(context_)!=1){if(error)*error=sslError("TLS certificate/private key load failed");return false;}
    addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;hints.ai_protocol=IPPROTO_TCP;hints.ai_flags=AI_PASSIVE;addrinfo* list=nullptr;
    if(getaddrinfo(listen.host.c_str(),std::to_string(listen.port).c_str(),&hints,&list)!=0){if(error)*error="control listen address resolution failed";return false;}
    for(auto* ai=list;ai;ai=ai->ai_next){auto s=::socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);if(s==badSocket)continue;int yes=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,reinterpret_cast<const char*>(&yes),sizeof(yes));if(::bind(s,ai->ai_addr,static_cast<int>(ai->ai_addrlen))==0&&::listen(s,16)==0){socket_=static_cast<std::intptr_t>(s);break;}closeSocket(s);}
    freeaddrinfo(list);if(socket_==-1&&error)*error="TLS control bind/listen failed";return socket_!=-1;
}
std::optional<Endpoint> TlsControlServer::localEndpoint()const{
    if(socket_==-1)return std::nullopt;sockaddr_storage address{};int size=sizeof(address);
    if(getsockname(native(socket_),reinterpret_cast<sockaddr*>(&address),&size)!=0)return std::nullopt;
    char host[NI_MAXHOST]{},service[NI_MAXSERV]{};
    if(getnameinfo(reinterpret_cast<sockaddr*>(&address),size,host,sizeof(host),service,sizeof(service),NI_NUMERICHOST|NI_NUMERICSERV)!=0)return std::nullopt;
    return Endpoint{host,static_cast<std::uint16_t>(std::stoi(service))};
}
void TlsControlServer::run(const std::atomic_bool& stop,const RouteEngine& routes,const std::function<bool(SessionId,RouteId,const SessionKey&)>& acceptSession){
    while(!stop.load()){
#ifdef _WIN32
        fd_set reads;FD_ZERO(&reads);FD_SET(native(socket_),&reads);timeval wait{0,200000};if(select(0,&reads,nullptr,nullptr,&wait)<=0)continue;
#else
        fd_set reads;FD_ZERO(&reads);FD_SET(native(socket_),&reads);timeval wait{0,200000};if(select(native(socket_)+1,&reads,nullptr,nullptr,&wait)<=0)continue;
#endif
        NativeSocket peer=::accept(native(socket_),nullptr,nullptr);if(peer==badSocket)continue;setIoTimeout(peer);SSL* sslRaw=SSL_new(context_);if(!sslRaw){closeSocket(peer);continue;}std::unique_ptr<SSL,decltype(&SSL_free)> ssl(sslRaw,SSL_free);SSL_set_fd(ssl.get(),static_cast<int>(peer));
        std::array<Byte,18> hello{};RouteId route{};SessionId session{};bool ok=SSL_accept(ssl.get())==1&&readExact(ssl.get(),hello.data(),static_cast<int>(hello.size()))&&verifyHello(hello.data(),route,session)&&routes.find(route).has_value();
        SessionKey key{};if(ok)ok=derive(ssl.get(),route,session,key)==1&&acceptSession(session,route,key);
        std::array<Byte,19> reply{};makeHello(reply.data(),ok?route:0,ok?session:0);reply[5]=2;reply[18]=ok?1:0;
        if(SSL_is_init_finished(ssl.get()))(void)writeExact(ssl.get(),reply.data(),static_cast<int>(reply.size()));
        OPENSSL_cleanse(key.data(),key.size());SSL_shutdown(ssl.get());closeSocket(peer);
    }
}
} // namespace s1lent
