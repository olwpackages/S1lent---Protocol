#include "s1lent/handshake.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

using namespace s1lent;
namespace {
void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
std::pair<std::filesystem::path,std::filesystem::path> createCertificate(){
    std::unique_ptr<EVP_PKEY_CTX,decltype(&EVP_PKEY_CTX_free)> keyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr),EVP_PKEY_CTX_free);
    require(keyContext&&EVP_PKEY_keygen_init(keyContext.get())==1&&EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(),2048)==1,"RSA key init");
    EVP_PKEY* keyRaw=nullptr;require(EVP_PKEY_keygen(keyContext.get(),&keyRaw)==1,"RSA key generation");std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(keyRaw,EVP_PKEY_free);
    std::unique_ptr<X509,decltype(&X509_free)> cert(X509_new(),X509_free);require(cert!=nullptr,"X509 allocation");
    require(X509_set_version(cert.get(),2)==1&&ASN1_INTEGER_set(X509_get_serialNumber(cert.get()),1)==1,"X509 version/serial");
    X509_gmtime_adj(X509_getm_notBefore(cert.get()),-60);X509_gmtime_adj(X509_getm_notAfter(cert.get()),3600);require(X509_set_pubkey(cert.get(),key.get())==1,"X509 public key");
    X509_NAME* subject=X509_get_subject_name(cert.get());require(X509_NAME_add_entry_by_txt(subject,"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char*>("localhost"),-1,-1,0)==1,"X509 subject");
    require(X509_set_issuer_name(cert.get(),subject)==1,"X509 issuer");X509V3_CTX extensionContext{};X509V3_set_ctx(&extensionContext,cert.get(),cert.get(),nullptr,nullptr,0);
    for(const auto& [nid,value]:{std::pair{NID_basic_constraints,"critical,CA:TRUE"},std::pair{NID_subject_alt_name,"DNS:localhost"}}){
        X509_EXTENSION* extension=X509V3_EXT_conf_nid(nullptr,&extensionContext,nid,const_cast<char*>(value));require(extension!=nullptr,"X509 extension");X509_add_ext(cert.get(),extension,-1);X509_EXTENSION_free(extension);
    }
    require(X509_sign(cert.get(),key.get(),EVP_sha256())>0,"X509 signing");
    auto base=std::filesystem::temp_directory_path()/("s1lent-handshake-"+std::to_string(randomSessionId()));auto certPath=base;certPath+=L".crt.pem";auto keyPath=base;keyPath+=L".key.pem";
    std::unique_ptr<BIO,decltype(&BIO_free)> certFile(BIO_new_file(certPath.string().c_str(),"wb"),BIO_free),keyFile(BIO_new_file(keyPath.string().c_str(),"wb"),BIO_free);
    require(certFile&&keyFile&&PEM_write_bio_X509(certFile.get(),cert.get())==1&&PEM_write_bio_PrivateKey(keyFile.get(),key.get(),nullptr,nullptr,0,nullptr,nullptr)==1,"write TLS test credentials");
    return {certPath,keyPath};
}
}
int main(){
    std::filesystem::path cert,key;
    try{
        auto files=createCertificate();cert=files.first;key=files.second;
        StaticRouteEngine routes;Route route{19,1,{{"test-hop",{"127.0.0.1",41001},"udp"}},{"127.0.0.1",41002},0,3000};require(routes.addRoute(route),"add route");
        TlsControlServer server;std::string error;require(server.start({"127.0.0.1",0},cert.string(),key.string(),&error),"start TLS control server");auto endpoint=server.localEndpoint();require(endpoint&&endpoint->port,"TLS ephemeral port");
        std::atomic_bool stop{false};SessionKey serverKey{};SessionId acceptedId{};bool accepted=false;std::mutex acceptedMutex;
        std::thread worker([&]{server.run(stop,routes,[&](SessionId id,RouteId routeId,const SessionKey& sessionKey){std::lock_guard lock(acceptedMutex);if(routeId!=19||accepted)return false;accepted=true;acceptedId=id;serverKey=sessionKey;return true;});});
        struct JoinOnExit { std::atomic_bool& stop;std::thread& worker;~JoinOnExit(){stop=true;if(worker.joinable())worker.join();} } joinOnExit{stop,worker};
        const SessionId id=randomSessionId();auto clientKey=establishClientSessionKey(*endpoint,"localhost",cert.string(),19,id,&error);
        require(clientKey.has_value(),error.c_str());{std::lock_guard lock(acceptedMutex);require(acceptedId==id&&*clientKey==serverKey,"TLS exporter keys match for the session");}
        auto missingRoute=establishClientSessionKey(*endpoint,"localhost",cert.string(),999,randomSessionId(),&error);require(!missingRoute,"server rejects unconfigured route setup");
        auto wrongIdentity=establishClientSessionKey(*endpoint,"not-localhost",cert.string(),19,randomSessionId(),&error);require(!wrongIdentity,"client rejects mismatched server identity");
        stop=true;worker.join();std::filesystem::remove(cert);std::filesystem::remove(key);
        std::cout<<"TLS 1.3 server authentication, route setup, and per-session key exporter tests passed\n";return 0;
    }catch(const std::exception& e){if(!cert.empty())std::filesystem::remove(cert);if(!key.empty())std::filesystem::remove(key);std::cerr<<e.what()<<'\n';return 1;}
}
