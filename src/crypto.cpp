#include "s1lent/crypto.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <climits>
#include <stdexcept>

namespace s1lent {
namespace {
using Ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
std::array<Byte,12> nonceFor(std::uint64_t n, Direction d) {
    std::array<Byte,12> iv{}; iv[0]=static_cast<Byte>(d);
    for(int i=0;i<8;++i) iv[4+static_cast<std::size_t>(i)]=static_cast<Byte>(n >> ((7-i)*8));
    return iv;
}
}
Aes256GcmContext::Aes256GcmContext(std::array<Byte,32> k):key_(k) {}
Aes256GcmContext::~Aes256GcmContext(){ OPENSSL_cleanse(key_.data(),key_.size()); }
bool Aes256GcmContext::encrypt(std::span<const Byte> pt,std::span<const Byte> aad,std::uint64_t n,Direction d,Bytes& out) {
    if(n==0||pt.size()>static_cast<std::size_t>(INT_MAX)||aad.size()>static_cast<std::size_t>(INT_MAX)) return false;
    Ctx c(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free); if(!c) return false;
    const auto iv=nonceFor(n,d); int len=0, written=0; out.assign(pt.size()+16,0);
    bool ok=EVP_EncryptInit_ex(c.get(),EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1 &&
      EVP_CIPHER_CTX_ctrl(c.get(),EVP_CTRL_GCM_SET_IVLEN,static_cast<int>(iv.size()),nullptr)==1 &&
      EVP_EncryptInit_ex(c.get(),nullptr,nullptr,key_.data(),iv.data())==1;
    if(ok&&!aad.empty()) ok=EVP_EncryptUpdate(c.get(),nullptr,&len,aad.data(),static_cast<int>(aad.size()))==1;
    if(ok&&!pt.empty()) { ok=EVP_EncryptUpdate(c.get(),out.data(),&len,pt.data(),static_cast<int>(pt.size()))==1; written=len; }
    if(ok) { ok=EVP_EncryptFinal_ex(c.get(),out.data()+written,&len)==1; written+=len; }
    if(ok) ok=EVP_CIPHER_CTX_ctrl(c.get(),EVP_CTRL_GCM_GET_TAG,16,out.data()+pt.size())==1;
    if(!ok) out.clear(); else out.resize(static_cast<std::size_t>(written)+16); return ok;
}
bool Aes256GcmContext::decrypt(std::span<const Byte> ct,std::span<const Byte> aad,std::uint64_t n,Direction d,Bytes& out) {
    if(n==0||ct.size()<16||ct.size()>static_cast<std::size_t>(INT_MAX)||aad.size()>static_cast<std::size_t>(INT_MAX)) return false;
    const auto size=ct.size()-16; Ctx c(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free); if(!c) return false;
    const auto iv=nonceFor(n,d); int len=0,written=0; out.assign(size,0);
    bool ok=EVP_DecryptInit_ex(c.get(),EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1 &&
      EVP_CIPHER_CTX_ctrl(c.get(),EVP_CTRL_GCM_SET_IVLEN,static_cast<int>(iv.size()),nullptr)==1 &&
      EVP_DecryptInit_ex(c.get(),nullptr,nullptr,key_.data(),iv.data())==1;
    if(ok&&!aad.empty()) ok=EVP_DecryptUpdate(c.get(),nullptr,&len,aad.data(),static_cast<int>(aad.size()))==1;
    if(ok&&size) { ok=EVP_DecryptUpdate(c.get(),out.data(),&len,ct.data(),static_cast<int>(size))==1; written=len; }
    if(ok) ok=EVP_CIPHER_CTX_ctrl(c.get(),EVP_CTRL_GCM_SET_TAG,16,const_cast<Byte*>(ct.data()+size))==1;
    Byte emptyOutput{};
    if(ok) { auto* finalOut=out.empty()?&emptyOutput:out.data()+written; ok=EVP_DecryptFinal_ex(c.get(),finalOut,&len)==1; written+=len; }
    if(!ok) out.clear(); else out.resize(static_cast<std::size_t>(written)); return ok;
}
std::array<Byte,32> randomSessionKey(){ std::array<Byte,32> key{}; if(RAND_bytes(key.data(),static_cast<int>(key.size()))!=1) throw std::runtime_error("OpenSSL random generator failed"); return key; }
} // namespace s1lent
