#include "s1lent/crypto.hpp"
#include <chrono>
#include <iostream>

int main(){
    std::array<s1lent::Byte,32> key{};for(std::size_t i=0;i<key.size();++i)key[i]=static_cast<s1lent::Byte>(i);
    s1lent::Aes256GcmContext crypto(key);const std::array<s1lent::Byte,4> aad{1,2,3,4};
    constexpr std::size_t iterations=100000;
    for(const std::size_t size:{64,1200}){
        s1lent::Bytes plain(size,0x5a),cipher;std::uint64_t number=1;
        const auto begin=std::chrono::steady_clock::now();
        for(std::size_t i=0;i<iterations;++i){if(!crypto.encrypt(plain,aad,number++,s1lent::Direction::outbound,cipher))return 1;}
        const auto elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-begin).count();
        std::cout<<"AES-256-GCM encrypt payload="<<size<<" bytes iterations="<<iterations
                 <<" seconds="<<elapsed<<" packets_per_second="<<iterations/elapsed
                 <<" payload_MiB_per_second="<<(static_cast<double>(iterations*size)/(1024.0*1024.0))/elapsed<<'\n';
    }
}
