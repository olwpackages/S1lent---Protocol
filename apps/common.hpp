#pragma once
#include "s1lent/route.hpp"
#include <iostream>
#include <stdexcept>

inline std::array<s1lent::Byte,32> parseKey(const std::string& hex) {
    if(hex.size()!=64)throw std::invalid_argument("key must be 64 hexadecimal characters");
    std::array<s1lent::Byte,32> out{};
    auto digit=[](char c)->int{if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
    for(std::size_t i=0;i<out.size();++i){int a=digit(hex[2*i]),b=digit(hex[2*i+1]);if(a<0||b<0)throw std::invalid_argument("key is not hexadecimal");out[i]=static_cast<s1lent::Byte>((a<<4)|b);}return out;
}
inline s1lent::Endpoint endpoint(const std::string& host,const std::string& port){auto p=std::stoul(port);if(p>65535)throw std::invalid_argument("port out of range");return {host,static_cast<std::uint16_t>(p)};}
