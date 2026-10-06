#include "s1lent/packet.hpp"
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data,std::size_t size){
    if(size>2048)return 0;s1lent::Bytes input(data,data+size);(void)s1lent::decodePacket(input);return 0;
}
