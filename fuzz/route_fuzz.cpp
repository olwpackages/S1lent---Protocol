#include "s1lent/route.hpp"
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data,std::size_t size){
    if(size>4096)return 0;std::string input(reinterpret_cast<const char*>(data),size);(void)s1lent::loadRouteConfigText(input);return 0;
}
