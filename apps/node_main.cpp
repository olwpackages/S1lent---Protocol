#include "common.hpp"
#include "s1lent/node.hpp"
#include <iostream>

int main(int argc,char** argv){
    if(argc!=6){std::cerr<<"usage: s1lent-node <route.conf> <node-index> <bind-host> <bind-port> <node-id>\n";return 2;}
    std::string error;auto route=s1lent::loadRouteConfig(argv[1],&error);if(!route){std::cerr<<error<<'\n';return 1;}
    const auto index=static_cast<std::size_t>(std::stoul(argv[2]));if(index>=route->nodes.size()||route->nodes[index].id!=argv[5]){std::cerr<<"node index/id does not match route\n";return 1;}
    s1lent::ForwardingNode node(*route,index);if(!node.start(endpoint(argv[3],argv[4]),&error)){std::cerr<<error<<'\n';return 1;}
    std::cout<<"S1lent experimental forwarding node "<<argv[5]<<" listening\n";
    std::atomic_bool stop{false};node.run(stop);return 0;
}
