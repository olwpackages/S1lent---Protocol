#include "s1lent/node.hpp"

namespace s1lent {
ForwardingNode::ForwardingNode(Route r,std::size_t i):route_(std::move(r)),index_(i){}
bool ForwardingNode::start(const Endpoint& listen,std::string* error){if(index_>=route_.nodes.size()||route_.nodes[index_].endpoint.port==0)return false;return transport_.bind(listen,error);}
void ForwardingNode::run(const std::atomic_bool& stop){transport_.receiveLoop([this](const Bytes& b,const Endpoint& peer){(void)forwardDatagram(b,peer);return true;},stop);}
bool ForwardingNode::forwardDatagram(const Bytes& wire,const Endpoint& peer,std::string* error){
    auto packet=decodePacket(wire,error);if(!packet||packet->routeId!=route_.id||index_>=route_.nodes.size())return false;
    Endpoint next;
    if(packet->direction==Direction::outbound){
        if(packet->hop!=index_)return false;
        {std::lock_guard lock(peersMutex_);upstream_[packet->sessionId]=peer;}
        ++packet->hop;next=index_+1<route_.nodes.size()?route_.nodes[index_+1].endpoint:route_.destination;
    }else{
        if(packet->hop!=index_)return false;
        {std::lock_guard lock(peersMutex_);auto i=upstream_.find(packet->sessionId);if(i==upstream_.end())return false;next=i->second;}
        if(packet->hop>0)--packet->hop;
    }
    return transport_.sendTo(next,encodePacket(*packet),error);
}
} // namespace s1lent
