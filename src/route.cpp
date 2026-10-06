#include "s1lent/route.hpp"
#include <algorithm>
#include <fstream>
#include <set>
#include <sstream>

namespace s1lent {
bool StaticRouteEngine::validateRoute(const Route& r) const {
    if(r.id==0||r.version!=1||r.nodes.empty()||r.nodes.size()>8||r.destination.host.empty()||r.destination.port==0||r.timeoutMs==0)return false;
    std::set<std::string> ids;
    for(const auto& n:r.nodes) if(n.id.empty()||n.endpoint.host.empty()||n.endpoint.port==0||n.transport!="udp"||!ids.insert(n.id).second)return false;
    return true;
}
bool StaticRouteEngine::addRoute(const Route& r){ if(!validateRoute(r))return false; std::unique_lock lock(mutex_); routes_[r.id]=r; return true; }
bool StaticRouteEngine::removeRoute(RouteId id){ std::unique_lock lock(mutex_); return routes_.erase(id)>0; }
std::optional<Route> StaticRouteEngine::find(RouteId id)const{std::shared_lock lock(mutex_);auto i=routes_.find(id);return i==routes_.end()?std::nullopt:std::optional<Route>(i->second);}
std::optional<Route> StaticRouteEngine::selectRoute(const Destination& d)const{
    std::shared_lock lock(mutex_);const Route* best=nullptr;
    for(const auto& [id,r]:routes_){(void)id;if((r.destination.host==d.host||r.destination.host=="*")&&(r.destination.port==d.port||r.destination.port==0)&&(!best||r.priority>best->priority))best=&r;}
    return best?std::optional<Route>(*best):std::nullopt;
}
std::optional<Route> loadRouteConfig(const std::string& path,std::string* error){
    std::ifstream f(path); if(!f){if(error)*error="cannot open route config";return std::nullopt;}
    std::ostringstream contents;contents<<f.rdbuf();return loadRouteConfigText(contents.str(),error);
}
std::optional<Route> loadRouteConfigText(const std::string& text,std::string* error){
    Route r; std::string line; std::istringstream f(text); bool inNodes=false; std::size_t lineNo=0;
    while(std::getline(f,line)){++lineNo;auto first=line.find_first_not_of(" \t\r");if(first==std::string::npos||line[first]=='#')continue;line=line.substr(first);
        if(line=="nodes:"){inNodes=true;continue;}
        if(inNodes&&line.rfind("- ",0)==0){auto spec=line.substr(2);auto at=spec.find('@');auto colon=spec.rfind(':');if(at==std::string::npos||colon==std::string::npos||colon<=at+1){if(error)*error="invalid node at line "+std::to_string(lineNo);return std::nullopt;}
            try{auto p=static_cast<unsigned long>(std::stoul(spec.substr(colon+1)));if(p==0||p>65535)throw std::out_of_range("port");r.nodes.push_back({spec.substr(0,at),{spec.substr(at+1,colon-at-1),static_cast<std::uint16_t>(p)},"udp"});}catch(...){if(error)*error="invalid node port at line "+std::to_string(lineNo);return std::nullopt;}continue;}
        inNodes=false;auto colon=line.find(':');if(colon==std::string::npos)continue;auto key=line.substr(0,colon);auto value=line.substr(colon+1);auto v=value.find_first_not_of(" \t");value=v==std::string::npos?"":value.substr(v);
        try{if(key=="route_id")r.id=static_cast<RouteId>(std::stoul(value));else if(key=="priority")r.priority=std::stoi(value);else if(key=="timeout_ms")r.timeoutMs=static_cast<std::uint32_t>(std::stoul(value));else if(key=="destination"){auto c=value.rfind(':');if(c==std::string::npos)throw std::invalid_argument("endpoint");auto p=std::stoul(value.substr(c+1));if(p==0||p>65535)throw std::out_of_range("port");r.destination={value.substr(0,c),static_cast<std::uint16_t>(p)};}}
        catch(...){if(error)*error="invalid value at line "+std::to_string(lineNo);return std::nullopt;}
    }
    StaticRouteEngine validator;if(!validator.validateRoute(r)){if(error)*error="route failed validation";return std::nullopt;}return r;
}
} // namespace s1lent
