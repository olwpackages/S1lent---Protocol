#pragma once
#include "types.hpp"
#include <map>
#include <mutex>
#include <optional>
#include <shared_mutex>

namespace s1lent {
class RouteEngine {
public:
    virtual ~RouteEngine() = default;
    virtual std::optional<Route> selectRoute(const Destination& destination) const = 0;
    virtual std::optional<Route> find(RouteId id) const = 0;
    virtual bool addRoute(const Route&) = 0;
    virtual bool removeRoute(RouteId) = 0;
    virtual bool validateRoute(const Route&) const = 0;
};
class StaticRouteEngine final : public RouteEngine {
public:
    std::optional<Route> selectRoute(const Destination&) const override;
    bool addRoute(const Route&) override;
    bool removeRoute(RouteId) override;
    bool validateRoute(const Route&) const override;
    std::optional<Route> find(RouteId) const override;
private:
    mutable std::shared_mutex mutex_;
    std::map<RouteId, Route> routes_;
};
std::optional<Route> loadRouteConfig(const std::string& path, std::string* error = nullptr);
std::optional<Route> loadRouteConfigText(const std::string& text, std::string* error = nullptr);
} // namespace s1lent
