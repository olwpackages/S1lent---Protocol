#pragma once
#include "types.hpp"
#include <chrono>
#include <span>

namespace s1lent {
class IpInterface {
public:
    virtual ~IpInterface() = default;
    virtual bool open(const std::wstring& adapterName, std::string* error = nullptr) = 0;
    virtual bool read(Bytes& packet, std::chrono::milliseconds timeout) = 0;
    virtual bool write(std::span<const Byte> packet, std::string* error = nullptr) = 0;
};

class WindowsTunInterface final : public IpInterface {
public:
    WindowsTunInterface();
    ~WindowsTunInterface() override;
    WindowsTunInterface(const WindowsTunInterface&) = delete;
    WindowsTunInterface& operator=(const WindowsTunInterface&) = delete;
    bool open(const std::wstring& adapterName, std::string* error = nullptr) override;
    bool read(Bytes& packet, std::chrono::milliseconds timeout) override;
    bool write(std::span<const Byte> packet, std::string* error = nullptr) override;
private:
    struct Functions;
    Functions* functions_{};
};
} // namespace s1lent
