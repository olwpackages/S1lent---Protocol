#pragma once
#include "types.hpp"
#include <memory>
#include <span>

namespace s1lent {
class CryptoContext {
public:
    virtual ~CryptoContext() = default;
    virtual bool encrypt(std::span<const Byte> plaintext, std::span<const Byte> associatedData,
                         std::uint64_t packetNumber, Direction direction, Bytes& ciphertext) = 0;
    virtual bool decrypt(std::span<const Byte> ciphertext, std::span<const Byte> associatedData,
                         std::uint64_t packetNumber, Direction direction, Bytes& plaintext) = 0;
};

// AES-256-GCM from OpenSSL. Keys are injected by a secure session-establishment layer.
class Aes256GcmContext final : public CryptoContext {
public:
    explicit Aes256GcmContext(std::array<Byte, 32> key);
    ~Aes256GcmContext() override;
    bool encrypt(std::span<const Byte>, std::span<const Byte>, std::uint64_t, Direction, Bytes&) override;
    bool decrypt(std::span<const Byte>, std::span<const Byte>, std::uint64_t, Direction, Bytes&) override;
private:
    std::array<Byte, 32> key_{};
};
std::array<Byte, 32> randomSessionKey();
} // namespace s1lent
