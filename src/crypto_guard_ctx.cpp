#include "crypto_guard_ctx.h"

#include <memory>
#include <openssl/evp.h>

#include <array>
#include <iomanip>
#include <iostream>
#include <istream>
#include <sstream>
#include <vector>

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

namespace CryptoGuard {
class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    static void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    static void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    static std::string CalculateChecksum(std::iostream &inStream);

private:
    static AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
    static void CipherImp(std::iostream &inStream, std::iostream &outStream, const AesCipherParams &params);
};

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;
    CipherImp(inStream, outStream, params);
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0;
    CipherImp(inStream, outStream, params);
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    if (!inStream) {
        throw(std::runtime_error("Error opening input file"));
    }

    std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *mdctx) { EVP_MD_CTX_free(mdctx); })> mdctx{EVP_MD_CTX_new()};
    if (!mdctx) {
        throw(std::runtime_error("Message digest create failed.\n"));
    }
    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    if (md == NULL) {
        throw(std::runtime_error("Unknown message digest\n"));
    }

    if (!EVP_DigestInit_ex2(mdctx.get(), md, NULL)) {
        throw(std::runtime_error("Message digest initialization failed.\n"));
    }

    std::vector<unsigned char> inBuf(16);

    inStream.exceptions(std::ios_base::badbit);

    for (inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size()); !inStream.eof();
         inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size())) {
        if (!EVP_DigestUpdate(mdctx.get(), inBuf.data(), inBuf.size())) {
            throw(std::runtime_error("Message digest update failed.\n"));
        }
    }

    std::vector<unsigned char> md_value(EVP_MAX_MD_SIZE);
    uint32_t md_len;

    if (!EVP_DigestFinal_ex(mdctx.get(), md_value.data(), &md_len)) {
        throw(std::runtime_error("Message digest finalization failed.\n"));
    } 

    std::ostringstream result;
    for (auto it = md_value.begin(); it != std::next(md_value.begin(), md_len); ++it) {
        result << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
    }

    return result.str();
}

AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password\n"};
    }

    return params;
}

void CryptoGuardCtx::Impl::CipherImp(std::iostream &inStream, std::iostream &outStream, const AesCipherParams &params) {
    if (!inStream) {
        throw(std::runtime_error("Error opening input file\n"));
    }
    if (!outStream) {
        throw(std::runtime_error("Error opening output file\n"));
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })> ctx{
        EVP_CIPHER_CTX_new()};

    // Инициализируем cipher
    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
        throw(std::runtime_error("Error initializing cipher\n"));
    }

    std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(16);
    int outLen;

    inStream.exceptions(std::ios_base::badbit);                            // may throw
    outStream.exceptions(std::ios_base::badbit | std::ios_base::failbit);  // may throw

    // Обрабатываем первые N символов
    for (inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size()); !inStream.eof();
         inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size())) {
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16))) {
            throw(std::runtime_error("Error update cipher.\n"));
        }
        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
    }

    // Обрабатываем оставшиеся символы
    std::streamsize bytes_read = inStream.gcount();
    if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytes_read))) {
        throw(std::runtime_error("Error update cipher.\n"));
    }
    outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);

    // Заканчиваем работу с cipher
    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throw(std::runtime_error("Error final cipher.\n"));
    }
    outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
}

//===================================================
//=================CryptoGuardCtx====================
//===================================================
CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() {}

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
