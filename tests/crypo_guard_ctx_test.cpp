#include "../include/crypto_guard_ctx.h"

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>

TEST(GryptoGuardCtx, Encrypt) {
    std::stringstream i_str{"01234567890123456789012345678901234567890123456789012345678901234567890123456789"};
    std::stringstream o_str;
    CryptoGuard::CryptoGuardCtx crypto_ctx;
    std::string pass{"12345"};
    crypto_ctx.EncryptFile(i_str, o_str, pass);

    std::string result{"v\x17"
                       "c\xBD#\x6\b\xB2X||\xAE"
                       "3\xAC-\xFAW\x16\xDF\x83\xCA\xDD\xB0H\xB2\xDF%\x5#\xA5"
                       "2\x12\x8F"
                       "C\v\xAC\x88\x8D"
                       "d\x80"
                       "d\xAC\x5/JnA\r,@n\xC0O\xB1\xA1\xB1]Y\xF2"
                       "d*\x1A"
                       "E\xB8Xv\x89\xD9Y\x87o\xD9g\x1E&\xC1>\xCF.\xBE\xC8\x97'\xDB\xA1"
                       "C0\xB1"
                       "a\xF7\xB3\x97\xEEV\xA8\x1"};
    ASSERT_EQ(o_str.str(), result);
}

TEST(GryptoGuardCtx, Decrypt) {
    std::stringstream i_str{"v\x17"
                            "c\xBD#\x6\b\xB2X||\xAE"
                            "3\xAC-\xFAW\x16\xDF\x83\xCA\xDD\xB0H\xB2\xDF%\x5#\xA5"
                            "2\x12\x8F"
                            "C\v\xAC\x88\x8D"
                            "d\x80"
                            "d\xAC\x5/JnA\r,@n\xC0O\xB1\xA1\xB1]Y\xF2"
                            "d*\x1A"
                            "E\xB8Xv\x89\xD9Y\x87o\xD9g\x1E&\xC1>\xCF.\xBE\xC8\x97'\xDB\xA1"
                            "C0\xB1"
                            "a\xF7\xB3\x97\xEEV\xA8\x1"};
    std::stringstream o_str;
    CryptoGuard::CryptoGuardCtx crypto_ctx;
    std::string pass{"12345"};
    crypto_ctx.DecryptFile(i_str, o_str, pass);

    std::string result{"01234567890123456789012345678901234567890123456789012345678901234567890123456789"};
    ASSERT_EQ(o_str.str(), result);
}

TEST(GryptoGuardCtx, Checksum) {
    std::stringstream i_str{"01234567890123456789012345678901234567890123456789012345678901234567890123456789"};
    CryptoGuard::CryptoGuardCtx crypto_ctx;
    std::string result = crypto_ctx.CalculateChecksum(i_str);
    ASSERT_EQ("af1909413b96cbb29927b3a67f3a8879c801a37be383e5f9b31df5fa8d10fa2b", result);
}

TEST(GryptoGuardCtx, ChecksumAfterEncDec) {
    std::stringstream i_str{"01234567890123456789012345678901234567890123456789012345678901234567890123456789"};
    std::stringstream o_str;
    CryptoGuard::CryptoGuardCtx crypto_ctx;
    std::string pass{"12345"};
    crypto_ctx.EncryptFile(i_str, o_str, pass);
    i_str.clear();
    i_str.str("");
    o_str.clear();
    o_str.seekg(0);
    crypto_ctx.DecryptFile(o_str, i_str, pass);
    i_str.clear();
    i_str.seekg(0);
    std::string result = crypto_ctx.CalculateChecksum(i_str);
    ASSERT_EQ("af1909413b96cbb29927b3a67f3a8879c801a37be383e5f9b31df5fa8d10fa2b", result);
}

TEST(GryptoGuardCtx, ThrowsFileNotExist) {
    CryptoGuard::CryptoGuardCtx crypto_ctx;
    std::fstream i_file{"a", std::ios_base::in};
    std::fstream o_file{"b", std::ios_base::out | std::ios_base::binary};
    std::string pass{"12345"};

    EXPECT_THROW(crypto_ctx.EncryptFile(i_file, o_file, pass), std::runtime_error);
}