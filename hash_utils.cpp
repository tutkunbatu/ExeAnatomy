#include "hash_utils.h"
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

static std::string toHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    return oss.str();
}

FileHashes HashUtils::compute(const std::vector<unsigned char>& bytes) {
    FileHashes out;

    // MD5 using EVP API
    unsigned char md5sum[16];
    EVP_MD_CTX* md5ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md5ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(md5ctx, bytes.data(), bytes.size());
    EVP_DigestFinal_ex(md5ctx, md5sum, nullptr);
    EVP_MD_CTX_free(md5ctx);
    out.md5 = toHex(md5sum, 16);

    // SHA256 using EVP API
    unsigned char sha[32];
    EVP_MD_CTX* shactx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(shactx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(shactx, bytes.data(), bytes.size());
    EVP_DigestFinal_ex(shactx, sha, nullptr);
    EVP_MD_CTX_free(shactx);
    out.sha256 = toHex(sha, 32);

    return out;
}