#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <string>
#include <vector>

struct FileHashes {
    std::string md5;
    std::string sha256;
};

class HashUtils {
public:
    static FileHashes compute(const std::vector<unsigned char>& bytes);
};

#endif