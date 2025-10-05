#ifndef STRING_EXTRACTOR_H
#define STRING_EXTRACTOR_H

#include <vector>
#include <string>

class StringExtractor {
public:
    static std::vector<std::string> extractASCII(const std::string& filepath, size_t minLength = 4);
};

#endif