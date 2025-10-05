#include "string_extractor.h"
#include <fstream>
#include <cctype>

std::vector<std::string> StringExtractor::extractASCII(const std::string& filepath, size_t minLength){
    std::ifstream file(filepath, std::ios::binary);
    std::vector<std::string> strings;
    if(!file){
        return strings;
    }

    std::string current;
    char c;
    while(file.get(c)) {
        if(std::isprint(static_cast<unsigned char>(c))){
            current += c;
        } else {
            if(current.length() >= minLength) {
                strings.push_back(current);
            }
            current.clear();
        }
    }

    return strings;
}