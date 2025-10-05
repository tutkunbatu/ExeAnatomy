#ifndef YARA_SCANNER_H
#define YARA_SCANNER_H

#include <string>
#include <vector>

class YARAScanner {
public:
    YARAScanner(const std::string& ruleFile);
    std::vector<std::string> scan(const std::string& filepath);

private:
    std::string rulesFile;
};

#endif