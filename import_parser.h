#ifndef IMPORT_PARSER_H
#define IMPORT_PARSER_H

#include <string>
#include <vector>
#include <cstdint>

class PEParser;

struct ImportFunction {
    std::string name;
    uint16_t ordinal = 0;
    bool byOrdinal = false; // Is this imported by ordinal (true) or name (false)
};

struct ImportDLL {
    std::string dllname;
    std::vector<ImportFunction> functions;
};

class ImportParser {
public:
    static std::vector<ImportDLL> parse(const std::string& filepath, const PEParser& pe);
};

#endif