#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <string>
#include <vector>
#include <fstream>
#include <cstdint>

struct DOSHeader {
    uint16_t e_magic;
    uint32_t e_lfanew; // Long file address to new executable, tells where the real PE header starts
};

struct COFFHeader {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

struct OptionalHeader {
    uint16_t magic;
    uint32_t addressOfEntryPoint; // Where the program starts executing
    uint64_t imageBase; // Where the program wants to be loaded in memory
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint16_t subsystem;
    uint16_t dllCharacteristics;
    uint32_t importDirRVA; // Points to the import directory table
    uint32_t importDirSize;
};

struct NTHeader {
    uint32_t signature;
    COFFHeader coff;
    OptionalHeader opt;
};

struct SectionHeader {
    std::string name;
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t characteristics; // Permissions
    double entropy;
};

class PEParser {
public:
    PEParser(const std::string& filepath);
    bool parse();
    const std::vector<SectionHeader>& getSections() const;
    const NTHeader& getNTHeader() const;

    bool rvaToFileOffset(uint32_t rva, uint32_t& offset) const;
    bool isPE32Plus() const { return ntHeader.opt.magic == 0x20B; }
    uint32_t entryPointRVA() const { return ntHeader.opt.addressOfEntryPoint; }

private:
    std::string filepath;
    std::ifstream file;
    size_t file_size_;
    DOSHeader dosHeader;
    NTHeader ntHeader;
    std::vector<SectionHeader> sections;

    bool readDOSHeader();
    bool readNTHeader();
    bool readOptionalHeader();
    bool readSectionHeaders();
    double calculateEntropy(const std::vector<uint8_t>& data);
};

#endif