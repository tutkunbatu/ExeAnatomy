#include "pe_parser.h"
#include <iostream>
#include <cmath>
#include <cstring>
#include <algorithm>

PEParser::PEParser(const std::string& filepath) : filepath(filepath), file_size_(0) {}

bool PEParser::parse() {
    file.open(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file.\n";
        return false;
    }

    // Get file size
    file.seekg(0, std::ios::end);
    file_size_ = file.tellg();
    file.seekg(0, std::ios::beg);

    // Bounds checking
    if (file_size_ < 64) {
        std::cerr << "Error: File too small to be PE\n";
        return false;
    }

    if (file_size_ > 100 * 1024 * 1024) {
        std::cerr << "Error: File too large (>100MB)\n";
        return false;
    }

    return readDOSHeader() && readNTHeader() && readSectionHeaders();
}

bool PEParser::readDOSHeader() {
    if (file_size_ < sizeof(DOSHeader)) return false;

    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(&dosHeader.e_magic), sizeof(uint16_t));
    
    if (dosHeader.e_magic != 0x5A4D) {
        std::cerr << "Error: Invalid DOS signature\n";
        return false;
    }

    file.seekg(60, std::ios::beg);
    file.read(reinterpret_cast<char*>(&dosHeader.e_lfanew), sizeof(uint32_t));

    // Validate e_lfanew
    if (dosHeader.e_lfanew >= file_size_ || dosHeader.e_lfanew < 64) {
        std::cerr << "Error: Invalid e_lfanew offset\n";
        return false;
    }

    return true;
}

bool PEParser::readNTHeader() {
    if (dosHeader.e_lfanew + 24 > file_size_) return false;

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    file.read(reinterpret_cast<char*>(&ntHeader.signature), sizeof(uint32_t));

    if (ntHeader.signature != 0x00004550) {
        std::cerr << "Error: Invalid PE signature\n";
        return false;
    }

    // Read COFF header (20 bytes)
    file.read(reinterpret_cast<char*>(&ntHeader.coff.machine), sizeof(uint16_t));
    file.read(reinterpret_cast<char*>(&ntHeader.coff.numberOfSections), sizeof(uint16_t));
    file.read(reinterpret_cast<char*>(&ntHeader.coff.timeDateStamp), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&ntHeader.coff.pointerToSymbolTable), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&ntHeader.coff.numberOfSymbols), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&ntHeader.coff.sizeOfOptionalHeader), sizeof(uint16_t));
    file.read(reinterpret_cast<char*>(&ntHeader.coff.characteristics), sizeof(uint16_t));

    // Validate optional header size
    if (ntHeader.coff.sizeOfOptionalHeader == 0) {
        std::cerr << "Error: No optional header\n";
        return false;
    }

    return readOptionalHeader();
}

bool PEParser::readOptionalHeader() {
    std::streampos optStart = file.tellg();

    file.read(reinterpret_cast<char*>(&ntHeader.opt.magic), sizeof(uint16_t));

    bool is64 = (ntHeader.opt.magic == 0x20B);
    if (!is64 && ntHeader.opt.magic != 0x10B) {
        std::cerr << "Error: Invalid optional header magic\n";
        return false;
    }

    // For PE32+, the data directories are at offset 112 bytes from the start of optional header
    // For PE32, they're at offset 96 bytes
    // But we need to position to the NumberOfRvaAndSizes field first

    if (is64) {
        // PE32+ (64-bit)
        file.seekg(static_cast<size_t>(optStart) + 108, std::ios::beg);
    }
    else {
        // PE32 (32-bit)  
        file.seekg(static_cast<size_t>(optStart) + 92, std::ios::beg);
    }

    uint32_t numDirs;
    file.read(reinterpret_cast<char*>(&numDirs), sizeof(uint32_t));

    if (numDirs > 1) {
        file.ignore(8); // Skip export directory (index 0)
        file.read(reinterpret_cast<char*>(&ntHeader.opt.importDirRVA), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&ntHeader.opt.importDirSize), sizeof(uint32_t));
    }

    return true;
}

bool PEParser::readSectionHeaders() {
    // Calculate section table position
    uint32_t sectionTableOffset = dosHeader.e_lfanew + 4 + 20 + ntHeader.coff.sizeOfOptionalHeader;

    // Position to section table explicitly
    file.seekg(sectionTableOffset, std::ios::beg);

    for (uint16_t i = 0; i < ntHeader.coff.numberOfSections; ++i) {
        SectionHeader sh;
        char name[8] = { 0 };

        file.read(name, 8);
        if (!file) {
            std::cerr << "Error reading section " << i << "\n";
            break;
        }

        sh.name = std::string(name, strnlen(name, 8));

        file.read(reinterpret_cast<char*>(&sh.virtualSize), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&sh.virtualAddress), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&sh.sizeOfRawData), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&sh.pointerToRawData), sizeof(uint32_t));
        file.ignore(12);
        file.read(reinterpret_cast<char*>(&sh.characteristics), sizeof(uint32_t));

        if (sh.sizeOfRawData > 0 && sh.pointerToRawData > 0 &&
            sh.pointerToRawData + sh.sizeOfRawData <= file_size_) {

            std::streampos savedPos = file.tellg();

            std::vector<uint8_t> data(sh.sizeOfRawData);
            file.seekg(sh.pointerToRawData, std::ios::beg);
            file.read(reinterpret_cast<char*>(data.data()), sh.sizeOfRawData);
            sh.entropy = calculateEntropy(data);

            file.seekg(savedPos, std::ios::beg);
        }
        else {
            sh.entropy = 0.0;
        }

        sections.push_back(sh);
    }

    return true;
}

double PEParser::calculateEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    
    std::vector<int> freq(256, 0);
    for (uint8_t byte : data) freq[byte]++;
    
    double entropy = 0.0;
    for (int count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / data.size();
        entropy -= p * std::log2(p);
    }
    return entropy;
}

bool PEParser::rvaToFileOffset(uint32_t rva, uint32_t& offset) const {
    for (const auto& s : sections) {
        uint32_t sectionStart = s.virtualAddress;
        uint32_t sectionSize = std::max(s.virtualSize, s.sizeOfRawData);
        
        if (rva >= sectionStart && rva < sectionStart + sectionSize) {
            uint32_t delta = rva - sectionStart;
            if (delta >= s.sizeOfRawData) return false;
            offset = s.pointerToRawData + delta;
            return true;
        }
    }
    return false;
}

const std::vector<SectionHeader>& PEParser::getSections() const { return sections; }
const NTHeader& PEParser::getNTHeader() const { return ntHeader; }