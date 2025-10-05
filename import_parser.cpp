#include "import_parser.h"
#include "pe_parser.h"
#include <fstream>

// Structure in the PE file that describes one imported DLL
struct IMAGE_IMPORT_DESCRIPTOR_MIN {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDataStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

static bool readCStringAtRVA(std::ifstream& f, const PEParser& pe, uint32_t rva, std::string& out) {
    uint32_t off = 0;
    if (!pe.rvaToFileOffset(rva, off)) {
        return false;
    }
    
    f.seekg(off, std::ios::beg);
    if (!f) return false;
    
    out.clear();
    char ch;
    for (int i = 0; i < 512; ++i) {
        if (!f.get(ch)) break;
        if (ch == '\0') break;
        out.push_back(ch);
    }
    return !out.empty();
}

static uint32_t readU32(std::ifstream& f, uint32_t fileOff) {
    uint32_t v = 0;
    f.seekg(fileOff, std::ios::beg);
    f.read(reinterpret_cast<char*>(&v), sizeof(uint32_t));
    return v;
}

static uint64_t readU64(std::ifstream& f, uint32_t fileOff) {
    uint64_t v = 0;
    f.seekg(fileOff, std::ios::beg);
    f.read(reinterpret_cast<char*>(&v), sizeof(uint64_t));
    return v;
}

std::vector<ImportDLL> ImportParser::parse(const std::string& filepath, const PEParser& pe) {
    std::vector<ImportDLL> result;
    const auto& nt = pe.getNTHeader();

    if (nt.opt.importDirRVA == 0 || nt.opt.importDirSize == 0) return result;

    std::ifstream f(filepath, std::ios::binary);
    if (!f) return result;

    uint32_t dirStart = 0;
    if (!pe.rvaToFileOffset(nt.opt.importDirRVA, dirStart)) return result;
    
    uint32_t cursor = dirStart;

    while (true) {
        IMAGE_IMPORT_DESCRIPTOR_MIN d{};
        f.seekg(cursor, std::ios::beg);
        f.read(reinterpret_cast<char*>(&d), sizeof(d));
        if (!f || (d.OriginalFirstThunk == 0 && d.FirstThunk == 0 && d.Name == 0))
            break;

        ImportDLL dll{};
        if (!readCStringAtRVA(f, pe, d.Name, dll.dllname)) break;

        uint32_t thunkRVA = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
        if (thunkRVA == 0) { result.push_back(std::move(dll)); cursor += sizeof(d); continue; }

        uint32_t thunkOff = 0;
        if (!pe.rvaToFileOffset(thunkRVA, thunkOff)) {
            result.push_back(std::move(dll));
            cursor += sizeof(d);
            continue;
        }

        if (!pe.isPE32Plus()) {
            while (true) {
                uint32_t t = readU32(f, thunkOff);
                if (t == 0) break;

                ImportFunction fn{};
                if (t & 0x80000000u) {
                    fn.byOrdinal = true;
                    fn.ordinal = static_cast<uint16_t>(t & 0xFFFF);
                } else {
                    uint32_t ibnOff = 0;
                    if (pe.rvaToFileOffset(t, ibnOff)) {
                        f.seekg(ibnOff + 2, std::ios::beg);
                        std::string nm;
                        char c;
                        while (f.get(c) && c != '\0' && nm.size() < 512) nm.push_back(c);
                        fn.name = nm;
                    }
                }
                dll.functions.push_back(fn);
                thunkOff += sizeof(uint32_t);
            }
        } else {
            while (true) {
                uint64_t t = readU64(f, thunkOff);
                if (t == 0) break;

                ImportFunction fn{};
                if (t & 0x8000000000000000ULL) {
                    fn.byOrdinal = true;
                    fn.ordinal = static_cast<uint16_t>(t & 0xFFFF);
                } else {
                    uint32_t ibnRva = static_cast<uint32_t>(t & 0xFFFFFFFFu);
                    uint32_t ibnOff = 0;
                    if (pe.rvaToFileOffset(ibnRva, ibnOff)) {
                        f.seekg(ibnOff + 2, std::ios::beg);
                        std::string nm;
                        char c;
                        while (f.get(c) && c != '\0' && nm.size() < 512) nm.push_back(c);
                        fn.name = nm;
                    }
                }
                dll.functions.push_back(fn);
                thunkOff += sizeof(uint64_t);
            }
        }

        result.push_back(std::move(dll));
        cursor += sizeof(d);
    }

    return result;
}