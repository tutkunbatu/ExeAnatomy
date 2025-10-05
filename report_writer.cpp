#include "report_writer.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <regex>

using json = nlohmann::json;

static bool isSuspiciousAPI(const std::string& name) {
    static const std::unordered_set<std::string> bad = {
        "CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "WinExec",
        "WSAStartup", "connect", "GetKeyboardState", "CreateFile", "WriteFile",
        "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW"
    };
    return bad.count(name) > 0;
}

void ReportWriter::writeJSONReport(const std::string& filepath,
                                   int score,
                                   const std::vector<SectionHeader>& sections,
                                   const FileHashes& hashes,
                                   const std::vector<ImportDLL>& imports,
                                   const std::vector<std::string>& strings) {
    json j;
    j["file"] = filepath;
    j["risk_score"] = score;
    j["hashes"] = { {"md5", hashes.md5}, {"sha256", hashes.sha256} };

    j["sections"] = json::array();
    for (const auto& s : sections) {
        j["sections"].push_back({
            {"name", s.name},
            {"entropy", s.entropy},
            {"raw_size", s.sizeOfRawData}
        });
    }

    j["imports"] = json::array();
    for (const auto& dll : imports) {
        json jdll;
        jdll["dll"] = dll.dllname;
        jdll["functions"] = json::array();
        for (const auto& f : dll.functions) {
            jdll["functions"].push_back({
                {"name", f.name},
                {"by_ordinal", f.byOrdinal},
                {"ordinal", f.ordinal},
                {"suspicious", (!f.byOrdinal && !f.name.empty()) ? isSuspiciousAPI(f.name) : false}
            });
        }
        j["imports"].push_back(jdll);
    }

    std::ofstream out("report.json");
    out << j.dump(4);
}

void ReportWriter::writeHumanReport(const std::string& filepath,
    int score,
    const std::vector<SectionHeader>& sections,
    const FileHashes& hashes,
    const std::vector<ImportDLL>& imports,
    const std::vector<std::string>& strings) {
    std::cout << "File: " << filepath << "\n";
    std::cout << "Risk Score: " << score << "/100\n\n";

    std::cout << "Hashes:\n";
    std::cout << "  MD5:    " << hashes.md5 << "\n";
    std::cout << "  SHA256: " << hashes.sha256 << "\n\n";

    std::cout << "\nSection Entropy:\n";
    for (const auto& s : sections) {
        std::cout << "  [" << s.name << "] Entropy: " << s.entropy
            << "  RawSize: " << s.sizeOfRawData << "\n";
    }

    std::cout << "\nImport Summary:\n";
    if (imports.empty()) {
        std::cout << "  (none)\n";
    }
    else {
        std::cout << "  Total DLLs imported: " << imports.size() << "\n";

        // Count suspicious APIs
        int suspiciousCount = 0;
        std::vector<std::string> suspiciousAPIs;

        for (const auto& dll : imports) {
            for (const auto& f : dll.functions) {
                if (!f.byOrdinal && isSuspiciousAPI(f.name)) {
                    suspiciousCount++;
                    suspiciousAPIs.push_back(dll.dllname + "!" + f.name);
                }
            }
        }

        std::cout << "  Suspicious APIs found: " << suspiciousCount << "\n";

        if (suspiciousCount > 0) {
            std::cout << "\n  Flagged APIs:\n";
            for (const auto& dll : imports) {
                for (const auto& f : dll.functions) {
                    if (!f.byOrdinal && isSuspiciousAPI(f.name)) {
                        std::cout << "    - " << f.name << "\n";
                    }
                }
            }
        }
    }

    std::cout << "\nSuspicious Strings:\n";
std::regex urlPattern(R"(https?://[^\s]+)");
int count = 0;

for (size_t i = 0; i < strings.size(); ++i) {
    const std::string& str = strings[i];  // Explicit type
    if (std::regex_search(str, urlPattern)) {
        std::cout << "  - " << str << "\n";
        count++;
    }
}

if (count == 0) {
    std::cout << "  (none detected)\n";
}

    std::cout << "\nReport written to report.json\n";
}
