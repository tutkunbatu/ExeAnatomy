#include "risk_engine.h"
#include <algorithm>
#include <regex>
#include <unordered_set>

int RiskEngine::analyzeEntropy(const std::vector<SectionHeader>& sections) {
    int score = 0;
    for (const auto& section : sections) {
        if (section.entropy >= 7.5) score += 10; // high entropy sections (may be packed)
    }
    return std::min(score, 30);
}

int RiskEngine::analyzeSuspiciousStrings(const std::vector<std::string>& strings) {
    std::regex urlPattern(R"(https?://[^\s]+)"); // Regex to find urls
    int score = 0;
    for (const auto& str : strings) {
        if (std::regex_search(str, urlPattern)) { // Does this string contain a url?
            score += 5;
            if (score >= 20) break;
        }
    }
    return std::min(score, 20);
}

int RiskEngine::analyzeImports(const std::vector<ImportDLL>& imports) {
    static const std::unordered_set<std::string> suspiciousAPIs = {
    
    // Process Injection and memory Manipulation
    "CreateRemoteThread", // Creates thread in another process 
    "VirtualAlloc", // Allocates memory (may be shellcode)
    "VirtualAllocEx", // Allocates memory in remote process
    "WriteProcessMemory", // Writes to another process's memory space
    
    // Dynamic Code Loading
    "LoadLibraryA", // Loads DLL at runtime (ASCII)
    "LoadLibraryW", // Loads DLL at runtime (Unicode)
    "GetProcAddress", // Resolves function addresses dynamically
    
    // Process Execution
    "WinExec", // Executes programs 
    
    // Network Communication
    "WSAStartup", // Initializes Windows Sockets API
    "connect", // Establishes network connections
    
    // Keylogging and input Monitoring
    "GetAsyncKeyState", // Checks keyboard key states (keylogger indicator)
    "GetKeyboardState", // Retrieves entire keyboard state array
    
    // Registry Manipulation 
    "RegOpenKeyExA", // Opens registry key for modification (ASCII)
    "RegOpenKeyExW", // Opens registry key for modification (Unicode)
    "RegSetValueExA", // Modifies registry values (ASCII)
    "RegSetValueExW" // Modifies registry values (Unicode)
};
    int score = 0;
    for (const auto& dll : imports) {
        for (const auto& f : dll.functions) {
            if (!f.byOrdinal && !f.name.empty() && suspiciousAPIs.count(f.name)) {
                score += 10;
                if (score >= 40) return 40; // cap
            }
        }
    }
    return std::min(score, 40);
}

int RiskEngine::calculateRiskScore(const std::vector<SectionHeader>& sections,
                                   const std::vector<std::string>& strings,
                                   const std::vector<ImportDLL>& imports) {
    int score = 0;
    score += analyzeImports(imports);            // 0-40
    score += analyzeEntropy(sections);           // 0-30
    score += analyzeSuspiciousStrings(strings);  // 0-30

    // Normalize to 0–100
    double normalized = (static_cast<double>(score) / 120.0) * 100.0;
    return static_cast<int>(normalized);
}
