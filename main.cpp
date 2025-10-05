#include <iostream>
#include <fstream>
#include "pe_parser.h"
#include "string_extractor.h"
#include "import_parser.h"
#include "hash_utils.h"
#include "risk_engine.h"
#include "report_writer.h"

int main(int argc, char* argv[]) {
    std::cout << R"(  
   _____             _                _                        
  | ____|_  _____   / \   _ __   __ _| |_ ___  _ __ ___  _   _ 
  |  _| \ \/ / _ \ / _ \ | '_ \ / _` | __/ _ \| '_ ` _ \| | | |
  | |___ >  <  __// ___ \| | | | (_| | || (_) | | | | | | |_| |
  |_____/_/\_\___/_/   \_\_| |_|\__,_|\__\___/|_| |_| |_|\__, |
                                                          |___/  
)" << "\n";

    std::cout << "  Static Malware Analyzer - PE Parser & Entropy Tool\n";
    std::cout << " ----------------------------------------------------\n";
    std::cout << "| A C++ project to parse PE headers, analyze sections,|\n";
    std::cout << "| extract strings, calculate entropy and assess risks.|\n";
    std::cout << "|                  made by tutkunbatu                 |\n";
    std::cout << " ----------------------------------------------------\n\n";
    
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <.exe file>\n\n";
        return 1;
    }
    
    std::string filepath = argv[1];
    
    std::cout << "Analyzing file: " << filepath << "\n\n";

    // Parse PE file
    std::cout << "[*] Parsing PE headers...\n";
    PEParser parser(filepath);
    if (!parser.parse()) {
        std::cerr << "[-] Failed to parse PE file\n";
        return 1;
    }
    std::cout << "[+] PE parsing successful\n";

    // Parse imports
    std::cout << "[*] Analyzing import table...\n";
    auto imports = ImportParser::parse(filepath, parser);
    std::cout << "[+] Found " << imports.size() << " imported DLLs\n";

    // Extract strings
    std::cout << "[*] Extracting strings...\n";
    auto strings = StringExtractor::extractASCII(filepath);
    std::cout << "[+] Extracted " << strings.size() << " strings\n";

    // Calculate hashes
    std::cout << "[*] Computing file hashes...\n";
    std::ifstream hashFile(filepath, std::ios::binary);
    std::vector<unsigned char> fileBytes(
        (std::istreambuf_iterator<char>(hashFile)),
        std::istreambuf_iterator<char>()
    );
    auto hashes = HashUtils::compute(fileBytes);
    std::cout << "[+] Hashes computed\n";

    // Risk assessment
    std::cout << "[*] Calculating risk score...\n";
    RiskEngine risk;
    int score = risk.calculateRiskScore(parser.getSections(), strings, imports);
    std::cout << "[+] Risk assessment complete\n\n";

    // Generate reports
    std::cout << "===== ANALYSIS RESULTS =====\n\n";
    ReportWriter::writeHumanReport(filepath, score, 
                                   parser.getSections(), hashes, imports, strings);

    ReportWriter::writeJSONReport(filepath, score,
                                  parser.getSections(), hashes, imports, strings);

    // Summary verdict
    std::cout << "\n=== VERDICT ===\n";
    if (score < 30) {
        std::cout << "Status: LIKELY CLEAN (Low Risk)\n";
    } else if (score < 60) {
        std::cout << "Status: SUSPICIOUS (Medium Risk) - Manual review recommended\n";
    } else {
        std::cout << "Status: LIKELY MALICIOUS (High Risk) - Quarantine recommended\n";
    }

    return 0;
}