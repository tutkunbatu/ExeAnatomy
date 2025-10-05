#ifndef RISK_ENGINE_H
#define RISK_ENGINE_H

#include <vector>
#include <string>
#include "pe_parser.h"
#include "import_parser.h"

class RiskEngine {
public:
    int analyzeEntropy(const std::vector<SectionHeader>& sections);
    int analyzeSuspiciousStrings(const std::vector<std::string>& strings);
    int analyzeImports(const std::vector<ImportDLL>& imports);

    int calculateRiskScore(const std::vector<SectionHeader>& sections,
                           const std::vector<std::string>& strings,
                           const std::vector<ImportDLL>& imports);
};

#endif