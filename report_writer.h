#ifndef REPORT_WRITER_H
#define REPORT_WRITER_H

#include <string>
#include <vector>
#include <unordered_set>
#include "pe_parser.h"
#include "import_parser.h"
#include "hash_utils.h"

class ReportWriter {
public:
    static void writeJSONReport(const std::string& filepath,
                                int score,
                                const std::vector<SectionHeader>& sections,
                                const FileHashes& hashes,
                                const std::vector<ImportDLL>& imports,
                                const std::vector<std::string>& strings);

    static void writeHumanReport(const std::string& filepath,
                                 int score,
                                 const std::vector<SectionHeader>& sections,
                                 const FileHashes& hashes,
                                 const std::vector<ImportDLL>& imports, 
                                 const std::vector<std::string>& strings);
};

#endif
