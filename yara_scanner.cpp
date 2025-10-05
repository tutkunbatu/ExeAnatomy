#include "yara_scanner.h"
#include <cstdlib>
#include <fstream>

YARAScanner::YARAScanner(const std::string& rulesFile) : rulesFile(rulesFile) {}

std::vector<std::string> YARAScanner::scan(const std::string& filepath) {
    std::vector<std::string> matches;
    std::string command = "yara -s \"" + rulesFile + "\" \"" + filepath + "\" > yara_output.txt";
    int result = system(command.c_str());
    (void)result;

    std::ifstream out("yara_output.txt");
    std::string line;
    while (std::getline(out, line)) {
        if (!line.empty()) matches.push_back(line);
    }
    return matches;
}