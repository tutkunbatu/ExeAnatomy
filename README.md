# ExeAnatomy - Static Malware Analyzer
A C++ tool for analyzing PE (Portable Executable) files to detect potential malware through static analysis.

## Features
- Parse PE headers (DOS, NT, Optional, Section headers)
- Calculate section entropy to detect packed/encrypted code
- Extract and analyze ASCII strings
- Parse import tables (DLLs and functions)
- Compute MD5 and SHA256 hashes
- Risk scoring based on suspicious APIs, high entropy, and URLs
- JSON and human-readable reports

## Requirements
- C++11 or later
- OpenSSL
- nlohmann/json
