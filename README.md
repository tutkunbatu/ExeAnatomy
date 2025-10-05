# ExeAnatomy - Static Malware Analyzer
A C++ tool for analyzing PE (Portable Executable) files to detect potential malware through static analysis.

<img width="544" height="220" alt="Banner" src="https://github.com/user-attachments/assets/35e3162c-f0cc-4e68-a827-6789ea28bff7" />

## Features
- Parse PE headers (DOS, NT, Optional, Section headers)
- Calculate section entropy to detect packed/encrypted code
- Extract and analyze ASCII strings
- Parse import tables (DLLs and functions)
- Compute MD5 and SHA256 hashes
- Risk scoring based on suspicious APIs, high entropy and URLs
- JSON and human-readable reports

## Requirements
- C++11 or later
- OpenSSL
- nlohmann/json

## Building
### Linux
git clone https://github.com/tutkunbatu/ExeAnatomy.git
cd ExeAnatomy
g++ -std=c++11 src/*.cpp -o analyzer -lssl -lcrypto

### Windows (MSYS2 MinGW)1
```bash
git clone https://github.com/tutkunbatu/ExeAnatomy.git
cd ExeAnatomy
g++ -std=c++11 src/*.cpp -o analyzer.exe -lssl -lcrypto
```
## Usage
```bash
./exeanatomy <file.exe>
```


