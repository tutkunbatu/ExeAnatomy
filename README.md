<img width="966" height="709" alt="tsk1" src="https://github.com/user-attachments/assets/5aa146e6-6a33-435b-9b45-f15f40397ce7" /><img width="590" height="678" alt="wn1" src="https://github.com/user-attachments/assets/17fe9a22-d7b3-46f7-83b9-38f6c142eeec" /># ExeAnatomy - Static Malware Analyzer
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
```bash
git clone https://github.com/tutkunbatu/ExeAnatomy.git
cd ExeAnatomy
g++ -std=c++11 src/*.cpp -o analyzer -lssl -lcrypto
```

### Windows (MSYS2 MinGW)
```bash
git clone https://github.com/tutkunbatu/ExeAnatomy.git
cd ExeAnatomy
g++ -std=c++11 src/*.cpp -o analyzer.exe -lssl -lcrypto
```
## Usage
```bash
./exeanatomy <file.exe>
```

## Examples

WannaCry Malware Test
<img width="590" height="678" alt="wn1" src="https://github.com/user-attachments/assets/0f904dd9-fdef-46a1-bf0f-a6ee6158dd39" />
<img width="619" height="627" alt="wn2" src="https://github.com/user-attachments/assets/96d62a1f-22f2-4fa3-
bd49-597523d9cc27" />

Task Manager Test
<img width="966" height="709" alt="tsk1" src="https://github.com/user-attachments/assets/20dcde5f-af23-42c3-8f1c-8991db8003fa" />
<img width="913" height="439" alt="tsk2" src="https://github.com/user-attachments/assets/0d52aac1-3c27-4689-96b5-d341aedb6bf1" />







