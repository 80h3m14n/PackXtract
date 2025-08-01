# PackXtract

**"packer, crypter, or polymorphic engine**

A cutting-edge Python obfuscation tool designed to protect intellectual property by making reverse engineering extremely difficult. It combines multiple layers of security:

- **AES-256 Encryption** with CBC mode
- **Abstract Syntax Tree (AST)** manipulation
- **Anti-Debugging** techniques
- **Polymorphic Code Generation**
- **Zlib Compression** + **Marshal Serialization**

Perfect for protecting sensitive algorithms, API keys, and proprietary business logic.

**Packing scheme**— base85 → AES-CBC with the hardcoded key/IV → zlib

---

### ✨ Feature

| Feature                                    | Found? | Notes                                                                                                                        |
| ------------------------------------------ | ------ | ---------------------------------------------------------------------------------------------------------------------------- |
| **Military-Grade Encryption**              | ✅     | Uses **AES-256-CBC** for encryption.                                                                                         |
| **AES-256-CBC with per-build random keys** | ✅     | Generates a new **32-byte key** (`self.aes_key = os.urandom(32)`) and **16-byte IV** (`self.iv = os.urandom(16)`) per build. |
| **AST-Level Transformations**              | ✅     | Implements **Variable Renaming, Control Flow Flattening, and String Encryption** using `ast.NodeTransformer`.                |
| **Variable Renaming**                      | ✅     | Uses a hashing method (`shake_128`) to obfuscate variable names.                                                             |
| **Control Flow Flattening**                | ✅     | Implements state-based execution in `ControlFlowFlattener`.                                                                  |
| **String Encryption**                      | ✅     | Encrypts string literals with AES before execution.                                                                          |
| **Anti-Analysis Protections**              | ✅     | Includes **Debugger Detection, Memory Bombardment, and Environment Checks**.                                                 |
| **Debugger Detection**                     | ✅     | `_anti_debug()` exits if a debugger is detected (`sys.gettrace()` or `IsDebuggerPresent`).                                   |
| **Memory Bombardment**                     | ❌     | No evidence of excessive memory usage or process exhaustion techniques.                                                      |
| **Environment Checks**                     | ✅     | Uses OS-based debugger detection.                                                                                            |
| **Self-Destruct Mechanism**                | ✅     | Implements **Tamper detection with SHA-3 integrity checks** (used in `_decrypt_str` with exception handling).                |
| **Stealth Operation**                      | ✅     | Uses **silent failure modes** (returns empty string if decryption fails) and **exception handling**.                         |
| **Cross-Platform**                         | ✅     | Designed for **Windows, Linux, and macOS** using standard Python and PyCryptodome.                                           |

### ❌ Missing or Partially Implemented Features:

1. **Memory Bombardment** → No aggressive memory-based anti-debugging measures.
2. **More Robust Self-Destruct** → While `_anti_debug()` exits on detection, a **secure self-erasing mechanism** isn't implemented.

### ❓ Upcoming Feature:

**memory bombardment** and a more **secure self-destruct mechanism** would enhance protection.
**Add a module that Works only on the original machine & ask for password.**

---

## 📖 Installation

```bash
git clone https://github.com/80h3m14n/PackXtract.git
cd PackXtract
pip install -r requirements.txt
```

# 🔥 Usage

# PackXtract Unified CLI

The `main.py` script provides a unified command-line interface for all packing, obfuscation, unpacking, and deobfuscation operations.

## Usage

```bash
python main.py <command> [options]
```

## Commands

### 1. Pack/Obfuscate (`pack`)

Pack and obfuscate Python files or binary executables with AES-256 encryption.

```bash
# Pack a Python file
python main.py pack script.py -o packed_script.py

# Pack a binary executable
python main.py pack binary.exe -o packed_binary.py

# Pack with custom encryption keys (hex format)
python main.py pack script.py -o packed_script.py --key deadbeef1234... --iv cafebabe5678...
```

**Options:**

- `-o, --output`: Output file path
- `-k, --key`: Custom encryption key (hex string, 32 bytes = 64 hex chars)
- `-i, --iv`: Custom initialization vector (hex string, 16 bytes = 32 hex chars)

### 2. Light Obfuscation (`light-obfuscate`)

Apply lightweight obfuscation to Python files (variable renaming, string obfuscation, etc.).

```bash
python main.py light-obfuscate script.py
#or
python text_obfuscator.py <your_script.py>
```

**Note:** This command only works with Python (.py) files and modifies them in-place.

### 3. Unpack/Deobfuscate (`unpack`)

Extract and decrypt packed files created with the `pack` command.

```bash
# Basic unpacking
python main.py unpack packed_script.py extracted_file
# or
python3 unpacker.py output/packed_executable_loader.py extracted.bin

# If you already extracted the blob to blob.txt:
python3 unpacker.py blob.txt extracted.bin

# Unpack with analysis options
python main.py unpack packed_script.py extracted_file --print-type --skip-write
# or
python3 unpacker.py output/packed_executable_loader.py /dev/null --skip-write --print-type

```

**Options:**

- `--print-type`: Display payload header information for analysis
- `--skip-write`: Skip writing output file (analysis only mode)

## Key Features

- **Automatic Key Detection**: The unpacker automatically extracts encryption keys from packed files
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Multiple File Types**: Supports Python scripts, executables, and arbitrary binary files
- **Comprehensive Error Handling**: Clear error messages and validation

## Examples

### Complete Workflow

```bash
# 1. Create a packed/obfuscated version
python main.py pack samples/hello.py -o output/secured_hello.py

# 2. Apply additional light obfuscation to the original
python main.py light-obfuscate samples/hello.py

# 3. Later, unpack the secured version
python main.py unpack output/secured_hello.py output/recovered_hello.py
```

### Binary Packing

```bash
# Pack a Windows executable
python main.py pack malware.exe -o packed_malware.py

# Unpack it later
python main.py unpack packed_malware.py recovered_malware.exe
```

## Migration from Separate Scripts

If you were previously using the individual scripts:

- `python packer.py file.py` → `python main.py pack file.py`
- `python text_obfuscator.py file.py` → `python main.py light-obfuscate file.py`
- `python unpacker.py packed.py output.bin` → `python main.py unpack packed.py output.bin`

All original functionality is preserved with improved error handling and automatic key extraction.

---

> [!CAUTION] > **Please use this responsibly and ethically.**
>
> <h4> DISCLAIMER </h4> 
> PackXtract is a **Proof of Concept (PoC) tool** created **strictly for educational and research purposes**. It is designed to demonstrate advanced Python obfuscation techniques that can help protect legitimate intellectual property from reverse engineering.  
> While this tool showcases its effectiveness by being undetectable on VirusTotal, **it is NOT intended for malicious use**. Using PackXtract to obfuscate malware, bypass security measures, or engage in any unethical activities is strictly prohibited.

---

#### **Responsibility & Ethics**

- Cybersecurity professionals and developers can use this tool to **understand, analyze, and defend against** similar obfuscation techniques used by attackers.
- The **developer does not condone** nor take responsibility for any misuse of this tool. Users are solely accountable for how they apply it.
- **Always comply with local laws and ethical guidelines** when using this tool.

By using , `you acknowledge that you understand these terms and accept full responsibility for your actions`.
