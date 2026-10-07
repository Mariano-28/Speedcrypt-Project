# 🔒 Speedcrypt File Encryption 🔓
### A Powerful File Encryptor & Complete Crypto Suite!

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)  
[![GitHub issues](https://img.shields.io/github/issues/Mariano-28/Speedcrypt-File-Encryption)](https://github.com/Mariano-28/Speedcrypt-File-Encryption/issues)  
[![GitHub stars](https://img.shields.io/github/stars/Mariano-28/Speedcrypt-File-Encryption?style=social)](https://github.com/Mariano-28/Speedcrypt-File-Encryption/stargazers)

---

## 🚀Overview

**Speedcrypt** is an enterprise-grade, high-performance cryptographic security suite designed to deliver uncompromising data privacy, ultra-secure key derivation, and advanced data sanitization. Engineered for environments demanding maximum throughput and absolute mathematical resilience, **Speedcrypt Release 2.0.0.0** introduces a massively scalable architecture featuring a multi-engine core, integrated hardware acceleration, and dynamic entropy harvesting.

> 📝 **Developer Note:** The raw technical notes and the comprehensive development build guide for programmers remain fully available in the repository inside the [README.txt](README.txt) file.

The subsystem integrates four core operational pillars:

*   **Cryptographic Core:** Features **11 symmetric encryption engines** implementing state-of-the-art block and stream ciphers with native hardware instruction set optimization.
*   **Key Derivation Function (KDF) Array:** Deploys a flexible execution matrix supporting **49 distinct cryptographic hash functions as primitives**, providing robust resistance against high-throughput GPU/ASIC brute-force vectors through tunable memory-hard and time-hard parameters.
*   **Secure Data Destruction Subsystem:** Embeds **14 multi-pass secure wiping engines** engineered to permanently sanitize magnetic and solid-state storage media in strict compliance with global military and governmental sanitization standards.
*   **Pseudo-Random Number Generation (PRNG) Suite:** Implements **five high-entropy pseudo-random number generators** specifically engineered for the secure derivation of cryptographic salts and cryptographically strong passwords.

To guarantee systemic operational integrity and runtime immunity against sophisticated threat vectors, Speedcrypt incorporates a kernel-level **Anti-Keylogger monitoring system** alongside an automated, non-blocking **Power-On Self-Test (POST)** routine that continuously validates cryptographic primitives and memory boundary states.

## 🖼️ Screenshot

<img width="929" height="692" alt="main-2" src="https://github.com/user-attachments/assets/31f91b3e-f733-441b-8611-711966e7455c" />

---
## 🛠️Technical Specifications & Architecture

### Cryptographic Core & Symmetric Engines

Speedcrypt deploys a high-performance, multi-layered cryptographic subsystem utilizing hardware-accelerated block and stream ciphers with native sub-pipelining to maximize multi-threaded CPU architectures.

#### File Encryption Engines
The system implements **11 symmetric encryption engines** dedicated to robust file sanitization and protection:
*   **AES / AES-GCM:** Industry-standard block ciphers implemented with native Intel AES-NI and AMD hardware instruction sets.
*   **PGP:** Pretty Good Privacy compliant symmetric primitives for legacy and interoperable secure data exchange.
*   **IDEA:** International Data Encryption Algorithm, operating with highly optimized bitwise transformation routines.
*   **GOST:** Strict implementation of the sovereign standard block cipher primitives.
*   **SERPENT:** Maximum security-margin block cipher configured for deep cryptographic diffusion.
*   **TWOFISH:** Advanced block cipher operating with flexible key-dependent S-boxes.
*   **CAMELLIA:** Fully certified enterprise-grade block cipher with hardware acceleration support.
*   **THREEFISH:** Large-block symmetric cipher optimized for massive data blocks and high-throughput execution.
*   **KUZNYECHIK:** Russian national standard (GOST R 34.12-2015) 128-bit block cipher implementation.
*   **XCHACHA20-POLY1305:** High-throughput authenticated stream cipher optimized for vector registers.

#### Salt & Password Encryption Engines
A dedicated cryptographic subset is engineered specifically for secure key derivation, robust internal SALT masking, and master password defense:
*   **AES / AES-GCM:** Native hardware-accelerated primitives for high-speed authentication and locking.
*   **SERPENT:** Deployed for ultra-secure password obfuscation matrices due to its extensive security margin.
*   **TWOFISH:** High-entropy block cipher configuration protecting internal key derivation structures.
*   **THREEFISH:** Utilized for broad-block password state diffusion.
*   **XCHACHA20 / XCHACHA20-POLY1305:** Extended-nonce stream ciphers providing elite protection against nonce-reuse vectors during key scheduling.

### Key Derivation & Cryptographic Hashing Matrix (49 Primitives)

To neutralize massive distributed GPU/ASIC dictionary attacks and provide ultimate cryptographic flexibility, Speedcrypt integrates a comprehensive matrix of **49 distinct hashing and key derivation primitives** grouped into specialized operational classes:

#### Memory-Hard & Time-Hard KDFs
*   **Argon2 Suite:** Full native implementation of **Argon2id, Argon2d, and Argon2i** variants with customizable memory, time, and multi-threading parallelization parameters.
*   **Scrypt:** Tuned with adjustable memory-exponential factors and high parallelization vectors.
*   **Bcrypt:** Adaptive hashing primitive utilized **strictly and exclusively** for high-entropy dynamic SALT generation and robust master password validation processes.

#### Standard Hardware-Stretching & KDF Formats
*   **PBKDF2-HASH:** High-iteration key derivation framework utilizing the system's extensive underlying hash layer.
*   **HMAC Architecture:** Dedicated keyed-hash message authentication codes (including HMAC-SHA1, HMAC-MD5, HMAC-SHA-2, and HMAC-RIPEMD) engineered for secure integrity verification.

#### High-Performance Hashing & Sovereign Standards
*   **Global Industry Standards:** Extensive support for SHA-2 (SHA-224 to SHA-512), SHA-3 (SHA3-256 to SHA3-512), BLAKE/BLAKE2/BLAKE3 families (up to BLAKE3-1024), RIPEMD, WHIRLPOOL, Tiger, and Keccak/Skein primitives.
*   **Sovereign Compliance Algorithms:** Strict native implementations of national cryptographic standards, including China's **SM3**, and the Russian Federation's **GOST R 34.11-94** and **Streebog** (STREEBOG-256 / STREEBOG-512).

---
### 🎲 Advanced Password Generator & Dynamic Entropy Harvesting Suite
To ensure absolute mathematical unpredictability during the creation of cryptographic salts, initialization vectors (IVs), and master passphrases, Speedcrypt embeds a high-security **Password Generator Subsystem** powered by a configurable, multi-source entropy harvesting matrix. This subsystem completely bypasses standard pseudo-random deterministic patterns by pooling active system noise into a volatile cryptographic pool.

#### 🧠 User-Defined Custom Pattern Architecture
The suite introduces a highly innovative, advanced structural framework allowing power users and security administrators to define, deploy, and store **Custom Generation Patterns**. To prevent the accidental creation of predictable or weak key topologies, the architecture enforces a strict validation protocol:
* **Rigorous Validation Array:** Every custom-configured pattern is automatically subjected to rigorous internal statistical randomness passes and semantic entropy checks.
* **Approval Cleansheet:** A pattern is approved for execution and saved to internal storage *only* after satisfying Speedcrypt's strict underlying compliance criteria, ensuring zero predictability.

#### 🎛️ Configurable Entropy & 5-Engine Execution Core
The generation layer completely isolates password derivation from standard operating system entropy vulnerabilities by utilizing five distinct, industry-certified pseudo-random number generation primitives:

* **BCRYPT Engine:** Adaptive hardware-stretching algorithm optimized for securing master passphrases against multi-GPU dictionaries.
* **FORTUNA Architecture:** Cryptographically secure PRNG utilizing automated internal seed-pooling and dynamic software/hardware entropy refreshment.
* **AES-CTR DRBG:** Deterministic Random Bit Generator operating in Counter Mode, backed by native Intel `AES-NI` / AMD instruction sets for massive parallel throughput.
* **CRYPTO-RANDOM Layer:** Native high-entropy operating system cryptographic provider utilized as a primary whitening and saturation layer.
* **BLUM-BLUM-SHUB [BBS]:** An elite, mathematically proven secure PRNG operating on the inherent computational difficulty of the quadratic residuosity problem, offering extreme resistance against cryptographic analysis.

#### 📸 Subsystem Visual Interface
Below is the operational interface of the Advanced Password Generator, demonstrating the real-time entropy accumulation matrix, with key selection calibrated based on the specific characteristics of your system. Generated cryptographic keys support ultra-secure granular lengths of **256**, **384**, **512**, **1024**, **2048**, and up to a massive **4096** bits:

<img width="925" height="693" alt="Additional Entropy" src="https://github.com/user-attachments/assets/c78a67b6-c72b-46ec-97ed-fb70e89b2644" />

---

## 🗑️Secure Data Destruction Subsystem (14 Wiping Engines)

Speedcrypt integrates an advanced data sanitization subsystem equipped with 14 secure wiping protocols. These engines overwrite storage cells with high-entropy pseudo-random patterns and fixed bitstreams to systematically neutralize magnetic and solid-state data remanence in strict compliance with international sanitization architectures.

The system implements the following 14 production-ready wiping methods:
*   **Quick 1 Pass:** High-throughput 1-pass execution utilizing rapid block clearing.
*   **Random 1 Pass:** High-entropy 1-pass overwrite using dynamically seeded pseudo-random patterns.
*   **DoD 3 Passes:** Standard US Department of Defense (5220.22-M) compliant 3-pass sanitization sequence.
*   **DoD 7 Passes:** Extended US Department of Defense (5220.22-M ECE) 7-pass military-grade overwriting matrix.
*   **Schneier 7 Passes:** Bruce Schneier's multi-pass data destruction methodology utilizing dedicated pseudo-random and fixed streams.
*   **German VSITR 7 Passes:** Federal German standard implementing strict alternating character bit-saturation and verification.
*   **Gutmann 35 Passes:** Classic 35-pass mathematical sequence engineered for legacy magnetic media constraints.
*   **RCMP TSSIT OPS-II:** Royal Canadian Mounted Police compliant multi-pass random and alternating sanitization layout.
*   **British HMG IS5 [Enhanced]:** Enhanced British government compliance verification and saturation protocol.
*   **Custom Erase by Mariano Ortu [User Defined]:** The author's proprietary advanced multi-pass mathematical saturation and purging sequence.
*   **NSA/CSS Standard 9:** High-security National Security Agency overwriting specification for media sanitization.
*   **NSA/CSS Standard 12:** Advanced administrative national agency security profile for data destruction.
*   **Secure Delete:** Highly optimized logic-level secure file unlinking and targeted cluster destruction.
*   **NIST 800-88 Rev.1 Secure Erase:** Modern cryptographic and logical media purging engineered for solid-state (SSD) and flash memory topologies.


---

## 🔨Systemic Protection & Runtime Integrity

#### Kernel-Level Anti-Keylogger & Screen Obfuscation
To guarantee absolute cryptographic key confidentiality during user input, Speedcrypt implements a deeply integrated runtime defense subsystem engineered to defeat both software-level and hardware-level interceptors:
*   **Anti-Keylogger Subsystem:** Operates via a low-level kernel monitoring hooks layer that dynamically isolates raw keyboard input streams, injects chaotic noise matrices into unauthorized polling hooks, and prevents hardware/software API sniffing vectors from capturing passphrases.
*   **Obfuscate Prevent Screen Technology:** Implements native hardware-accelerated screen protection mechanisms that systematically block unauthorized screen capture, video recording, and API-based scraping vectors, rendering critical input windows completely opaque to background spy processes.

#### Power-On Self-Test (POST) & Autotest
Every operational lifecycle begins with a non-blocking, multi-threaded Power-On Self-Test (POST) routine designed to guarantee that the system executes exclusively within a verified, uncompromised state:
*   **Primitive Consistency:** Verification of cryptographic mathematical correctness against strict Known-Answer Tests (KAT) before any user data is processed.
*   **Memory Boundary Isolation:** Active validation of zero-allocation buffers, ensuring complete isolation to prevent cross-process leakages or memory overflow vulnerabilities.

---

## 💻 Installation, Deployment & Build Configuration

#### System Requirements
*   **Operating Systems:** Microsoft Windows 8, Windows 10, and Windows 11 (fully optimized native architecture binaries).
*   **Hardware Acceleration:** Intel AES-NI / AMD Cryptographic Coprocessor capability required for high-throughput hardware-assisted encryption.

---

## ⚡ Source Build & Integrity Alignment Guide

Because Speedcrypt implements strict anti-tampering checks designed to enforce a hardened security posture at startup, any local recompilation will alter the final cryptographic signatures of the executable files. To ensure the compiled application runs correctly without triggering integrity faults, you MUST follow this mandatory post-build hash alignment process:

1. **First-Pass Compilation:** Compile the solution to generate the initial builds of `SpcShell.dll` and `SpcUtility.exe`.
2. **Hash Calculation:** Calculate the cryptographic hash (SHA-256) for both newly generated files using your preferred terminal tool.
3. **Integration in the Source Code:** Open the source project and update the hardcoded hash constants inside the designated protection classes:
   * Inject the new `SpcShell.dll` hash into the class: `SpeedcryptProtection`
   * Inject the new `SpcUtility.exe` hash into the class: `AntiTamperSpcUtility`
4. **Final Recompilation:** Rebuild the entire solution to apply the updated hashes. Your local build is now fully verified and ready for deployment!

---

## 📄 License & Copyright

**Speedcrypt**  
Copyright (C) 2024-2026 **Mariano Ortu** — [speedcrypt.info](https://speedcrypt.info)

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License as published by the Free Software Foundation, version 3 or later**.

This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

*   For comprehensive acknowledgements, external component licenses, and third-party resources utilized within the project, please refer directly to the compiled help file: **`Speedcrypt.chm`**.
*   A full verbatim copy of the GNU General Public License Version 3 is included within the repository root documentation.

---

## 🌐 Official Resources & Supply Chain Security

To ensure absolute authenticity and protect users against Man-in-the-Middle (MitM) attacks, malicious mirrors, or package tampering, Speedcrypt utilizes a dedicated, highly secure distribution and verification infrastructure.

Users and developers must rely exclusively on the following official channels:

*   **Official Website:** [speedcrypt.info](https://speedcrypt.info) — The central hub for project news, architectural overviews, detailed documentation, and official system requirements.
*   **Download Center:** [speedcrypt.info/download-page.html](https://speedcrypt.info/download-page.html) — The authenticated release platform providing official installation packages (`Setup.exe`), portable environments (`Portable.zip`), and the full open-source distribution.
*   **Package Integrity Verification:** [speedcrypt.info/integrity.html](https://speedcrypt.info/integrity.html) — The core security clearinghouse containing standalone, un-archived cryptographic multi-hash metadata (MD5, SHA-1, SHA-256) and raw detached OpenPGP Digital Signatures for every released artifact.

### 🔐 Mandatory Verification Notice
Before executing or deploying any Speedcrypt binary, users are strongly encouraged to independently validate their local files. This can be performed by computing local checksums (using tools like *EasyHash*) and 
verifying the detached OpenPGP signatures against Mariano Ortu's verified public master key fingerprint:  
**`🔑B96F 975A 6FA8 ED1D 0441 F9F3 2DBB 5444 2D09 9434`**
