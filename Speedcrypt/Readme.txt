# Speedcrypt

Speedcrypt is a robust, high-performance, and open-source data encryption and protection suite. Built on solid cryptographic foundations and optimized for the Windows platform, its hallmark feature is the exceptional execution speed of its encryption processes.

---

## 🚀 What’s New in This Version

This release introduces a massive architectural overhaul, making Speedcrypt more reliable, secure, and deeply integrated into the operating system.

* **Rewritten Encryption Module:** The core file and string encryption module has been completely redesigned from scratch for superior robustness and performance.
* **Windows Shell Integration:** Seamless OS-level integration now allows users to natively embed **"Encrypt with SpeedCrypt"** and **"Decrypt with SpeedCrypt"** commands directly into the Windows Context Menu.
* **Secure Desktop Shield:** A dedicated anti-keylogger shield providing rigorous protection during sensitive data and password entry.
* **Advanced Cryptographic Enhancements:**
  * Expanded **HASH functions** module with more algorithms for key derivation and integrity checks.
  * Enhanced **Secure Deletion System** for matrix files with improved overwrite methods and pass management.
  * Updated **Pseudo-Random Number Generators (PRNG)** ensuring a higher quality of entropy.
  * Completely rewritten **Password Generator** offering stronger keys and advanced custom parameters.
* **Hardened Security & Self-Diagnostics:** 
  * Integrated anti-tampering controls, configuration validation, and active countermeasures against padding-oracle attacks.
  * Automatic cryptographic engine self-diagnostics at startup (can also be triggered manually anytime).
* **Improved Exception Logging:** Detailed operational monitoring and enhanced debugging logs.

---

## 💻 System Requirements

* **Platform:** Windows 11 (Natively supported and optimized).
* **Compatibility:** Tested and fully operational on Windows 8 and later. 
  * *Note: Unofficial community tests report stable execution on Windows 7, provided the appropriate .NET Framework is installed.*
* **Framework:** Developed in C# using Visual Studio 2022 (.NET Framework 4.8, Common Language Runtime).

---

## 🛡️ Security & Integrity

Speedcrypt exclusively uses trusted, rigorously community-tested **Open Source third-party components** in the field of cryptography. 

While Speedcrypt provides an exceptionally secure environment for your sensitive data, users are reminded that data safety also depends on proper usage and maintaining the overall security hygiene of the host operating system.

---

## 📄 License & Open Source Commitment

Speedcrypt is free software released under an OSI-approved license. It is distributed under the terms of the **GNU General Public License (GPL) version 3 or later**.

* The full license text and author copyright information can be found in the `License/LICENSE` file.
* For acknowledgements and third-party component licenses, please refer to the `Speedcrypt.chm` documentation file.

❤️ *A heartfelt thanks to everyone who takes the time to examine the source code and contribute to improving this project.*