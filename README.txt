## Installation & Deployment

### System Requirements
*   **Operating Systems:** Windows 10/11 (Architecture-optimized binary available), Linux (Kernel >= 5.4), macOS (12.0 or later, Native Apple Silicon support).
*   **Hardware Acceleration:** Intel AES-NI / AMD Cryptographic Coprocessor capability required for multi-gigabit throughput.

### Build and Compilation
To compile Speedcrypt from source using the provided high-performance toolchain architecture:

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j\$(nproc)
```

## Usage Verification

Execute the binary with the desired cryptographic engine parameters and input saturation files:

```bash
# High-speed parallel AES-256 encryption with Argon2id key stretching
speedcrypt --encrypt --engine aes-256-gcm --kdf argon2id --input source.dat --output secure.enc

# Permanent media sanitization using the custom multi-pass matrix
speedcrypt --wipe --method custom-erase --target /dev/sdX
```

## License
This software is published under a **Proprietary and Commercial License**. All engineering architecture, mathematical cryptographic matrices, and specific secure data destruction subsystem specifications remain the exclusive intellectual property of Mariano Ortu. Unauthorized reproduction, disassembly, or distribution of any core primitive is strictly prohibited.




===============================================================================
⚡ SPEEDCRYPT SOURCE BUILD & INTEGRITY ALIGNMENT GUIDE ⚡
===============================================================================

Welcome developer! Since Speedcrypt is an Open Source project, you are fully
encouraged to modify, improve, and recompile the source code within your own
development environment. 

However, because Speedcrypt implements strict military-grade anti-tampering 
checks designed to enforce a hardened security posture at startup, any local 
recompilation will naturally alter the final cryptographic signatures of the 
executable files.  

To ensure the compiled application runs correctly without triggering integrity
faults, you MUST follow this mandatory post-build hash alignment process:

-------------------------------------------------------------------------------
📋 STEP-BY-STEP COMPILATION PROCEDURES
-------------------------------------------------------------------------------

1. 🛠️ FIRST-PASS COMPILATION
   Compile the solution to generate the initial builds of the following assets:
   - SpcShell.dll
   - SpcUtility.exe

2. 🧮 HASH CALCULATION
   Calculate the cryptographic hash (SHA-256) for both newly generated files
   using your preferred development tool or terminal command.

3. 🔧 INTEGRATION IN THE SOURCE CODE
   Open the source project and update the hardcoded hash constants inside the
   designated protection classes:
   
   👉 Inject the new SpcShell.dll hash into the class:
      [ SpeedcryptProtection ]
      
   👉 Inject the new SpcUtility.exe hash into the class:
      [ AntiTamperSpcUtility ]

4. 🚀 FINAL RECOMPILATION
   Rebuild the entire solution to apply the updated hashes. Your local build
   is now synchronized, fully verified, and ready for deployment or testing!

-------------------------------------------------------------------------------
⚠️ IMPORTANT DEVELOPER NOTE
-------------------------------------------------------------------------------
Every time you introduce new changes to the source code and recompile, the 
binary hashes will shift again. Remember to repeat this process to maintain
perfect synchronization between the code execution and the runtime integrity
validation engine. Happy coding! 💻✨
===============================================================================
