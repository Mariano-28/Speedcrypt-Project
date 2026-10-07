/// Speedcrypt software - The Open-Source for encrypt and decrypt files
// Copyright (C) 2024-2026 Mariano Ortu <https://www.speedcrypt.info/>
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//https://www.gnu.org/licenses/gpl-3.0.html 

using System;
using System.Security.Cryptography;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.Crypto.AES;
using Speedcrypt.Crypto.GOST;
using Speedcrypt.Crypto.IDEA;
using Speedcrypt.Crypto.AESGCM;
using Speedcrypt.Crypto.Serpent;
using Speedcrypt.Crypto.TwoFish;
using Speedcrypt.Crypto.CAMELLIA;
using Speedcrypt.Crypto.Threefish;
using Speedcrypt.Crypto.KUZNYECHIK;
using Speedcrypt.Crypto.XChaCha20Poly1305;

namespace Speedcrypt.Crypto
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// EncryptionManager: Central manager for file encryption and decryption across all supported algorithms in Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements unified encryption and decryption routing within the Speedcrypt framework with the following key features:
    /// - Expands or truncates derived password hashes to match exact algorithm key sizes.
    /// - Supports AES, AES-GCM, Camellia, GOST, IDEA, Kuznyechik, Serpent, Threefish, Twofish, and XChaCha20-Poly1305.
    /// - Routes encryption/decryption calls to algorithm-specific classes.
    /// - Maintains consistent encrypted file extensions (".SPCR") and integrity verification mechanisms.
    /// - Handles decryption failures securely via ForAllUnits.DecSett and Passwerr.HandleDecryptionFailure().
    ///
    /// Technical notes:
    /// - Key expansion uses SHA-256 hash chaining to preserve entropy when adjusting derived hashes.
    /// - Algorithms handling keys internally (GOST, IDEA, XChaCha20-Poly1305) bypass expansion.
    /// - Fully integrated into Speedcrypt framework for secure file encryption/decryption.
    /// - Designed for thread-safe, predictable, and secure operations across multiple algorithms.
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public static class EncryptionManager
     {
        public static byte[] ExpandKey(byte[] derivedHash, int keySize)
         {
             int required = keySize / 8;

             // Exact match: return clone
             if (derivedHash.Length == required)
                 return (byte[])derivedHash.Clone();

             byte[] result = new byte[required];
             int offset = 0;

             // Copy original bytes first
             Array.Copy(derivedHash, 0, result, 0, Math.Min(derivedHash.Length, required));
             offset = derivedHash.Length;

             using (var sha256 = SHA256.Create())
             {
                 byte[] temp = (byte[])derivedHash.Clone();

                 // Extend until we reach the required length
                 while (offset < required)
                 {
                     temp = sha256.ComputeHash(temp);
                     int toCopy = Math.Min(temp.Length, required - offset);
                     Array.Copy(temp, 0, result, offset, toCopy);
                     offset += toCopy;
                 }

                 // Clear temporary buffer
                 Array.Clear(temp, 0, temp.Length);
             }

             return result;
         }

        /// <summary>
        /// EncryptFile: Encrypts the input file using the specified algorithm and derived key.
        /// Routes the operation to the corresponding algorithm-specific class.
        /// </summary>
        ///
        /// <param name="inputFilePath">Full path of the input file to encrypt.</param>
        /// <param name="outputFilePath">Full path for the encrypted output file.</param>
        /// <param name="passwordBytes">Derived password bytes used for key generation.</param>
        /// <param name="keySize">Target key size in bits for the encryption algorithm.</param>
        /// <param name="algorithmName">Algorithm identifier (e.g., "AES", "SERPENT").</param>
        /// <remarks>
        /// Ensures that keys are expanded or truncated as required.
        /// Handles algorithm-specific details internally and maintains file integrity.
        /// Responsibility for secure encryption lies entirely with the author.
        /// </remarks>
        public static void EncryptFile(string inputFilePath, string outputFilePath, byte[] passwordBytes, int keySize, string algorithmName)
         {
             byte[] finalKey;

             switch (algorithmName)
             {
                 case "AES":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     AESencryptor aes = new AESencryptor();
                     aes.EncryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "AES-GCM":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     AESGCMEncryptor aesGcmEncryptor = new AESGCMEncryptor();
                     aesGcmEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "CAMELLIA":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     CamelliaEncryptor camelliaEncryptor = new CamelliaEncryptor();
                     camelliaEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "GOST":
                    finalKey = ExpandKey(passwordBytes, 256); // ensure 32 bytes
                    GostEncryptor gostEncryptor = new GostEncryptor();
                    gostEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey);
                    break;

                 case "IDEA":
                     finalKey = passwordBytes; // IDEA handles key length internally
                     IDEAEncryptor ideaEncryptor = new IDEAEncryptor();
                      ideaEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey);
                     break;

                 case "KUZNYECHIK":
                     finalKey = ExpandKey(passwordBytes, 256); // Kuznyechik requires 32 bytes
                     KuznyechikEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey);
                     break;

                 case "SERPENT":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     SerpentEncryptor serpentEncryptor = new SerpentEncryptor();
                     serpentEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "THREEFISH":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     ThreeFishEncryptor threeFishEncryptor = new ThreeFishEncryptor();
                     threeFishEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "TWOFISH":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     TwoFishEncryptor twoFishEncryptor = new TwoFishEncryptor();
                      twoFishEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "XCHACHA20-POLY1305":
                     finalKey = passwordBytes; // XChaCha20-Poly1305 handles key length internally
                     XChaCha20Poly1305FileEncryptor.EncryptFile(inputFilePath, outputFilePath, finalKey);
                     break;

                 default:
                     throw new NotSupportedException($"Algorithm {algorithmName} not supported.");
             }
         }

        /// <summary>
        /// DecryptFile: Decrypts the input file using the specified algorithm and derived key.
        /// Routes the operation to the corresponding algorithm-specific class.
        /// </summary>
        ///
        /// <param name="inputFilePath">Full path of the encrypted input file.</param>
        /// <param name="outputFilePath">Full path for the decrypted output file.</param>
        /// <param name="passwordBytes">Derived password bytes used for key generation.</param>
        /// <param name="keySize">Target key size in bits for the decryption algorithm.</param>
        /// <param name="algorithmName">Algorithm identifier (e.g., "AES", "SERPENT").</param>
        /// <returns>Boolean indicating success (true) or failure (false) of decryption.</returns>
        /// <remarks>
        /// Resets ForAllUnits.DecSett in case of failure to signal decryption error.
        /// Handles algorithm-specific decryption internally and securely.
        /// Responsibility for correct, safe decryption lies entirely with the author.
        /// </remarks>
        public static bool DecryptFile(string inputFilePath, string outputFilePath, byte[] passwordBytes, int keySize, string algorithmName)
         {
             bool success = false;
             ForAllUnits.DecSett = 0;
             byte[] finalKey;

             switch (algorithmName)
             {
                 case "AES":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     AESencryptor aes = new AESencryptor();
                     success = aes.DecryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "AES-GCM":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     AESGCMEncryptor aesGcmDecryptor = new AESGCMEncryptor();
                      success = aesGcmDecryptor.DecryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "CAMELLIA":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     CamelliaEncryptor camelliaDecryptor = new CamelliaEncryptor();
                      success = camelliaDecryptor.DecryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "GOST":
                    finalKey = ExpandKey(passwordBytes, 256); // ensure 32 bytes
                    GostEncryptor gostDecryptor = new GostEncryptor();
                    success = gostDecryptor.DecryptFile(inputFilePath, outputFilePath, finalKey);
                    break;

                 case "IDEA":
                     finalKey = passwordBytes;
                     IDEAEncryptor ideaDecryptor = new IDEAEncryptor();
                     success = ideaDecryptor.DecryptFile(inputFilePath, outputFilePath, finalKey);
                     break;

                 case "KUZNYECHIK":
                     finalKey = ExpandKey(passwordBytes, 256);
                     success = KuznyechikEncryptor.DecryptFile(inputFilePath, outputFilePath, finalKey);
                     break;

                 case "SERPENT":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     SerpentEncryptor serpentDecryptor = new SerpentEncryptor();
                     success = serpentDecryptor.DecryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "THREEFISH":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     ThreeFishEncryptor threeFishDecryptor = new ThreeFishEncryptor();
                     success = threeFishDecryptor.DecryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "TWOFISH":
                     finalKey = ExpandKey(passwordBytes, keySize);
                     TwoFishEncryptor twoFishDecryptor = new TwoFishEncryptor();
                      success = twoFishDecryptor.DecryptFile(inputFilePath, outputFilePath, finalKey, keySize);
                     break;

                 case "XCHACHA20-POLY1305":
                     finalKey = passwordBytes;
                     success = XChaCha20Poly1305FileEncryptor.DecryptFile(inputFilePath, outputFilePath, finalKey);
                     break;

                 default:
                     throw new NotSupportedException($"Algorithm {algorithmName} not supported.");
             }

             if (!success)
                 ForAllUnits.DecSett = 1;

             return success;
         }
     }    
}