// Speedcrypt software - The Open-Source for encrypt and decrypt files
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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.StringCrypto
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// AESGCMStringCrypt: String encryption and decryption class based on AES-256 in Galois/Counter Mode (GCM).
    /// Uses password-derived keys via PBKDF2-HMAC-SHA256 with configurable iteration count.
    /// Designed for Speedcrypt cryptographic core with authenticated encryption guarantees.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Secure encryption and decryption of byte arrays using AES-256-GCM (AEAD)
    /// - Password-based key derivation using PBKDF2 with HMAC-SHA256 and per-message random salt
    /// - Use of a 96-bit random IV and a 128-bit authentication tag as recommended by NIST
    /// - Self-contained encrypted blob format:
    ///   [4 bytes PBKDF2 iterations][salt][IV][ciphertext + authentication tag]
    /// - Automatic integrity and authenticity verification during decryption
    /// - Immediate failure on authentication errors or invalid passwords
    /// - Explicit clearing of sensitive material from memory after use
    ///
    /// Responsibility for this C# implementation, cryptographic design,
    /// integration, and validation lies entirely with the author.
    /// </remarks>
    public static class AESGCMStringCrypt
    {
        private static readonly int SaltSize = 16; // 128-bit salt
        private static readonly int KeySize = 32;  // 256-bit key
        private static readonly int IvSize = 12;   // 96-bit IV (GCM standard)
        private static readonly int TagSize = 16;  // 128-bit authentication tag
        public static int Iterations = 100000;     // PBKDF2 iteration count (default)

        private static readonly SecureRandom RandomGenerator = new SecureRandom();

        /// <summary>
        /// Encrypts plaintext bytes using password-derived key (PBKDF2 with SHA-256), AES-GCM.
        /// Output blob format: [4 bytes iterations][salt][iv][ciphertext+tag].
        /// Returns the raw byte[] blob (no Base64).
        /// </summary>
        public static byte[] Encrypt(byte[] plainBytes, byte[] passwordBytes)
        {
            if (plainBytes == null) throw new ArgumentNullException(nameof(plainBytes));
            if (passwordBytes == null) throw new ArgumentNullException(nameof(passwordBytes));
            if (passwordBytes.Length == 0) throw new ArgumentException("Password bytes empty", nameof(passwordBytes));

            byte[] salt = GenerateRandomBytes(SaltSize);
            int iterationsToUse = Iterations;
            byte[] key = DeriveKey(passwordBytes, salt, iterationsToUse);

            byte[] iv = GenerateRandomBytes(IvSize);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), TagSize * 8, iv);
            cipher.Init(true, parameters);

            byte[] cipherBytes = new byte[cipher.GetOutputSize(plainBytes.Length)];
            int processed = cipher.ProcessBytes(plainBytes, 0, plainBytes.Length, cipherBytes, 0);
            int final = cipher.DoFinal(cipherBytes, processed);
            int cipherLen = processed + final;

            // Build output: iterations (4) + salt + iv + ciphertext(tag included)
            byte[] iterBytes = BitConverter.GetBytes(iterationsToUse);
            int combinedLen = iterBytes.Length + salt.Length + iv.Length + cipherLen;
            byte[] combined = new byte[combinedLen];

            int offset = 0;
            Array.Copy(iterBytes, 0, combined, offset, iterBytes.Length); offset += iterBytes.Length;
            Array.Copy(salt, 0, combined, offset, salt.Length); offset += salt.Length;
            Array.Copy(iv, 0, combined, offset, iv.Length); offset += iv.Length;
            Array.Copy(cipherBytes, 0, combined, offset, cipherLen);

            // Clear sensitive material
            Array.Clear(key, 0, key.Length);
            Array.Clear(cipherBytes, 0, cipherBytes.Length);

            return combined;
        }

        /// <summary>
        /// Decrypts the raw byte[] blob produced by Encrypt.
        /// Expects blob layout: [4 bytes iterations][salt][iv][ciphertext+tag].
        /// Returns plaintext bytes.
        /// </summary>
        public static byte[] Decrypt(byte[] encryptedBlob, byte[] passwordBytes)
        {
            if (encryptedBlob == null) throw new ArgumentNullException(nameof(encryptedBlob));
            if (passwordBytes == null) throw new ArgumentNullException(nameof(passwordBytes));
            if (passwordBytes.Length == 0) throw new ArgumentException("Password bytes empty", nameof(passwordBytes));

            // Minimal header check
            int headerSize = sizeof(int) + SaltSize + IvSize;
            if (encryptedBlob.Length < headerSize + TagSize)
                throw new ArgumentException("Input data is too short.", nameof(encryptedBlob));

            int offset = 0;
            int storedIterations = BitConverter.ToInt32(encryptedBlob, offset);
            offset += sizeof(int);

            byte[] salt = new byte[SaltSize];
            Array.Copy(encryptedBlob, offset, salt, 0, SaltSize);
            offset += SaltSize;

            byte[] iv = new byte[IvSize];
            Array.Copy(encryptedBlob, offset, iv, 0, IvSize);
            offset += IvSize;

            int cipherTextLen = encryptedBlob.Length - offset;
            if (cipherTextLen <= 0)
                throw new ArgumentException("No ciphertext present.", nameof(encryptedBlob));

            byte[] cipherText = new byte[cipherTextLen];
            Array.Copy(encryptedBlob, offset, cipherText, 0, cipherTextLen);

            byte[] key = DeriveKey(passwordBytes, salt, storedIterations);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), TagSize * 8, iv);
            cipher.Init(false, parameters);

            byte[] plainBytes = new byte[cipher.GetOutputSize(cipherText.Length)];
            try
            {
                int processed = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainBytes, 0);
                int final = cipher.DoFinal(plainBytes, processed);
                int total = processed + final;

                // Trim to actual plaintext length
                byte[] result = new byte[total];
                Array.Copy(plainBytes, 0, result, 0, total);

                // Clear sensitive buffers
                Array.Clear(key, 0, key.Length);
                Array.Clear(plainBytes, 0, plainBytes.Length);
                Array.Clear(cipherText, 0, cipherText.Length);

                return result;
            }
            catch (InvalidCipherTextException)
            {
                // Clear sensitive buffers before rethrowing
                Array.Clear(key, 0, key.Length);
                Array.Clear(plainBytes, 0, plainBytes.Length);
                Array.Clear(cipherText, 0, cipherText.Length);

                throw new CryptographicException("AES-GCM: Authentication failed. Data may be corrupted or password is incorrect!");
            }
        }

        /// <summary>
        /// Derives key using PBKDF2 (HMAC-SHA256) from password bytes.
        /// </summary>
        private static byte[] DeriveKey(byte[] passwordBytes, byte[] salt, int iterations)
        {
            if (passwordBytes == null) throw new ArgumentNullException(nameof(passwordBytes));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (iterations <= 0) throw new ArgumentOutOfRangeException(nameof(iterations));

            // Use Rfc2898DeriveBytes with byte[] password if available on target framework.
            // If your framework doesn't expose the byte[] overload, replace with a PBKDF2 implementation that accepts bytes.
            using (var kdf = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, HashAlgorithmName.SHA256))
            {
                return kdf.GetBytes(KeySize);
            }
        }

        // Generate secure random bytes for salt and IV
        private static byte[] GenerateRandomBytes(int length)
        {
            if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
            byte[] bytes = new byte[length];
            RandomGenerator.NextBytes(bytes);
            return bytes;
        }
    }
}