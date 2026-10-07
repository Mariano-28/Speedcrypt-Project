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

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.StringCrypto
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Threefish-256 CBC string encryption for Speedcrypt with PBKDF2 key derivation and HMAC authentication.
    /// </summary>
    ///
    /// <remarks>
    /// Responsibilities:
    /// - Encrypts/decrypts data using Threefish-256 in CBC mode with PKCS7 padding
    /// - Derives a 512-bit secret from password + salt using PBKDF2-HMAC-SHA256
    ///   (first 32 bytes = Threefish key, next 32 bytes = HMAC key)
    /// - Uses a 256-bit random IV consistent with Threefish block size
    /// - Implements Encrypt-then-MAC (HMAC-SHA256) for integrity and authenticity
    /// - Produces deterministic binary blob:
    ///   [iterations][salt][iv][ciphertext][hmac]
    /// - Verifies HMAC prior to decryption and aborts on authentication failure
    /// - Explicitly clears sensitive buffers to reduce memory exposure
    ///
    /// This implementation is a deliberate architectural choice designed for
    /// consistency with other Speedcrypt engines (AES, Serpent, etc.).
    /// It is final, production-ready, and fully owned by the author.
    ///
    /// Design note:
    /// Threefish is natively designed as a tweakable block cipher and is commonly
    /// used in constructions such as Skein or XTS-like modes.
    /// 
    /// In this implementation, Threefish-256 is intentionally used in CBC mode
    /// with PKCS7 padding to maintain architectural consistency across Speedcrypt
    /// block-cipher engines (AES, Serpent, Twofish, Threefish).
    /// 
    /// This is a deliberate and conscious design choice, not a limitation of the
    /// underlying primitive. Security is preserved by:
    /// - a full-width 256-bit random IV,
    /// - strong PBKDF2-HMAC-SHA256 key derivation,
    /// - strict Encrypt-then-MAC authentication.
    /// 
    /// /// Responsibility for this C# implementation, cryptographic design,
    /// integration, and validation lies entirely with the author.
    /// </remarks>
    public static class ThreeFishStringCrypt
    {
        private static readonly int SaltSize = 16;  // 128-bit salt
        private static readonly int KeySize = 32;   // 256-bit Threefish key
        private static readonly int IvSize = 32;    // 256-bit IV
        private static readonly int HmacSize = 32;  // 256-bit HMAC-SHA256 tag
        public static int Iterations = 100000;      // PBKDF2 default iterations

        private static readonly SecureRandom RandomGenerator = new SecureRandom();
        public static byte[] Encrypt(byte[] plainBytes, byte[] passwordBytes)
        {
            if (plainBytes == null) throw new ArgumentNullException(nameof(plainBytes));
            if (passwordBytes == null) throw new ArgumentNullException(nameof(passwordBytes));
            if (Iterations <= 0) throw new ArgumentOutOfRangeException(nameof(Iterations), "Iterations must be positive.");

            byte[] salt = GenerateRandomBytes(SaltSize);
            int iterationsToUse = Iterations;

            byte[] derived = DeriveKeyMaterial(passwordBytes, salt, iterationsToUse, KeySize * 2);
            byte[] threefishKey = new byte[KeySize];
            byte[] hmacKey = new byte[KeySize];
            Array.Copy(derived, 0, threefishKey, 0, KeySize);
            Array.Copy(derived, KeySize, hmacKey, 0, KeySize);

            byte[] iv = GenerateRandomBytes(IvSize);
            byte[] cipherText;

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new ThreefishEngine(256)));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(threefishKey), iv));
            cipherText = cipher.DoFinal(plainBytes);

            byte[] iterBytes = BitConverter.GetBytes(iterationsToUse);
            int preHmacLen = iterBytes.Length + salt.Length + iv.Length + cipherText.Length;
            byte[] preHmac = new byte[preHmacLen];
            int offset = 0;
            Array.Copy(iterBytes, 0, preHmac, offset, iterBytes.Length); offset += iterBytes.Length;
            Array.Copy(salt, 0, preHmac, offset, salt.Length); offset += salt.Length;
            Array.Copy(iv, 0, preHmac, offset, iv.Length); offset += iv.Length;
            Array.Copy(cipherText, 0, preHmac, offset, cipherText.Length);

            byte[] hmac = ComputeHmacSha256(hmacKey, preHmac);

            byte[] combined = new byte[preHmacLen + hmac.Length];
            Array.Copy(preHmac, 0, combined, 0, preHmacLen);
            Array.Copy(hmac, 0, combined, preHmacLen, hmac.Length);

            ClearBytes(derived);
            ClearBytes(threefishKey);
            ClearBytes(hmacKey);
            ClearBytes(preHmac);

            return combined;
        }
        public static byte[] Decrypt(byte[] encryptedBytes, byte[] passwordBytes)
        {
            if (encryptedBytes == null) throw new ArgumentNullException(nameof(encryptedBytes));
            if (passwordBytes == null) throw new ArgumentNullException(nameof(passwordBytes));

            int offset = 0;
            int storedIterations = BitConverter.ToInt32(encryptedBytes, offset);
            offset += sizeof(int);
            if (storedIterations <= 0)
                throw new ArgumentException("Stored iterations is invalid.", nameof(encryptedBytes));

            byte[] salt = new byte[SaltSize];
            Array.Copy(encryptedBytes, offset, salt, 0, SaltSize);
            offset += SaltSize;

            byte[] iv = new byte[IvSize];
            Array.Copy(encryptedBytes, offset, iv, 0, IvSize);
            offset += IvSize;

            int cipherTextLen = encryptedBytes.Length - offset - HmacSize;
            if (cipherTextLen <= 0)
                throw new ArgumentException("No ciphertext present.", nameof(encryptedBytes));

            byte[] cipherText = new byte[cipherTextLen];
            Array.Copy(encryptedBytes, offset, cipherText, 0, cipherTextLen);
            offset += cipherTextLen;

            byte[] hmacStored = new byte[HmacSize];
            Array.Copy(encryptedBytes, offset, hmacStored, 0, HmacSize);

            byte[] derived = DeriveKeyMaterial(passwordBytes, salt, storedIterations, KeySize * 2);
            byte[] threefishKey = new byte[KeySize];
            byte[] hmacKey = new byte[KeySize];
            Array.Copy(derived, 0, threefishKey, 0, KeySize);
            Array.Copy(derived, KeySize, hmacKey, 0, KeySize);

            int preHmacLen = sizeof(int) + salt.Length + iv.Length + cipherText.Length;
            byte[] preHmac = new byte[preHmacLen];
            int p = 0;
            Array.Copy(BitConverter.GetBytes(storedIterations), 0, preHmac, p, sizeof(int)); p += sizeof(int);
            Array.Copy(salt, 0, preHmac, p, salt.Length); p += salt.Length;
            Array.Copy(iv, 0, preHmac, p, iv.Length); p += iv.Length;
            Array.Copy(cipherText, 0, preHmac, p, cipherText.Length);

            byte[] hmacCalc = ComputeHmacSha256(hmacKey, preHmac);

            if (!AreEqual(hmacStored, hmacCalc))
            {
                ClearBytes(derived);
                ClearBytes(threefishKey);
                ClearBytes(hmacKey);
                ClearBytes(preHmac);
                ClearBytes(hmacCalc);
                throw new CryptographicException("THREEFISH: Authentication failed. Data may be corrupted or password is incorrect!");
            }

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new ThreefishEngine(256)));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(threefishKey), iv));
            byte[] plainBytes = cipher.DoFinal(cipherText);

            ClearBytes(derived);
            ClearBytes(threefishKey);
            ClearBytes(hmacKey);
            ClearBytes(preHmac);
            ClearBytes(hmacCalc);

            return plainBytes;
        }
        private static byte[] DeriveKeyMaterial(byte[] passwordBytes, byte[] salt, int iterations, int outputBytes)
        {
            using (var kdf = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, HashAlgorithmName.SHA256))
            {
                return kdf.GetBytes(outputBytes);
            }
        }
        private static byte[] ComputeHmacSha256(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }
        private static bool AreEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }
        private static byte[] GenerateRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            RandomGenerator.NextBytes(bytes);
            return bytes;
        }
        private static void ClearBytes(byte[] buffer)
        {
            if (buffer == null) return;
            for (int i = 0; i < buffer.Length; i++)
                buffer[i] = 0;
        }
    }
}