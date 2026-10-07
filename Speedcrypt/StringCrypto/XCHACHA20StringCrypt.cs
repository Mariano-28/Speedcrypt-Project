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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.StringCrypto
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// XChaCha20StringCrypt is a password-based encryption component designed for
    /// secure string encryption using XChaCha20 stream cipher and Encrypt-then-MAC
    /// authentication with HMAC-SHA256.
    /// </summary>
    /// <remarks>
    /// This class provides:
    /// - Confidentiality via XChaCha20 stream cipher with a 192-bit nonce
    /// - Key derivation via PBKDF2-HMAC-SHA256 with configurable iteration count
    /// - Independent encryption and authentication keys derived from a single KDF output
    /// - Integrity and authenticity via HMAC-SHA256 (Encrypt-then-MAC)
    /// - Pre-decryption authentication verification
    /// - Self-contained encrypted blob format:
    ///   [4 bytes iterations][16 bytes salt][24 bytes nonce][ciphertext][HMAC-SHA256]
    /// - Embedded iteration count for forward compatibility
    /// - Explicit clearing of sensitive memory buffers after use
    ///
    /// This implementation is intended as a production-ready cryptographic component
    /// for the Speedcrypt system.
    ///
    /// Responsibility for this C# implementation, cryptographic design,
    /// integration, and validation lies entirely with the author.
    /// </remarks>
    public static class XChaCha20StringCrypt
    {
        private static readonly int SaltSize = 16;
        private static readonly int KeySize = 32;
        private static readonly int NonceSize = 24;
        private static readonly int HmacSize = 32;

        public static int Iterations = 100000;

        private static readonly SecureRandom RandomGenerator = new SecureRandom();

        // ------------------------------------------------------------
        // PUBLIC ENCRYPT
        // ------------------------------------------------------------
        public static byte[] Encrypt(byte[] plainBytes, byte[] password)
        {
            if (plainBytes == null) throw new ArgumentNullException(nameof(plainBytes));
            if (password == null) throw new ArgumentNullException(nameof(password));

            byte[] salt = GenerateRandomBytes(SaltSize);
            byte[] nonce = GenerateRandomBytes(NonceSize);

            byte[] derived = DeriveKeyMaterial(password, salt, Iterations, KeySize * 2);

            byte[] cipherKey = new byte[KeySize];
            byte[] hmacKey = new byte[KeySize];

            Array.Copy(derived, 0, cipherKey, 0, KeySize);
            Array.Copy(derived, KeySize, hmacKey, 0, KeySize);

            byte[] cipherBytes = XChaCha20Stream(cipherKey, nonce, plainBytes);

            byte[] iterBytes = BitConverter.GetBytes(Iterations);

            int preHmacLen = iterBytes.Length + salt.Length + nonce.Length + cipherBytes.Length;
            byte[] preHmac = new byte[preHmacLen];

            int offset = 0;
            Array.Copy(iterBytes, 0, preHmac, offset, iterBytes.Length); offset += iterBytes.Length;
            Array.Copy(salt, 0, preHmac, offset, salt.Length); offset += salt.Length;
            Array.Copy(nonce, 0, preHmac, offset, nonce.Length); offset += nonce.Length;
            Array.Copy(cipherBytes, 0, preHmac, offset, cipherBytes.Length);

            byte[] hmac = ComputeHmacSha256(hmacKey, preHmac);

            byte[] result = new byte[preHmacLen + HmacSize];
            Array.Copy(preHmac, 0, result, 0, preHmacLen);
            Array.Copy(hmac, 0, result, preHmacLen, HmacSize);

            ClearBytes(derived);
            ClearBytes(cipherKey);
            ClearBytes(hmacKey);
            ClearBytes(preHmac);
            ClearBytes(hmac);

            return result;
        }

        // ------------------------------------------------------------
        // PUBLIC DECRYPT
        // ------------------------------------------------------------
        public static byte[] Decrypt(byte[] encryptedBytes, byte[] password)
        {
            if (encryptedBytes == null) throw new ArgumentNullException(nameof(encryptedBytes));
            if (password == null) throw new ArgumentNullException(nameof(password));

            int offset = 0;

            int iterations = BitConverter.ToInt32(encryptedBytes, offset);
            offset += sizeof(int);

            byte[] salt = new byte[SaltSize];
            Array.Copy(encryptedBytes, offset, salt, 0, SaltSize);
            offset += SaltSize;

            byte[] nonce = new byte[NonceSize];
            Array.Copy(encryptedBytes, offset, nonce, 0, NonceSize);
            offset += NonceSize;

            int cipherLen = encryptedBytes.Length - offset - HmacSize;

            byte[] cipherBytes = new byte[cipherLen];
            Array.Copy(encryptedBytes, offset, cipherBytes, 0, cipherLen);
            offset += cipherLen;

            byte[] hmacStored = new byte[HmacSize];
            Array.Copy(encryptedBytes, offset, hmacStored, 0, HmacSize);

            byte[] derived = DeriveKeyMaterial(password, salt, iterations, KeySize * 2);

            byte[] cipherKey = new byte[KeySize];
            byte[] hmacKey = new byte[KeySize];

            Array.Copy(derived, 0, cipherKey, 0, KeySize);
            Array.Copy(derived, KeySize, hmacKey, 0, KeySize);

            int preHmacLen = sizeof(int) + salt.Length + nonce.Length + cipherBytes.Length;
            byte[] preHmac = new byte[preHmacLen];

            int p = 0;
            Array.Copy(BitConverter.GetBytes(iterations), 0, preHmac, p, sizeof(int)); p += sizeof(int);
            Array.Copy(salt, 0, preHmac, p, salt.Length); p += salt.Length;
            Array.Copy(nonce, 0, preHmac, p, nonce.Length); p += nonce.Length;
            Array.Copy(cipherBytes, 0, preHmac, p, cipherBytes.Length);

            byte[] hmacCalc = ComputeHmacSha256(hmacKey, preHmac);

            if (!AreEqual(hmacStored, hmacCalc))
                throw new CryptographicException("XCHACHA20: Authentication failed. Data may be corrupted or password is incorrect!");

            byte[] plain = XChaCha20Stream(cipherKey, nonce, cipherBytes);

            ClearBytes(derived);
            ClearBytes(cipherKey);
            ClearBytes(hmacKey);
            ClearBytes(preHmac);
            ClearBytes(hmacCalc);

            return plain;
        }

        // ------------------------------------------------------------
        // CORE XCHACHA20 STREAM
        // ------------------------------------------------------------
        private static byte[] XChaCha20Stream(byte[] key, byte[] nonce, byte[] input)
        {
            // 1. derive subkey using HChaCha20
            byte[] subkey = HChaCha20.CreateSubkey(key, nonce);

            // 2. RFC7539 requires 12-byte nonce:
            // 4 bytes counter (zero) + 8 bytes nonce tail
            byte[] iv = new byte[12];
            Array.Copy(nonce, 16, iv, 4, 8);

            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(subkey), iv);

            var cipher = new ChaCha7539Engine();
            cipher.Init(true, parameters);

            byte[] output = new byte[input.Length];
            cipher.ProcessBytes(input, 0, input.Length, output, 0);

            return output;
        }

        // ------------------------------------------------------------
        // HChaCha20
        // ------------------------------------------------------------
        public static class HChaCha20
        {
            public static byte[] CreateSubkey(byte[] key, byte[] nonce)
            {
                uint[] state = CreateInitialState(key, nonce);
                PerformRounds(state);

                return FromUint32LittleEndian(new[]
                {
                state[0], state[1], state[2], state[3],
                state[12], state[13], state[14], state[15]
            }, 32);
            }
            private static uint[] CreateInitialState(byte[] key, byte[] nonce)
            {
                uint[] state = new uint[16];

                uint[] constants =
                {
                0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
            };

                Array.Copy(constants, state, 4);
                Array.Copy(ToUint32LittleEndian(key, 8), 0, state, 4, 8);
                Array.Copy(ToUint32LittleEndian(nonce, 4), 0, state, 12, 4);

                return state;
            }
            private static void PerformRounds(uint[] state)
            {
                for (int i = 0; i < 10; i++)
                {
                    ChaCha20.QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);
                    ChaCha20.QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);
                    ChaCha20.QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]);
                    ChaCha20.QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]);

                    ChaCha20.QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]);
                    ChaCha20.QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]);
                    ChaCha20.QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);
                    ChaCha20.QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);
                }
            }
            private static uint[] ToUint32LittleEndian(byte[] bytes, int count)
            {
                uint[] result = new uint[count];
                for (int i = 0; i < count; i++)
                    result[i] = BitConverter.ToUInt32(bytes, i * 4);
                return result;
            }
            private static byte[] FromUint32LittleEndian(uint[] input, int length)
            {
                byte[] result = new byte[length];
                for (int i = 0; i < input.Length; i++)
                    BitConverter.GetBytes(input[i]).CopyTo(result, i * 4);

                return result;
            }
        }

        // ------------------------------------------------------------
        // CHACHA20
        // ------------------------------------------------------------
        public static class ChaCha20
        {
            public static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
            {
                a += b; d = Rotate(d ^ a, 16);
                c += d; b = Rotate(b ^ c, 12);
                a += b; d = Rotate(d ^ a, 8);
                c += d; b = Rotate(b ^ c, 7);
            }
            private static uint Rotate(uint v, int n)
                => (v << n) | (v >> (32 - n));
        }

        // ------------------------------------------------------------
        // HELPERS
        // ------------------------------------------------------------
        private static byte[] DeriveKeyMaterial(byte[] password, byte[] salt, int iterations, int size)
        {
            using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
                return kdf.GetBytes(size);
        }
        private static byte[] ComputeHmacSha256(byte[] key, byte[] data)
        {
            using (var h = new HMACSHA256(key))
                return h.ComputeHash(data);
        }
        private static bool AreEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];

            return diff == 0;
        }
        private static byte[] GenerateRandomBytes(int len)
        {
            byte[] b = new byte[len];
            RandomGenerator.NextBytes(b);
            return b;
        }
        private static void ClearBytes(byte[] buffer)
        {
            if (buffer == null) return;
            for (int i = 0; i < buffer.Length; i++)
                buffer[i] = 0;
        }
    }
}    