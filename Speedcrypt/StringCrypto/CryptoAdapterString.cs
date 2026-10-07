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
using System.Collections.Generic;

namespace Speedcrypt.StringCrypto
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CryptoAdapterByte: Cryptographic dispatch adapter operating on byte arrays,
    /// providing a string-based engine selection layer over multiple encryption algorithms.
    /// Designed for dynamic configuration scenarios within Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Unified encrypt/decrypt interface using string-based engine identifiers.
    /// - Centralized mapping of cryptographic engines via high-performance delegate dictionaries.
    /// - Thread-safe, atomic synchronization (via mutual exclusion locks) when stateful static properties are updated.
    /// - Single-pass dictionary resolution using TryGetValue to minimize hash-table overhead.
    /// - Per-operation configuration of PBKDF2 iteration count with automated security baseline enforcement.
    /// - Clear separation between engine selection logic and cryptographic implementation.
    /// - Deterministic execution paths devoid of reflection, dynamic invocation, or structural overhead.
    ///
    /// The adapter encapsulates concurrent execution safety, guaranteeing that shared static 
    /// iteration parameters are isolated and protected against race conditions at call time.
    ///
    /// Responsibility for this C# implementation, cryptographic design,
    /// integration, and validation lies entirely with the author.
    /// </remarks>
    public interface ICryptoServiceByte
    {
        /// <summary>
        /// Encrypts plaintext bytes using the specified cryptographic engine and password.
        /// </summary>
        /// <param name="engine">The name of the encryption algorithm (e.g., "AES-GCM").</param>
        /// <param name="plaintext">The raw plaintext bytes to encrypt.</param>
        /// <param name="password">The password bytes used for key derivation.</param>
        /// <param name="iterations">The PBKDF2 iteration count (defaults to 100,000).</param>
        /// <returns>A byte array containing the encrypted blob.</returns>
        byte[] Encrypt(string engine, byte[] plaintext, byte[] password, int iterations = 100000);

        /// <summary>
        /// Decrypts ciphertext bytes using the specified cryptographic engine and password.
        /// </summary>
        /// <param name="engine">The name of the decryption algorithm (e.g., "AES-GCM").</param>
        /// <param name="ciphertext">The encrypted byte array blob.</param>
        /// <param name="password">The password bytes used for key derivation.</param>
        /// <param name="iterations">The PBKDF2 iteration count used as fallback if not embedded in the header.</param>
        /// <returns>A byte array containing the decrypted plaintext.</returns>
        byte[] Decrypt(string engine, byte[] ciphertext, byte[] password, int iterations = 100000);
    }
    public class CryptoAdapterByte : ICryptoServiceByte
    {
        // Synchronization object to enforce thread-safety across static state configuration updates
        private static readonly object SyncLock = new object();

        private readonly Dictionary<string, Func<byte[], byte[], int, byte[]>> _encryptMap;
        private readonly Dictionary<string, Func<byte[], byte[], int, byte[]>> _decryptMap;

        public CryptoAdapterByte()
        {
            // StringComparer.OrdinalIgnoreCase ensures case-insensitive matching across target engines
            _encryptMap = new Dictionary<string, Func<byte[], byte[], int, byte[]>>(StringComparer.OrdinalIgnoreCase)
        {
            { "AES", (text, pwd, iter) => { AESStringCrypt.Iterations = iter; return AESStringCrypt.Encrypt(text, pwd); } },
            { "AES-GCM", (text, pwd, iter) => { AESGCMStringCrypt.Iterations = iter; return AESGCMStringCrypt.Encrypt(text, pwd); } },
            { "SERPENT", (text, pwd, iter) => { SerpentStringCrypt.Iterations = iter; return SerpentStringCrypt.Encrypt(text, pwd); } },
            { "TWOFISH", (text, pwd, iter) => { TwofishStringCrypt.Iterations = iter; return TwofishStringCrypt.Encrypt(text, pwd); } },
            { "THREEFISH", (text, pwd, iter) => { ThreeFishStringCrypt.Iterations = iter; return ThreeFishStringCrypt.Encrypt(text, pwd); } },
            { "XCHACHA20", (text, pwd, iter) => { XChaCha20StringCrypt.Iterations = iter; return XChaCha20StringCrypt.Encrypt(text, pwd); } },
            { "XCHACHA20POLY1305", (text, pwd, iter) => { XChaCha20Poly1305StringCrypt.Iterations = iter; return XChaCha20Poly1305StringCrypt.Encrypt(text, pwd); } },
        };

            _decryptMap = new Dictionary<string, Func<byte[], byte[], int, byte[]>>(StringComparer.OrdinalIgnoreCase)
        {
            { "AES", (text, pwd, iter) => { AESStringCrypt.Iterations = iter; return AESStringCrypt.Decrypt(text, pwd); } },
            { "AES-GCM", (text, pwd, iter) => { AESGCMStringCrypt.Iterations = iter; return AESGCMStringCrypt.Decrypt(text, pwd); } },
            { "SERPENT", (text, pwd, iter) => { SerpentStringCrypt.Iterations = iter; return SerpentStringCrypt.Decrypt(text, pwd); } },
            { "TWOFISH", (text, pwd, iter) => { TwofishStringCrypt.Iterations = iter; return TwofishStringCrypt.Decrypt(text, pwd); } },
            { "THREEFISH", (text, pwd, iter) => { ThreeFishStringCrypt.Iterations = iter; return ThreeFishStringCrypt.Decrypt(text, pwd); } },
            { "XCHACHA20", (text, pwd, iter) => { XChaCha20StringCrypt.Iterations = iter; return XChaCha20StringCrypt.Decrypt(text, pwd); } },
            { "XCHACHA20POLY1305", (text, pwd, iter) => { XChaCha20Poly1305StringCrypt.Iterations = iter; return XChaCha20Poly1305StringCrypt.Decrypt(text, pwd); } },
        };
        }
        public byte[] Encrypt(string engine, byte[] plaintext, byte[] password, int iterations = 100000)
        {
            if (!_encryptMap.TryGetValue(engine, out var encryptFunc))
                throw new ArgumentOutOfRangeException(nameof(engine), $"Unsupported cryptographic engine: {engine}");

            // Enforce the execution baseline inside a synchronized block to prevent race conditions on static properties
            lock (SyncLock)
            {
                return encryptFunc(plaintext, password, SanitizeIterations(iterations));
            }
        }
        public byte[] Decrypt(string engine, byte[] ciphertext, byte[] password, int iterations = 100000)
        {
            if (!_decryptMap.TryGetValue(engine, out var decryptFunc))
                throw new ArgumentOutOfRangeException(nameof(engine), $"Unsupported cryptographic engine: {engine}");

            // Thread-safe isolation for stateful properties during simultaneous decryption sequences
            lock (SyncLock)
            {
                return decryptFunc(ciphertext, password, iterations);
            }
        }

        /// <summary>
        /// Enforces security baselines by preventing low iteration counts.
        /// </summary>
        /// <param name="iterations">The requested number of PBKDF2 rounds.</param>
        /// <returns>A secure iteration count, defaulting to 100000 if the input falls below the threshold.</returns>
        private static int SanitizeIterations(int iterations)
        {
            return iterations < 100000 ? 100000 : iterations;
        }
    }
}