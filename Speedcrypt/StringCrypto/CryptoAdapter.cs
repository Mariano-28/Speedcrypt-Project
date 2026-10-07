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

namespace Speedcrypt.StringCrypto
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CryptoAdapter: Central adapter for dispatching encryption and decryption
    /// operations across multiple cryptographic engines using a common ICryptoService interface.
    /// Supports configurable PBKDF2 iteration counts via delegate provider.
    /// Designed for Speedcrypt core to unify algorithm invocation and key derivation settings.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized abstraction layer for multiple encryption/decryption engines
    ///   (AES, AES-GCM, Serpent, Twofish, ThreeFish, XChaCha20, XChaCha20-Poly1305)
    /// - All PBKDF2 iteration counts are applied consistently before each encrypt/decrypt call
    ///   using an optional rounds provider delegate
    /// - Provides a coherent switch-based dispatch to engine-specific static cryptography classes
    /// - Enforces a minimal safe iteration limit to avoid weak key derivation configurations
    /// - Unsupported engines raise a defined InvalidOperationException
    ///
    /// Responsibility for this C# implementation, cryptographic design,
    /// integration, and validation lies entirely with the author.
    /// </remarks>
    public class CryptoAdapter : ICryptoService
    {
        private readonly Func<int> _roundsProvider;

        /// <summary>
        /// Constructor accepts optional rounds provider delegate.
        /// </summary>
        public CryptoAdapter(Func<int> roundsProvider = null)
        {
            _roundsProvider = roundsProvider;
        }

        /// <summary>
        /// Encrypts plaintext using selected engine and password.
        /// Applies PBKDF2 iteration count before encryption.
        /// </summary>
        public byte[] Encrypt(CryptoEngine engine, byte[] plaintext, byte[] password)
        {
            ApplyPBKDF2Rounds();

            switch (engine)
            {
                case CryptoEngine.AES:
                    return AESStringCrypt.Encrypt(plaintext, password);
                case CryptoEngine.AES_GCM:
                    return AESGCMStringCrypt.Encrypt(plaintext, password);
                case CryptoEngine.SERPENT:
                    return SerpentStringCrypt.Encrypt(plaintext, password);
                case CryptoEngine.TWOFISH:
                    return TwofishStringCrypt.Encrypt(plaintext, password);
                case CryptoEngine.THREEFISH:
                    return ThreeFishStringCrypt.Encrypt(plaintext, password);
                case CryptoEngine.XCHACHA20:
                    return XChaCha20StringCrypt.Encrypt(plaintext, password);
                case CryptoEngine.XCHACHA20POLY1305:
                    return XChaCha20Poly1305StringCrypt.Encrypt(plaintext, password);
                default:
                    throw new InvalidOperationException("Unsupported crypto engine.");
            }
        }

        /// <summary>
        /// Decrypts ciphertext using selected engine and password.
        /// Applies PBKDF2 iteration count before decryption.
        /// </summary>
        public byte[] Decrypt(CryptoEngine engine, byte[] ciphertext, byte[] password)
        {
            ApplyPBKDF2Rounds();

            switch (engine)
            {
                case CryptoEngine.AES:
                    return AESStringCrypt.Decrypt(ciphertext, password);
                case CryptoEngine.AES_GCM:
                    return AESGCMStringCrypt.Decrypt(ciphertext, password);
                case CryptoEngine.SERPENT:
                    return SerpentStringCrypt.Decrypt(ciphertext, password);
                case CryptoEngine.TWOFISH:
                    return TwofishStringCrypt.Decrypt(ciphertext, password);
                case CryptoEngine.THREEFISH:
                    return ThreeFishStringCrypt.Decrypt(ciphertext, password);
                case CryptoEngine.XCHACHA20:
                    return XChaCha20StringCrypt.Decrypt(ciphertext, password);
                case CryptoEngine.XCHACHA20POLY1305:
                    return XChaCha20Poly1305StringCrypt.Decrypt(ciphertext, password);
                default:
                    throw new InvalidOperationException("Unsupported crypto engine.");
            }
        }

        /// <summary>
        /// Applies PBKDF2 iteration count to all algorithms before encrypt/decrypt.
        /// </summary>
        private void ApplyPBKDF2Rounds()
        {
            int rounds = _roundsProvider?.Invoke() ?? 100000;
            if (rounds < 1000) rounds = 100000;

            AESStringCrypt.Iterations = rounds;
            AESGCMStringCrypt.Iterations = rounds;
            SerpentStringCrypt.Iterations = rounds;
            TwofishStringCrypt.Iterations = rounds;
            ThreeFishStringCrypt.Iterations = rounds;
            XChaCha20StringCrypt.Iterations = rounds;
            XChaCha20Poly1305StringCrypt.Iterations = rounds;
        }
    }
}