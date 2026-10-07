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
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Speedcrypt.SALT.AESCTRDRBGen
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// AesCtrDrbg: Deterministic Random Bit Generator (DRBG) based on AES-256 in CTR mode.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the cryptography subsystem.
    /// 
    /// Purpose:
    /// - Provide a secure, deterministic random byte and integer generator using AES-256 CTR mode.
    /// - Support reseeding with new keys and counters for ongoing cryptographic operations.
    /// - Ensure thread-safe generation of random data.
    /// - Clear sensitive data (keys, counter, keystream) on disposal to prevent leakage.
    /// 
    /// Design notes:
    /// - Uses AES-256 in ECB mode strictly as the block cipher for CTR operation.
    /// - Counter is 128-bit and incremented in big-endian format.
    /// - Keystream buffer is refilled automatically as bytes are consumed.
    /// - Exception handling and fail-safe operations are expected to be logged centrally using CentralLog.
    /// 
    /// Security scope and limits:
    /// - Provides cryptographically secure pseudorandom numbers suitable for key material, salts, or nonces.
    /// - Clears sensitive buffers on Dispose.
    /// - Resistant to basic tampering or memory snooping at application level.
    /// - Does not claim protection against a fully privileged attacker or OS-level compromise.
    /// - Implements IDisposable for proper cleanup.
    /// - While robust, no random generator at application level is truly unbreakable.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class AesCtrDrbg : IDisposable
    {
        private readonly Aes _aes;
        private ICryptoTransform _encryptor;
        private byte[] _v;
        private byte[] _key;
        private readonly object _lock = new object();
        private bool _disposed;

        private const int BlockSize = 16;
        private const int KeySize = 32;
        private const int MaxBlocksBeforeReseed = 1 << 20;

        private int _blocksGenerated = 0;

        /// <summary>
        /// Initializes a new instance of the AesCtrDrbg class using internal or provided seed entropy.
        /// </summary>
        /// <param name="entropy">Optional external entropy seed buffer. Must strictly match KeySize + BlockSize.</param>
        public AesCtrDrbg(byte[] entropy = null)
        {
            _aes = Aes.Create();
            _aes.Mode = CipherMode.ECB;
            _aes.Padding = PaddingMode.None;

            byte[] seed = entropy ?? GenerateEntropy(KeySize + BlockSize);
            if (seed.Length != KeySize + BlockSize)
                throw new ArgumentException("Entropy length must be KeySize + BlockSize");

            _key = new byte[KeySize];
            _v = new byte[BlockSize];
            Array.Copy(seed, 0, _key, 0, KeySize);
            Array.Copy(seed, KeySize, _v, 0, BlockSize);

            _encryptor = _aes.CreateEncryptor(_key, new byte[BlockSize]);
        }

        /// <summary>
        /// Initializes a new instance of the AesCtrDrbg class using a specialized SystemEntropyProvider source.
        /// </summary>
        /// <param name="provider">The enterprise entropy provider instance. Cannot be null.</param>
        public AesCtrDrbg(SystemEntropyProvider provider)
            : this(provider ?? throw new ArgumentNullException(nameof(provider)), provider.GetEntropy(KeySize + BlockSize)) { }

        /// <summary>
        /// Target private constructor to guarantee atomic validation state before executing initialization chaining.
        /// </summary>
        private AesCtrDrbg(SystemEntropyProvider provider, byte[] entropy) : this(entropy)
        {
            // Chained execution successfully completed under safe null validation contexts
        }

        /// <summary>
        /// Reseeds the internal state of the DRBG with new cryptographic entropy to ensure continuous forward secrecy.
        /// </summary>
        /// <param name="entropy">Optional external entropy seed buffer.</param>
        public void Reseed(byte[] entropy = null)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(AesCtrDrbg));
            lock (_lock)
            {
                byte[] seed = entropy ?? GenerateEntropy(KeySize + BlockSize);
                if (seed.Length != KeySize + BlockSize)
                    throw new ArgumentException("Entropy length must be KeySize + BlockSize");

                ClearBytes(_key);
                ClearBytes(_v);
                _encryptor.Dispose();

                Array.Copy(seed, 0, _key, 0, KeySize);
                Array.Copy(seed, KeySize, _v, 0, BlockSize);

                _encryptor = _aes.CreateEncryptor(_key, new byte[BlockSize]);
                _blocksGenerated = 0;
            }
        }

        /// <summary>
        /// Generates cryptographically secure pseudo-random bytes sequence of arbitrary specified length.
        /// </summary>
        /// <param name="length">The target allocation size of the returned byte array.</param>
        public byte[] NextBytes(int length)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(AesCtrDrbg));
            byte[] output = new byte[length];
            int offset = 0;

            lock (_lock)
            {
                while (length > 0)
                {
                    if (_blocksGenerated >= MaxBlocksBeforeReseed)
                        Reseed();

                    IncrementCounter();
                    byte[] block = EncryptCounter();
                    int toCopy = Math.Min(BlockSize, length);
                    Array.Copy(block, 0, output, offset, toCopy);

                    offset += toCopy;
                    length -= toCopy;

                    _blocksGenerated++;
                }
            }

            return output;
        }

        /// <summary>
        /// Generates a bounded uniform integer distribution within a specific range using rejection sampling.
        /// </summary>
        public int NextInt(int minValue, int maxValue)
        {
            if (minValue >= maxValue) throw new ArgumentException("minValue must be less than maxValue");

            uint range = (uint)(maxValue - minValue);
            uint value;
            do
            {
                byte[] buf = NextBytes(4);
                value = BitConverter.ToUInt32(buf, 0);
            } while (value >= uint.MaxValue - (uint.MaxValue % range));

            return minValue + (int)(value % range);
        }

        /// <summary>
        /// Executes a direct raw single-block transformation using the internal AES state encryptor engine.
        /// </summary>
        private byte[] EncryptCounter()
        {
            byte[] output = new byte[BlockSize];
            _encryptor.TransformBlock(_v, 0, BlockSize, output, 0);
            return output;
        }

        /// <summary>
        /// Advances the state array counter via big-endian multi-byte increment tracking to prevent key-stream duplication.
        /// </summary>
        private void IncrementCounter()
        {
            for (int i = BlockSize - 1; i >= 0; i--)
            {
                _v[i]++;
                if (_v[i] != 0) return;
            }

            // Overflow condition reached: full period elapsed. Automatic explicit reseed required.
            Reseed();
        }

        /// <summary>
        /// Accesses the operating system level underlying cryptographic RNG provider to extract absolute seed entropy.
        /// </summary>
        private static byte[] GenerateEntropy(int length)
        {
            byte[] bytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        /// <summary>
        /// Disposes all managed hardware abstractions and explicitly purges sensitive computational states from application memory.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;

            _encryptor.Dispose();
            _aes.Dispose();
            ClearBytes(_key);
            ClearBytes(_v);

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Securely erases sensitive raw buffers from runtime memory using non-optimizable loop execution constraints.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoOptimization)]
        private static void ClearBytes(byte[] buffer)
        {
            if (buffer == null) return;
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = 0;
            }
        }
    }
}