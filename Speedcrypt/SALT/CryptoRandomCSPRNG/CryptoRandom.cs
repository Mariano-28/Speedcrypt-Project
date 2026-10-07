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
// https://www.gnu.org/licenses/gpl-3.0.html

using System;
using System.Text;
using System.Runtime.CompilerServices;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Digests;

namespace Speedcrypt.SALT.CryptoRandomCSPRNG
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// CryptoRandom: Simple cryptographically secure random number generator wrapper.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the SALT / random utility subsystem.
    ///
    /// Purpose:
    /// - Provide a convenient, application‑friendly interface to generate cryptographically secure
    ///   random values using a SecureRandom source.
    /// - Support generation of positive random integers, random byte arrays of arbitrary length,
    ///   random doubles in [0.0, 1.0) with unbiased 53‑bit precision, and random hexadecimal strings.
    ///
    /// Design notes:
    /// - SecureRandom is the underlying cryptographically secure source (BouncyCastle implementation).
    /// - This wrapper does NOT introduce its own entropy source; it relies on SecureRandom’s
    ///   cryptographically strong output.
    /// - All public generation methods check validity of arguments and throw appropriate exceptions
    ///   for misuse.
    ///
    /// Security scope and limits:
    /// - Outputs cryptographically secure pseudorandom values suitable for salts, nonces, tokens,
    ///   and random values where unpredictability is required.
    /// - Does NOT provide deterministic behavior — SecureRandom’s internal state and seed are
    ///   not exposed or controlled externally.
    /// - Does NOT claim resistance against fully privileged attackers or OS‑level compromise.
    /// - It does everything reasonably achievable at application level within the project’s scope.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class CryptoRandom
    {
        private readonly SecureRandom _secureRandom;
        private readonly object _lock = new object();

        /// <summary>
        /// Initializes a new instance of the CryptoRandom class using the default implicit OS secure random source.
        /// </summary>
        public CryptoRandom()
        {
            _secureRandom = new SecureRandom();
        }

        /// <summary>
        /// Initializes a new instance of the CryptoRandom class conditioned with seed entropy from an external enterprise provider.
        /// </summary>
        /// <param name="entropyProvider">The external enterprise entropy validation provider. Cannot be null.</param>
        public CryptoRandom(SystemEntropyProvider entropyProvider)
        {
            if (entropyProvider == null)
                throw new ArgumentNullException(nameof(entropyProvider));

            byte[] seed = entropyProvider.GetEntropy(32);

            var digest = new DigestRandomGenerator(new Sha256Digest());
            digest.AddSeedMaterial(seed);
            _secureRandom = new SecureRandom(digest);

            ClearBytes(seed);
        }

        /// <summary>
        /// Generates a non-negative cryptographically secure 31-bit integer.
        /// </summary>
        public int NextInt()
        {
            byte[] buffer = new byte[4];
            lock (_lock)
            {
                _secureRandom.NextBytes(buffer);
            }
            int value = BitConverter.ToInt32(buffer, 0) & int.MaxValue;
            ClearBytes(buffer);
            return value;
        }

        /// <summary>
        /// Fills an allocated destination array with a cryptographically strong sequence of random bytes.
        /// </summary>
        public byte[] NextBytes(int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length cannot be negative.");

            byte[] data = new byte[length];
            lock (_lock)
            {
                _secureRandom.NextBytes(data);
            }
            return data;
        }

        /// <summary>
        /// Generates a random double-precision floating-point number greater than or equal to 0.0, and less than 1.0 without IEEE 754 truncation bias.
        /// </summary>
        public double NextDouble()
        {
            byte[] buffer8 = new byte[8];
            lock (_lock)
            {
                _secureRandom.NextBytes(buffer8);
            }
            ulong randUInt64 = BitConverter.ToUInt64(buffer8, 0);
            ClearBytes(buffer8);

            // Standard 53-bit mask formatting to fit IEEE 754 mantissa limitations and eliminate structural alignment bias
            ulong mask53Bits = randUInt64 >> 11;
            return mask53Bits / (double)(1UL << 53);
        }

        /// <summary>
        /// Generates a structured cryptographic hex string token representation.
        /// </summary>
        public string NextHexString(int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length cannot be negative.");
            if (length % 2 != 0)
                throw new ArgumentException("Length must be even to represent full bytes.", nameof(length));

            int byteLength = length / 2;
            byte[] bytes = NextBytes(byteLength);

            // Use StringBuilder to reduce transient memory footprints during allocation phases
            StringBuilder hexBuilder = new StringBuilder(length);
            for (int i = 0; i < bytes.Length; i++)
            {
                hexBuilder.Append(bytes[i].ToString("X2"));
            }

            ClearBytes(bytes);
            return hexBuilder.ToString();
        }

        /// <summary>
        /// Enforces rigorous localized buffer zeroization by restricting runtime JIT compiler optimizations.
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