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
using System.Text;
using System.Runtime.CompilerServices;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Speedcrypt.SALT.BBS
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// BlumBlumShub: Cryptographically secure pseudorandom number generator (BBS algorithm).
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the SALT and cryptography subsystem.
    ///
    /// Purpose:
    /// - Generate strong pseudorandom bits, bytes, and numbers using the Blum-Blum-Shub (BBS) algorithm.
    /// - Ensure cryptographic security based on quadratic residues modulo N = p * q.
    /// - Provide reliable initialization with primes congruent to 3 mod 4.
    /// - Support secure SALT generation and key material derivation.
    /// 
    /// Design notes:
    /// - Outputs only the least significant bit (LSB) of the internal state for security.
    /// - Internal state (_x) is always coprime with modulus N.
    /// - Generates primes and seeds using a cryptographically secure source.
    /// - All operations are fail-safe and suitable for integration with central logging of exceptions.
    /// 
    /// Security scope and limits:
    /// - Suitable for cryptographic SALT generation and pseudorandom number derivation.
    /// - Resistant to casual tampering or observation at application level.
    /// - Does not claim resistance to a fully privileged OS-level attacker.
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    /// <summary>
    /// Blum Blum Shub PRNG fully secure for Speedcrypt, using BouncyCastle.
    /// Default modulus 2048-bit, optional reseed for long-running sessions, fully thread-safe.
    /// Supports external reseed for added entropy.
    /// </summary>       
    public class BlumBlumShub
    {
        private readonly BigInteger _N;
        private BigInteger _x;
        private readonly SecureRandom _random;
        private readonly object _lock = new object();
        private int _bitsGeneratedSinceReseed = 0;
        private const int BitsBeforeReseed = 65536; // Optimized threshold to balance security and modular exponentiation performance

        private readonly SystemEntropyProvider _entropyProvider;
        public BlumBlumShub(int bitLength = 2048, SystemEntropyProvider entropyProvider = null)
        {
            if (bitLength < 1024)
                throw new ArgumentException("Bit length must be at least 1024 for security.");

            _entropyProvider = entropyProvider;
            _random = new SecureRandom();

            BigInteger p = GeneratePrime(bitLength / 2);
            BigInteger q;
            do { q = GeneratePrime(bitLength / 2); } while (q.Equals(p));

            _N = p.Multiply(q);
            _x = GenerateInitialState(_N);

            if (_entropyProvider != null)
            {
                // Execute initial synchronized state injection
                lock (_lock)
                {
                    ExecuteExternalReseed();
                }
            }
        }
        private BigInteger GeneratePrime(int bitLength)
        {
            BigInteger prime;
            do
            {
                prime = new BigInteger(bitLength, 100, _random);
            } while (!prime.Mod(BigInteger.ValueOf(4)).Equals(BigInteger.ValueOf(3)));
            return prime;
        }
        private BigInteger GenerateInitialState(BigInteger N)
        {
            BigInteger x0;
            do
            {
                x0 = new BigInteger(N.BitLength - 1, _random).Add(BigInteger.Two);
            } while (!x0.Gcd(N).Equals(BigInteger.One));
            return x0;
        }

        /// <summary>
        /// Performs internal core reseed processing. Must be invoked exclusively within an active thread-safe lock context.
        /// </summary>
        private void ExecuteExternalReseed()
        {
            if (_entropyProvider == null) return;

            byte[] entropyBytes = _entropyProvider.GetEntropy((_N.BitLength + 7) / 8);
            BigInteger externalSeed = new BigInteger(1, entropyBytes);

            _x = _x.Add(externalSeed).Mod(_N);
            _bitsGeneratedSinceReseed = 0;

            ClearBytes(entropyBytes);
        }

        /// <summary>
        /// Evaluates generator health lifecycle parameters and forces state shifting if reseed boundaries are breached.
        /// </summary>
        private void ReseedIfNeeded()
        {
            if (_bitsGeneratedSinceReseed >= BitsBeforeReseed)
            {
                if (_entropyProvider != null)
                    ExecuteExternalReseed();
                else
                    _x = GenerateInitialState(_N);

                _bitsGeneratedSinceReseed = 0;
            }
        }

        /// <summary>
        /// Extracts the next single pseudorandom bit using core Blum-Blum-Shub modular squaring iteration. Thread-safe execution.
        /// </summary>
        public bool GenerateNextBit()
        {
            lock (_lock)
            {
                _x = _x.Multiply(_x).Mod(_N);
                _bitsGeneratedSinceReseed++;
                ReseedIfNeeded();
                return _x.TestBit(0);
            }
        }
        private byte GenerateNextByte()
        {
            byte result = 0;
            for (int i = 0; i < 8; i++)
            {
                if (GenerateNextBit())
                    result |= (byte)(1 << (7 - i));
            }
            return result;
        }

        /// <summary>
        /// Populates an allocated buffer array with cryptographically strong pseudorandom bytes.
        /// </summary>
        public byte[] GenerateRandomBytes(int length)
        {
            if (length <= 0) throw new ArgumentException("Length must be positive.");
            byte[] output = new byte[length];
            for (int i = 0; i < length; i++)
            {
                output[i] = GenerateNextByte();
            }
            return output;
        }

        /// <summary>
        /// Transmutes random binary distributions into formatted hexadecimal string tracking tokens.
        /// </summary>
        public string GenerateRandomHexSequence(int length)
        {
            byte[] bytes = GenerateRandomBytes(length);
            StringBuilder hex = new StringBuilder(length * 3);
            for (int i = 0; i < bytes.Length; i++)
            {
                hex.AppendFormat("{0:X2}", bytes[i]);
                if (i < bytes.Length - 1) hex.Append('-');
            }
            return hex.ToString();
        }

        /// <summary>
        /// Generates an arbitrary bit-length BigInteger value utilizing full uniform distribution boundaries.
        /// </summary>
        public BigInteger GenerateRandomNumber(int bitLength)
        {
            if (bitLength <= 0) throw new ArgumentException("Bit length must be positive.");
            BigInteger result = BigInteger.Zero;
            for (int i = 0; i < bitLength; i++)
            {
                if (GenerateNextBit())
                    result = result.SetBit(i);
            }
            return result;
        }
        public BigInteger Modulus => _N;

        /// <summary>
        /// Forces strict memory reclamation by purging localized state metadata buffers via non-optimizable constraints.
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