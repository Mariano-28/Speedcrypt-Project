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
using Org.BouncyCastle.Security;

namespace Speedcrypt.SALT
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SystemEntropyProvider: Cryptographically secure entropy source provider.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the
    /// cryptographic primitives and entropy generation subsystem.
    ///
    /// Purpose:
    /// - Provide a reliable source of cryptographically secure random data.
    /// - Generate entropy suitable for keys, salts, nonces, and internal operations.
    /// - Ensure thread-safe access to the underlying CSPRNG.
    /// - Minimize exposure of sensitive data in memory.
    ///
    /// Design notes:
    /// - Based on BouncyCastle SecureRandom as CSPRNG.
    /// - All access to the random generator is synchronized for thread safety.
    /// - Generated buffers are explicitly cleared when no longer needed.
    /// - Output methods provide raw entropy without interpretation or bias.
    ///
    /// Security scope and limits:
    /// - Provides high-quality entropy suitable for cryptographic use.
    /// - Relies on the security guarantees of the underlying CSPRNG implementation.
    /// - Does not attempt to implement custom randomness algorithms.
    /// - Proper usage is required to maintain overall system security.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class SystemEntropyProvider
    {
        private readonly SecureRandom _secureRandom; // BouncyCastle CSPRNG
        private readonly object _lock = new object(); // Thread safety

        public SystemEntropyProvider()
        {
            _secureRandom = new SecureRandom();
        }

        /// <summary>
        /// Generates a secure random byte array of specified length.
        /// </summary>
        public byte[] GetEntropy(int length)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");

            byte[] buffer = new byte[length];
            lock (_lock)
            {
                _secureRandom.NextBytes(buffer);
            }
            return buffer;
        }

        /// <summary>
        /// Generates a secure random 32-bit integer.
        /// </summary>
        public int GetInt()
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
        /// Generates a secure random 64-bit double in [0,1).
        /// </summary>
        public double GetDouble()
        {
            byte[] buffer = new byte[8];
            lock (_lock)
            {
                _secureRandom.NextBytes(buffer);
            }
            ulong randUInt64 = BitConverter.ToUInt64(buffer, 0);
            ClearBytes(buffer);
            return randUInt64 / ((double)ulong.MaxValue + 1.0);
        }

        /// <summary>
        /// Clears sensitive data from memory.
        /// </summary>
        private static void ClearBytes(byte[] buffer)
        {
            if (buffer == null) return;
            for (int i = 0; i < buffer.Length; i++)
                buffer[i] = 0;
        }
    }
}