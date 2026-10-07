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

using Org.BouncyCastle.Crypto.Digests;

namespace Speedcrypt.Autotest.DIGESTS.WRAPPER
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// KeccakDigestWrapper: Wrapper class for the Keccak digest algorithm.
    /// Provides a simplified interface conforming to IDigest for use in Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct initialization and usage of Keccak digest with default or custom bit length
    /// - Support for cloning an existing KeccakDigest instance
    /// - Full support for incremental updates, finalization, and reset
    /// - Optional Span/ReadOnlySpan support where available
    /// - Access to the internal digest instance for advanced usage
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class KeccakDigestWrapper : IDigest
    {
        private readonly KeccakDigest digestInstance;

        // Constructor for default Keccak
        public KeccakDigestWrapper()
        {
            digestInstance = new KeccakDigest();
        }

        // Constructor for Keccak with specific bit length
        public KeccakDigestWrapper(int bitLength)
        {
            digestInstance = new KeccakDigest(bitLength);
        }

        // Constructor for cloning existing KeccakDigest
        public KeccakDigestWrapper(KeccakDigest existing)
        {
            digestInstance = new KeccakDigest(existing);
        }

        // The algorithm name
        public string AlgorithmName
        {
            get { return digestInstance.AlgorithmName; }
        }

        // Digest size in bytes
        public int GetDigestSize()
        {
            return digestInstance.GetDigestSize();
        }

        // Internal buffer size in bytes
        public int GetByteLength()
        {
            return digestInstance.GetByteLength();
        }

        // Update the digest with a single byte
        public void Update(byte input)
        {
            digestInstance.Update(input);
        }

        // Update the digest with a byte array
        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            digestInstance.BlockUpdate(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public void BlockUpdate(ReadOnlySpan<byte> input)
    {
        digestInstance.BlockUpdate(input);
    }
#endif

        // Compute the final digest value and reset
        public int DoFinal(byte[] output, int outOff)
        {
            return digestInstance.DoFinal(output, outOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public int DoFinal(Span<byte> output)
    {
        return digestInstance.DoFinal(output);
    }
#endif

        // Reset the digest to initial state
        public void Reset()
        {
            digestInstance.Reset();
        }

        // Expose underlying digest if needed for special cases
        public KeccakDigest InnerDigest
        {
            get { return digestInstance; }
        }
    }
}