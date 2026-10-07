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
    /// RipeMD320DigestWrapper: Wrapper class for the RipeMD320 digest algorithm.
    /// Provides a simplified interface conforming to IDigest for use in Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct initialization and usage of the RipeMD320 digest
    /// - Support for cloning an existing RipeMD320DigestWrapper instance
    /// - Full support for incremental updates, finalization, and reset
    /// - Optional Span/ReadOnlySpan support where available
    /// - Conforms to the standard IDigest interface
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class RipeMD320DigestWrapper : IDigest
    {
        private readonly RipeMD320Digest _digest;

        // Default constructor
        public RipeMD320DigestWrapper()
        {
            _digest = new RipeMD320Digest();
        }

        // Copy constructor
        public RipeMD320DigestWrapper(RipeMD320DigestWrapper other)
        {
            _digest = new RipeMD320Digest(other._digest);
        }
        public string AlgorithmName => _digest.AlgorithmName;
        public int GetDigestSize() => _digest.GetDigestSize();
        public int GetByteLength() => _digest.GetByteLength();
        public void Update(byte input) => _digest.Update(input);
        public void BlockUpdate(byte[] input, int inOff, int inLen) => _digest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public void BlockUpdate(System.ReadOnlySpan<byte> input) => _digest.BlockUpdate(input);
#endif
        public int DoFinal(byte[] output, int outOff) => _digest.DoFinal(output, outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public int DoFinal(System.Span<byte> output) => _digest.DoFinal(output);
#endif
        public void Reset() => _digest.Reset();
    }
}