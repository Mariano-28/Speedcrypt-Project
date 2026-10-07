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

using Org.BouncyCastle.Crypto.Digests;

namespace Speedcrypt.Autotest.DIGESTS.WRAPPER
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Blake2sDigestWrapper: Wrapper class for the Blake2s digest algorithm.
    /// Provides a simplified interface conforming to IDigest for use in Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct initialization and usage of the Blake2s digest with specified bit length
    /// - Full support for incremental updates and finalization
    /// - Compatibility with standard IDigest interface methods
    /// - Optional support for Span/ReadOnlySpan where supported
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class Blake2sDigestWrapper : IDigest
    {
        private readonly Blake2sDigest digest;
        public Blake2sDigestWrapper(int bitLength)
        {
            digest = new Blake2sDigest(bitLength);
        }
        public string AlgorithmName => digest.AlgorithmName;
        public int GetDigestSize() => digest.GetDigestSize();
        public int GetByteLength() => digest.GetByteLength();
        public void Update(byte input) => digest.Update(input);
        public void BlockUpdate(byte[] input, int inOff, int inLen) => digest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public void BlockUpdate(ReadOnlySpan<byte> input) => digest.BlockUpdate(input);
#endif
        public int DoFinal(byte[] output, int outOff) => digest.DoFinal(output, outOff);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public int DoFinal(Span<byte> output) => digest.DoFinal(output);
#endif
        public void Reset() => digest.Reset();
    }
}