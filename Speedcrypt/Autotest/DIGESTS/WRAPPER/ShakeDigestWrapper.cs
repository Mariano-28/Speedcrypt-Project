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

namespace Speedcrypt.Autotest.DIGESTS.WRAPPER
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ShakeDigestWrapper: Wrapper class for the SHAKE (Extendable-Output Function) digest algorithm.
    /// Provides a simplified interface conforming to IDigest for use in Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct initialization and usage of the ShakeDigest with variable bit length
    /// - Full support for incremental updates, finalization, and reset
    /// - Provides a custom Output method to generate variable-length digest data
    /// - Supports cloning of the digest wrapper
    /// - Optional Span/ReadOnlySpan support where available
    /// - Conforms to the standard IDigest interface
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class ShakeDigestWrapper : IDigest
    {
        private Org.BouncyCastle.Crypto.Digests.ShakeDigest _digest;

        public ShakeDigestWrapper(int bitLength)
        {
            _digest = new Org.BouncyCastle.Crypto.Digests.ShakeDigest(bitLength);
        }
        public string AlgorithmName => _digest.AlgorithmName;
        public int GetDigestSize() => _digest.GetDigestSize();
        public int GetByteLength() => _digest.GetByteLength();
        public void Update(byte input) => _digest.Update(input);
        public void BlockUpdate(byte[] input, int inOff, int inLen) => _digest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public void BlockUpdate(System.ReadOnlySpan<byte> input) => _digest.BlockUpdate(input);
#endif
        public int DoFinal(byte[] output, int outOff)
        {
            return _digest.DoFinal(output, outOff);
        }
        public void Reset() => _digest.Reset();

        // Custom method to output variable-length data for SHAKE
        public void Output(byte[] output, int outOff, int outLen)
        {
            byte[] buffer = new byte[_digest.GetDigestSize()];
            int generated = 0;
            while (generated < outLen)
            {
                int n = _digest.DoFinal(buffer, 0);
                int copyLen = Math.Min(n, outLen - generated);
                Array.Copy(buffer, 0, output, outOff + generated, copyLen);
                generated += copyLen;
                _digest.Reset(); // reset to continue XOF output
                _digest.BlockUpdate(buffer, 0, n); // feed back last block
            }
        }
        public ShakeDigestWrapper Clone()
        {
            return new ShakeDigestWrapper(_digest.GetDigestSize() * 8);
        }
    }
}