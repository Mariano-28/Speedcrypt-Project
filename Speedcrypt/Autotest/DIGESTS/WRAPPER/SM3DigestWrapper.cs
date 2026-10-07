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

namespace Speedcrypt.Autotest.DIGESTS.WRAPPER
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SM3DigestWrapper: Wrapper class for the SM3 digest algorithm.
    /// Provides a standard interface conforming to IDigest for use in Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Proper initialization and usage of the SM3 digest
    /// - Full support for incremental updates, finalization, and reset
    /// - Optional ReadOnlySpan support for modern .NET versions
    /// - DoFinal resets the internal digest automatically after computing the output
    /// - Conforms to the standard IDigest interface
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    internal class SM3DigestWrapper : IDigest
    {
        private readonly Org.BouncyCastle.Crypto.Digests.SM3Digest _sm3;

        public SM3DigestWrapper()
        {
            _sm3 = new Org.BouncyCastle.Crypto.Digests.SM3Digest();
        }
        public string AlgorithmName => _sm3.AlgorithmName;
        public int GetDigestSize() => _sm3.GetDigestSize();
        public int GetByteLength() => _sm3.GetByteLength();
        public void Update(byte input) => _sm3.Update(input);
        public void BlockUpdate(byte[] input, int inOff, int inLen) => _sm3.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public void BlockUpdate(ReadOnlySpan<byte> input)
    {
        foreach (byte b in input)
        {
            _sm3.Update(b);
        }
    }
#endif
        public int DoFinal(byte[] output, int outOff)
        {
            int len = _sm3.DoFinal(output, outOff);
            _sm3.Reset();
            return len;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
    public int DoFinal(Span<byte> output)
    {
        byte[] temp = output.ToArray();
        int len = _sm3.DoFinal(temp, 0);
        temp.CopyTo(output);
        _sm3.Reset();
        return len;
    }
#endif
        public void Reset() => _sm3.Reset();
    }
}