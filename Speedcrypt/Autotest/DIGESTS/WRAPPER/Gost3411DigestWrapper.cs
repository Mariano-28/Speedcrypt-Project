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

using Org.BouncyCastle.Crypto.Digests;

namespace Speedcrypt.Autotest.DIGESTS.WRAPPER
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Gost3411DigestWrapper: Wrapper class for the original Gost3411Digest algorithm.
    /// Provides a simplified interface conforming to IDigest for use in Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct initialization and usage of the Gost3411Digest
    /// - Validation of input parameters to prevent null or out-of-range errors
    /// - Full support for incremental updates, finalization, reset, and copy
    /// - Conforms to the standard IDigest interface
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public sealed class Gost3411DigestWrapper : IDigest
    {
        private readonly Gost3411Digest _digest;
        public Gost3411DigestWrapper()
        {
            _digest = new Gost3411Digest();
        }
        public Gost3411DigestWrapper(Gost3411Digest digest)
        {
            _digest = digest ?? throw new ArgumentNullException(nameof(digest));
        }
        public string AlgorithmName
        {
            get { return _digest.AlgorithmName; }
        }
        public int GetDigestSize()
        {
            return _digest.GetDigestSize();
        }
        public void Update(byte input)
        {
            _digest.Update(input);
        }
        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            if (inOff < 0 || length < 0 || (inOff + length > input.Length))
                throw new ArgumentOutOfRangeException();

            _digest.BlockUpdate(input, inOff, length);
        }
        public int DoFinal(byte[] output, int outOff)
        {
            if (output == null)
                throw new ArgumentNullException(nameof(output));

            if (outOff < 0 || (outOff + GetDigestSize() > output.Length))
                throw new ArgumentOutOfRangeException();

            return _digest.DoFinal(output, outOff);
        }
        public void Reset()
        {
            _digest.Reset();
        }
        public int GetByteLength()
        {
            return _digest.GetByteLength();
        }
        public IDigest Copy()
        {
            return new Gost3411DigestWrapper(new Gost3411Digest(_digest));
        }
    }
}