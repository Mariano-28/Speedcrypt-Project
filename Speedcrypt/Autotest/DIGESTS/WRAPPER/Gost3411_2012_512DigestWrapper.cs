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
    /// Gost3411_2012_512DigestWrapper: Wrapper class for the GOST3411-2012-512 digest algorithm.
    /// Provides a simplified interface conforming to IDigest for use in Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct initialization and usage of the GOST3411-2012-512 digest
    /// - Support for creating a new digest or wrapping an existing instance
    /// - Full support for incremental updates, finalization, reset, and copy
    /// - Access to the internal digest instance if needed
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class Gost3411_2012_512DigestWrapper : IDigest
    {
        private readonly Gost3411_2012_512Digest gost;

        public Gost3411_2012_512DigestWrapper()
        {
            gost = new Gost3411_2012_512Digest();
        }
        public Gost3411_2012_512DigestWrapper(Gost3411_2012_512Digest existing)
        {
            gost = new Gost3411_2012_512Digest(existing);
        }
        public string AlgorithmName
        {
            get { return "GOST3411-2012-512"; }
        }
        public int GetDigestSize()
        {
            return gost.GetDigestSize();
        }
        public void Update(byte input)
        {
            gost.Update(input);
        }
        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            gost.BlockUpdate(input, inOff, length);
        }
        public int DoFinal(byte[] output, int outOff)
        {
            return gost.DoFinal(output, outOff);
        }
        public void Reset()
        {
            gost.Reset();
        }
        public IDigest Copy()
        {
            return new Gost3411_2012_512DigestWrapper(new Gost3411_2012_512Digest(gost));
        }
        public int GetByteLength()
        {
            return gost.GetByteLength();
        }
        public IDigest GetInternalDigest()
        {
            return (IDigest)gost;
        }
    }
}