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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Macs;
using BC = Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Autotest.DIGESTS.PBKDF2
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Pkcs5S2ParametersGenerator: Implements the PKCS #5 v2.0 Scheme 2 PBKDF2 key derivation function.
    /// Uses HMAC-SHA1 as the underlying pseudorandom function to generate derived keys and IVs.
    /// Designed for Speedcrypt framework with centralized logging of exceptions when used in tests.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct derivation of keys and IVs according to PKCS #5 v2.0 (PBKDF2) specification
    /// - Supports generation of key-only, key with IV, and MAC parameters
    /// - Handles arbitrary iteration counts and salts
    /// - Can be used as a reliable component in Speedcrypt self-tests and cryptographic operations
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class Pkcs5S2ParametersGenerator : PbeParametersGenerator
    {
        private readonly IMac hMac;
        private readonly byte[] state;

        // Default constructor: HMAC-SHA1
        public Pkcs5S2ParametersGenerator()
            : this(new Org.BouncyCastle.Crypto.Digests.Sha1Digest())
        {
        }
        public Pkcs5S2ParametersGenerator(BC.IDigest digest)
        {
            hMac = new HMac(digest);
            state = new byte[hMac.GetMacSize()];
        }
        private void F(byte[] S, int c, byte[] iBuf, byte[] outBytes, int outOff)
        {
            if (c <= 0)
                throw new ArgumentException("Iteration count must be >= 1");

            KeyParameter param = new KeyParameter(mPassword);

            hMac.Init(param);

            if (S != null)
                hMac.BlockUpdate(S, 0, S.Length);

            hMac.BlockUpdate(iBuf, 0, iBuf.Length);
            hMac.DoFinal(state, 0);

            Array.Copy(state, 0, outBytes, outOff, state.Length);

            for (int j = 1; j < c; j++)
            {
                hMac.Init(param); // reinit HMAC every iteration
                hMac.BlockUpdate(state, 0, state.Length);
                hMac.DoFinal(state, 0);

                for (int k = 0; k < state.Length; k++)
                    outBytes[outOff + k] ^= state[k];
            }
        }
        private byte[] GenerateDerivedKey(int dkLen)
        {
            int hLen = hMac.GetMacSize();
            int l = (dkLen + hLen - 1) / hLen;
            byte[] outBytes = new byte[l * hLen];
            byte[] iBuf = new byte[4];
            int outPos = 0;

            for (int i = 1; i <= l; i++)
            {
                // big-endian block index
                iBuf[0] = (byte)((i >> 24) & 0xff);
                iBuf[1] = (byte)((i >> 16) & 0xff);
                iBuf[2] = (byte)((i >> 8) & 0xff);
                iBuf[3] = (byte)(i & 0xff);

                F(mSalt, mIterationCount, iBuf, outBytes, outPos);
                outPos += hLen;
            }

            byte[] dk = new byte[dkLen];
            Array.Copy(outBytes, 0, dk, 0, dkLen);
            return dk;
        }
        public override ICipherParameters GenerateDerivedParameters(string algorithm, int keySize)
        {
            byte[] dKey = GenerateDerivedKey(keySize / 8);
            return ParameterUtilities.CreateKeyParameter(algorithm, dKey, 0, dKey.Length);
        }
        public override ICipherParameters GenerateDerivedParameters(string algorithm, int keySize, int ivSize)
        {
            byte[] dKey = GenerateDerivedKey((keySize + ivSize) / 8);
            KeyParameter key = ParameterUtilities.CreateKeyParameter(algorithm, dKey, 0, keySize / 8);
            return new ParametersWithIV(key, dKey, keySize / 8, ivSize / 8);
        }
        public override ICipherParameters GenerateDerivedMacParameters(int keySize)
        {
            byte[] dKey = GenerateDerivedKey(keySize / 8);
            return new KeyParameter(dKey, 0, dKey.Length);
        }
    }
}