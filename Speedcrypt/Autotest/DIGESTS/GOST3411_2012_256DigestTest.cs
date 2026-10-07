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

// NUnit unit testing framework
using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Speedcrypt.Autotest.DIGESTS.WRAPPER;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// GOST3411_2012_256DigestTest: Unit test class for the GOST R 34.11‑2012 256‑bit digest.
    /// /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// <remarks>
    /// This test class provides:
    /// - Self‑validation of the GOST R 34.11‑2012 256‑bit message digest implementation
    ///   against known reference vectors
    /// - Verification of correct digest computation for multiple messages
    /// - HMAC test to ensure correct keyed hashing behavior
    ///
    /// Test vectors and test structure are conceptually analogous to the
    /// GOST3411_2012_256DigestTest class found in the Bouncy Castle Java crypto test suite
    /// (org.bouncycastle.crypto.test.GOST3411_2012_256DigestTest). :contentReference[oaicite:2]{index=2}
    ///
    /// The implementation intentionally avoids external unit test frameworks for core validation
    /// logic, in line with the Speedcrypt testing philosophy:
    /// - Explicit behavior
    /// - Deterministic results
    /// - Immediate failure on deviation
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class GOST3411_2012_256DigestTest : DigestTest
    {
        private static readonly byte[][] messageBytes;

        private static readonly byte[] M1 =
        {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32
    };

        private static readonly byte[] M2 =
        {
        0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2,
        0xf0, 0xe8, 0x2c, 0x20, 0xd1, 0xf2,
        0xf0, 0xe8, 0xe1, 0xee, 0xe6, 0xe8,
        0x20, 0xe2, 0xed, 0xf3, 0xf6, 0xe8,
        0x2c, 0x20, 0xe2, 0xe5, 0xfe, 0xf2,
        0xfa, 0x20, 0xf1, 0x20, 0xec, 0xee,
        0xf0, 0xff, 0x20, 0xf1, 0xf2, 0xf0,
        0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20,
        0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0,
        0xe1, 0xf0, 0xfb, 0xff, 0x20, 0xef,
        0xeb, 0xfa, 0xea, 0xfb, 0x20, 0xc8,
        0xe3, 0xee, 0xf0, 0xe5, 0xe2, 0xfb
    };
        static GOST3411_2012_256DigestTest()
        {
            messageBytes = new byte[][]
            {
            M1,
            M2
            };
        }

        private static readonly string[] digests =
        {
        "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
        "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50"
    };
        public GOST3411_2012_256DigestTest()
            : base(new Gost3411_2012_256DigestWrapper(), new string[] { "M1", "M2" }, digests)
        {
        }
        public override void PerformTest()
        {
            IDigest digest = new Gost3411_2012_256DigestWrapper();
            byte[] result = new byte[digest.GetDigestSize()];

            for (int i = 0; i < messageBytes.Length; i++)
            {
                digest.BlockUpdate(messageBytes[i], 0, messageBytes[i].Length);
                digest.DoFinal(result, 0);

                byte[] expected = Hex.Decode(digests[i]);
                if (!Arrays.AreEqual(expected, result))
                {
                    Fail("GOST3411_2012_256 vector " + i + " failed");
                }

                digest.Reset();
            }

            // HMAC test
            HMac gMac = new HMac(new Gost3411_2012_256DigestWrapper().GetInternalDigest());
            gMac.Init(new KeyParameter(Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")));

            byte[] data = Hex.Decode("0126bdb87800af214341456563780100");
            gMac.BlockUpdate(data, 0, data.Length);
            byte[] mac = new byte[gMac.GetMacSize()];
            gMac.DoFinal(mac, 0);

            if (!Arrays.AreEqual(Hex.Decode("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"), mac))
            {
                Fail("GOST3411_2012_256 HMAC test failed.");
            }
        }
        protected override IDigest CloneDigest(IDigest digest)
        {
            return new Gost3411_2012_256DigestWrapper(((Gost3411_2012_256DigestWrapper)digest).GetInternalDigest());
        }
    }
}