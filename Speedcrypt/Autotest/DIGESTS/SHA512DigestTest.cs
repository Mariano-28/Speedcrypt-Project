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

// NUnit unit testing framework
using NUnit.Framework;

using Speedcrypt.Exceptionlog;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Cryptographic self-test for SHA-512 message digest function.
    /// This class verifies the .NET SHA-512 implementation against standard test vectors from the FIPS Draft 180-2 specification.
    /// The vectors are the same as those defined in the original Bouncy Castle test suite for SHA-512.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This test class ensures:
    /// - Correct SHA-512 hash computation for multiple message lengths against known reference outputs.
    /// - Full reset of the digest between test vectors to prevent state leakage.
    /// - Immediate failure reporting on mismatch.
    /// - Structured logging of any unexpected exception for later analysis.
    ///
    /// Reference implementation lineage:
    /// - Bouncy Castle `SHA512DigestTest` class from the Java crypto test suite.
    ///
    /// Original test vectors and expected outputs derive from FIPS Draft 180-2.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    /// 
    [TestFixture]
    public class Sha512DigestTest : SimpleTest
    {
        private static readonly string[] Messages =
        {
        "",
        "a",
        "abc",
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    };

        private static readonly string[] Digests =
        {
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    };
        public override string Name => "SHA-512";

        private readonly Sha512Digest digest = new Sha512Digest();
        public override void PerformTest()
        {
            try
            {
                byte[] resBuf = new byte[digest.GetDigestSize()];

                for (int i = 0; i < Messages.Length; i++)
                {
                    byte[] input = System.Text.Encoding.ASCII.GetBytes(Messages[i]);
                    digest.BlockUpdate(input, 0, input.Length);
                    digest.DoFinal(resBuf, 0);

                    byte[] expected = Hex.Decode(Digests[i]);
                    if (!AreEqual(resBuf, expected))
                    {
                        Fail($"SHA-512 vector {i} failed");
                    }

                    digest.Reset();
                }
            }
            catch (Exception ex)
            {
                Fail("failed - exception - " + ex);
                CentralLog.LogException(ex, "SHA512DigestTest Self-Test", "failed - exception! " + ex.Message);
            }
        }
    }
}