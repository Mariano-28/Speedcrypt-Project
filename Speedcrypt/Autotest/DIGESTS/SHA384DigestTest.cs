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

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Sha384DigestTest: Unit test class for the SHA-384 hash function.
    /// Validates output against standard test vectors from FIPS 180-2 and FIPS 180-4.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This test class ensures:
    /// - Correct SHA-384 hash computation for a variety of input messages
    /// - Validation against known reference outputs, including edge cases (empty string, single characters, long sequences)
    /// - Proper handling of digest reset between tests to guarantee independent computations
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class Sha384DigestTest : SimpleTest
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
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
    };
        public override string Name => "SHA-384";

        private readonly Sha384Digest digest = new Sha384Digest();
        public override void PerformTest()
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
                    Fail($"SHA-384 vector {i} failed");
                }

                digest.Reset();
            }
        }
    }
}