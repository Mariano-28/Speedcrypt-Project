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
    /// Sha256DigestTest: Unit test class for the SHA-256 hash function.
    /// Validates output against standard test vectors from FIPS 180-2 and FIPS 180-4.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This test class ensures:
    /// - Correct SHA-256 hash computation for a variety of input messages
    /// - Validation against known reference outputs, including edge cases (empty string, single characters, long sequences)
    /// - Proper handling of digest reset between tests to guarantee independent computations
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class Sha256DigestTest : SimpleTest
    {
        private static readonly string[] Messages =
        {
        "",
        "a",
        "abc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    };

        private static readonly string[] Digests =
        {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    };
        public override string Name => "SHA-256";

        private readonly Sha256Digest digest = new Sha256Digest();
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
                    Fail($"SHA-256 vector {i} failed");
                }

                digest.Reset();
            }
        }
    }
}