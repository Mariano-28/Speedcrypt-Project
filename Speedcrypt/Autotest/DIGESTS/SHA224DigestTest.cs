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
    /// Sha224DigestTest: Unit test class for the SHA-224 hash function.
    /// Validates output against standard test vectors from RFC 3874 and FIPS 180-4.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This test class ensures:
    /// - Correct SHA-224 hash computation for a variety of input messages
    /// - Validation against known reference outputs, including edge cases (empty string, single characters, long sequences)
    /// - Proper handling of digest reset between tests to guarantee independent computations
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class Sha224DigestTest : SimpleTest
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
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
    };
        public override string Name => "SHA-224";

        private readonly Sha224Digest digest = new Sha224Digest();
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
                    Fail($"SHA-224 vector {i} failed");
                }

                digest.Reset();
            }
        }
    }
}