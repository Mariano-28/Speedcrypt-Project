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
    /// MD5DigestTest: Unit test class for the MD5 message digest.
    /// Validates standard vectors from "Handbook of Applied Cryptography", page 345.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Correct MD5 hash computation for standard test vectors
    /// - Deterministic and consistent digest results
    /// - Compliance with RFC 1321 standard
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class MD5DigestTest : SimpleTest
    {
        private static readonly string[] Messages =
        {
            "",
            "a",
            "abc",
            "abcdefghijklmnopqrstuvwxyz"
        };

        private static readonly string[] Digests =
        {
            "d41d8cd98f00b204e9800998ecf8427e",
            "0cc175b9c0f1b6a831c399e269772661",
            "900150983cd24fb0d6963f7d28e17f72",
            "c3fcd3d76192e4007dfb496cca67e13b"
        };
        public override string Name => "MD5";
        public override void PerformTest()
        {
            byte[] resBuf = new byte[16]; // MD5 digest size

            for (int i = 0; i < Messages.Length; i++)
            {
                byte[] input = System.Text.Encoding.ASCII.GetBytes(Messages[i]);
                digest.BlockUpdate(input, 0, input.Length);
                digest.DoFinal(resBuf, 0);

                byte[] expected = Hex.Decode(Digests[i]);
                if (!AreEqual(resBuf, expected))
                {
                    Fail($"MD5 vector {i} failed");
                }

                digest.Reset();
            }
        }

        private readonly MD5Digest digest = new MD5Digest();
    }
}