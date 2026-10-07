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

using Org.BouncyCastle.Utilities.Encoders;

// Speedcrypt
using Speedcrypt.Digests.GOST;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// GOST94DigestTest: Unit test class for the GOST R 34.11-94 hash function.
    /// /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// Validates hash output against known reference vectors.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct hash derivation using GOST R 34.11-94
    /// - Validation against provided test vectors
    /// - Any mismatch or exception is treated as a critical test failure and logged centrally
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class GOST94DigestTest : SimpleTest
    {
        private static readonly string[] Messages =
        {
        "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabc",
        "Suppose the original message has length = 50 bytes",
        "This is message, length=32 bytes"
    };

        private static readonly string[] Digests =
        {
        "92F55DE3CF4136318A63C4371E28D4AE56B7B13A0080712AE69B5325842DB25B",
        "471ABA57A60A770D3A76130635C1FBEA4EF14DE51F78B4AE57DD893B62F55208",
        "B1C466D37519B82E8319819FF32595E047A28CB6F83EFF1C6916A815A637FFFA"
    };
        public override string Name => "GOST R 34.11-94";

        public override void PerformTest()
        {
            byte[] resBuf;
            GOSTash94 gost = new GOSTash94();

            for (int i = 0; i < Messages.Length; i++)
            {
                gost.InitModule();
                gost.InitNewHash();

                byte[] input = System.Text.Encoding.ASCII.GetBytes(Messages[i]);
                gost.UpdateHash(input, (ulong)input.Length, true);
                gost.FinalizeHash();

                resBuf = gost.GetDigest();
                byte[] expected = Hex.Decode(Digests[i]);

                if (!AreEqual(resBuf, expected))
                    Fail($"GOST vector {i} failed");

                gost = new GOSTash94();
            }
        }
    }
}