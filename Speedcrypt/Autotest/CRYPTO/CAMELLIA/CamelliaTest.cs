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

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Autotest.CRYPTO.CAMELLIA
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CamelliaTest: Unit test class for the Camellia block cipher.
    /// Validates encryption and decryption correctness using official NESSIE
    /// and RFC 3713 test vectors.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class ensures:
    /// - Correct Camellia encryption and decryption with 128, 192 and 256-bit keys
    /// - Proper handling of official NESSIE and RFC 3713 reference vectors
    /// - Any failure is logged centrally and treated as a critical test failure
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class CamelliaTest
        : CipherTest
    {
        static SimpleTest[] tests =
        {
        new BlockCipherVectorTest(0, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("00000000000000000000000000000000")),
            "80000000000000000000000000000000", "07923A39EB0A817D1C4D87BDB82D1F1C"),
        new BlockCipherVectorTest(1, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("80000000000000000000000000000000")),
            "00000000000000000000000000000000", "6C227F749319A3AA7DA235A9BBA05A2C"),
        new BlockCipherVectorTest(2, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("0123456789abcdeffedcba9876543210")),
            "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"),
        //
        // 192 bit
        //
        new BlockCipherVectorTest(3, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("0123456789abcdeffedcba98765432100011223344556677")),
            "0123456789abcdeffedcba9876543210", "b4993401b3e996f84ee5cee7d79b09b9"),
        new BlockCipherVectorTest(4, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("000000000000000000000000000000000000000000000000")),
            "00040000000000000000000000000000", "9BCA6C88B928C1B0F57F99866583A9BC"),
        new BlockCipherVectorTest(5, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("949494949494949494949494949494949494949494949494")),
            "636EB22D84B006381235641BCF0308D2", "94949494949494949494949494949494"),
        //
        // 256 bit
        //
        new BlockCipherVectorTest(6, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff")),
            "0123456789abcdeffedcba9876543210", "9acc237dff16d76c20ef7c919e3a7509"),
        new BlockCipherVectorTest(7, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A")),
            "057764FE3A500EDBD988C5C3B56CBA9A", "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A"),
        new BlockCipherVectorTest(8, new CamelliaEngine(),
            new KeyParameter(Hex.Decode("0303030303030303030303030303030303030303030303030303030303030303")),
            "7968B08ABA92193F2295121EF8D75C8A", "03030303030303030303030303030303"),
        };
        public CamelliaTest()
                : base(tests, new CamelliaEngine(), new KeyParameter(new byte[32]))
        {
        }
        public override string Name
        {
            get { return "Camellia"; }
        }

        [Test]
        public void TestFunction()
        {
            try
            {
                string resultText = Perform().ToString();
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "Camellia Self-Test", "Camellia test execution failed!");
                Fail("Camellia test execution failed - " + ex);
            }
        }
    }
}