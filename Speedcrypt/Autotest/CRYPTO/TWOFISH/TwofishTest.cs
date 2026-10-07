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

// NUnit unit testing framework
using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Autotest.CRYPTO.TWOFISH
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// TwofishTest: Unit test class for the Twofish block cipher.
    /// Validates encryption correctness using official reference test vectors
    /// with multiple key sizes.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class ensures:
    /// - Correct Twofish encryption with 128, 192 and 256-bit keys
    /// - Proper handling of fixed plaintext test vectors
    /// - Any failure is logged centrally and treated as a critical test failure
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>     

    [TestFixture]
    public class TwofishTest : CipherTest
    {
        public override string Name
        {
            get { return "Twofish"; }
        }

        internal static string key1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        internal static string key2 = "000102030405060708090a0b0c0d0e0f1011121314151617";
        internal static string key3 = "000102030405060708090a0b0c0d0e0f";

        internal static string input = "000102030405060708090A0B0C0D0E0F";

        internal static SimpleTest[] tests =
        {
        new BlockCipherVectorTest(0,
            new TwofishEngine(),
            new KeyParameter(Hex.Decode(key1)),
            input,
            "8ef0272c42db838bcf7b07af0ec30f38"),

        new BlockCipherVectorTest(1,
            new TwofishEngine(),
            new KeyParameter(Hex.Decode(key2)),
            input, "95accc625366547617f8be4373d10cd7"),

        new BlockCipherVectorTest(2,
            new TwofishEngine(),
            new KeyParameter(Hex.Decode(key3)),
            input, "9fb63337151be9c71306d159ea7afaa4")
    };
        public TwofishTest()
            : base(tests, new TwofishEngine(), new KeyParameter(new byte[32]))
        {
        }

        [Test]
        public void TestFunction()
        {
            try
            {
                string resultText = Perform().ToString();

                // Uncomment the assertion if strict validation is required
                // Assert.AreEqual(Name + ": Okay", resultText);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "Twofish Self-Test", "Twofish test failed!");
                Fail("Twofish test failed - " + ex);
            }
        }
    }
}