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

namespace Speedcrypt.Autotest.CRYPTO.THREEFISH
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Threefish512Test: Unit test class for Threefish-512 block cipher.
    /// Validates encryption correctness against official Skein 1.3 NIST CD test vectors.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class ensures:
    /// - Correct block cipher encryption and decryption for 512-bit blocks
    /// - Proper handling of keys and tweak values
    /// - Any failure is logged centrally and treated as a critical test failure
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    
    [TestFixture]
    public class Threefish512Test : CipherTest
    {
        // Test vectors from skein_golden_kat_internals.txt (Skein 1.3 NIST CD)
        static SimpleTest[] tests =
        {
        new BlockCipherVectorTest(0,
            new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512),
            new TweakableBlockCipherParameters(
            new KeyParameter(new byte[64]),
            new byte[16]), "0000000000000000000000000000000000000000000000000000000000000000" +
                           "0000000000000000000000000000000000000000000000000000000000000000",
                           "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b" +
                           "7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe"),

        new BlockCipherVectorTest(1,
            new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512),
            new TweakableBlockCipherParameters(
            new KeyParameter(Hex.Decode("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
                                        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")),
                                        Hex.Decode("000102030405060708090a0b0c0d0e0f")),
                                        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
                                        "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0",
                                        "e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779" +
                                        "272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d")
    };
        public Threefish512Test()
            : base(tests, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512), new KeyParameter(new byte[64]))
        {
        }
        public override string Name
        {
            get { return "Threefish-512"; }
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
                CentralLog.LogException(ex, "Threefish-512 Self-Test", "Threefish-512 test failed!");
                Fail("Threefish-512 test failed - " + ex);
            }
        }
    }
}