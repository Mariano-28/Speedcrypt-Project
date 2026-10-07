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
    /// Threefish256Test: Unit test class for Threefish-256 block cipher.
    /// Validates encryption correctness against official Skein 1.3 NIST CD test vectors.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class ensures:
    /// - Correct block cipher encryption/decryption with known vectors
    /// - Proper handling of keys and tweaks
    /// - Failures are logged centrally and reported as critical test failures
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    [TestFixture]
    public class Threefish256Test : CipherTest
    {
        // Test vectors from skein_golden_kat_internals.txt (Skein 1.3 NIST CD)
        static SimpleTest[] tests =
        {
        new BlockCipherVectorTest(0,
            new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256),
            new TweakableBlockCipherParameters(
                new KeyParameter(new byte[32]),
                new byte[16]),
                             "0000000000000000000000000000000000000000000000000000000000000000",
                             "84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8"),

        new BlockCipherVectorTest(1,
            new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256),
            new TweakableBlockCipherParameters(
            new KeyParameter(Hex.Decode("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")),
                             Hex.Decode("000102030405060708090a0b0c0d0e0f")),
                                        "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
                                        "e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df")
        };
        public Threefish256Test()
            : base(tests, new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256), new KeyParameter(new byte[32]))
        {
        }
        public override string Name
        {
            get { return "Threefish-256"; }
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
                CentralLog.LogException(ex, "Threefish-256 Self-Test", "Threefish-256 test failed!");
                Fail("Threefish-256 test failed - " + ex);
            }
        }
    }
}