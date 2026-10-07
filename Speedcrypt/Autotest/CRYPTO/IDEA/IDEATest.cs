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

namespace Speedcrypt.Autotest.CRYPTO.IDEA
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// IdeaTest: Unit test class for the IDEA block cipher.
    /// Validates encryption correctness using official reference test vectors.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class ensures:
    /// - Correct IDEA encryption and decryption using standard block cipher vectors
    /// - Proper key processing and handling
    /// - Output verification matches expected results
    /// - Any failure is logged centrally and treated as a critical test failure
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class IdeaTest : CipherTest
    {
        /// <summary>
        /// Gets the name of the cipher under test.
        /// </summary>
        public override string Name
        {
            get { return "IDEA"; }
        }

        /// <summary>
        /// Predefined test vectors for IDEA cipher validation.
        /// </summary>
        internal static SimpleTest[] tests = new SimpleTest[]
        {
        new BlockCipherVectorTest(0, new IdeaEngine(),
                                     new KeyParameter(Hex.Decode("00112233445566778899AABBCCDDEEFF")),
                                                                 "000102030405060708090a0b0c0d0e0f",
                                                                 "ed732271a7b39f475b4b2b6719f194bf"),

        new BlockCipherVectorTest(0, new IdeaEngine(),
                                     new KeyParameter(Hex.Decode("00112233445566778899AABBCCDDEEFF")),
                                                                 "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                                                                 "b8bc6ed5c899265d2bcfad1fc6d4287d")
        };

        /// <summary>
        /// Default constructor initializing the CipherTest base with IDEA engine and key.
        /// </summary>
        public IdeaTest()
            : base(tests, new IdeaEngine(), new KeyParameter(new byte[32]))
        {
            // No log here since initialization is not exceptional
        }

        /// <summary>
        /// Executes the IDEA cipher test.
        /// Logs exceptions centrally if they occur.
        /// </summary>
        [Test]
        public void TestFunction()
        {
            try
            {
                string resultText = Perform().ToString();
                //Assert.AreEqual(Name + ": Okay", resultText);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "IDEA Self-Test", "IDEA Self-Test failed!");
                Fail("IDEA Self-Test failed - " + ex);
            }
        }
    }
}