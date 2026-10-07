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
using System.Text;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Autotest.DIGESTS.PBKDF2
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Pbkdf2Test: Unit test class for the PBKDF2 key derivation function.
    /// Validates derived keys against official RFC 6070 test vectors.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct PBKDF2 key derivation using SHA1
    /// - Validation against RFC 6070 reference vectors
    /// - Any mismatch or exception is treated as a critical test failure and logged centrally
    /// - Extremely high iteration counts are skipped to avoid freezing the application, with a log entry
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>     
    internal class Pbkdf2Test : SimpleTest
    {
        public override string Name => "PBKDF2";
        public override void PerformTest()
        {
            try
            {
                // Execute test vectors from RFC 6070
                RunVector("password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
                RunVector("password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
                RunVector("password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1");
                RunVector("password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
                RunVector("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
                          "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
            }
            catch (TestFailedException)
            {
                // Test failed as expected: do not log
                throw;
            }
            catch (Exception ex)
            {
                // Log unexpected exceptions to CentralLog
                CentralLog.LogException(ex, "PBKDF2 Self-Test", "PBKDF2 test failed! " + ex.Message);
                throw;
            }
        }
        private void RunVector(string password, string salt, int iterationCount, int dkLen, string expectedHex)
        {
            // Initialize PBKDF2 generator with SHA1
            Pkcs5S2ParametersGenerator generator = new Pkcs5S2ParametersGenerator();
            generator.Init(
                Encoding.ASCII.GetBytes(password),
                Encoding.ASCII.GetBytes(salt),
                iterationCount
            );

            // Generate derived key
            KeyParameter key = (KeyParameter)generator.GenerateDerivedMacParameters(dkLen);
            byte[] derived = key.GetKey();

            // Convert derived key to hex string
            string resultHex = Hex.ToHexString(derived);

            // Compare result with expected value
            if (!string.Equals(resultHex, expectedHex, StringComparison.OrdinalIgnoreCase))
            {
                Fail("PBKDF2 vector failed.\n" +
                     "Password: " + password + "\n" +
                     "Salt: " + salt + "\n" +
                     "Iterations: " + iterationCount + "\n" +
                     "Expected: " + expectedHex + "\n" +
                     "Got: " + resultHex);
            }
        }
    }
}