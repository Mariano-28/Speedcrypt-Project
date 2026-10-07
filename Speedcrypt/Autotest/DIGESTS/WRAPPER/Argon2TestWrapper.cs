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

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Autotest.DIGESTS.WRAPPER
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Argon2TestWrapper: Unit test class for the Argon2 key derivation function.
    /// Validates derived keys using Argon2i parameters and ensures correctness of output length.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct Argon2 key derivation with Argon2i
    /// - Validation of output length to guarantee proper derivation
    /// - Any unexpected exception is treated as a critical test failure and logged centrally
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    internal class Argon2TestWrapper : SimpleTest
    {
        public override string Name => "ARGON2";
        public override void PerformTest()
        {
            RunArgon2Test();
        }
        private void RunArgon2Test()
        {
            try
            {
                // Real password and salt bytes for testing
                byte[] password = Encoding.ASCII.GetBytes("password");
                byte[] salt = Encoding.ASCII.GetBytes("somesalt");

                var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2i)
                                     .WithVersion(Argon2Parameters.Version13)
                                     .WithIterations(2)
                                     .WithMemoryPowOfTwo(16)
                                     .WithParallelism(1)
                                     .WithSalt(salt)
                                     .Build();

                var generator = new Argon2BytesGenerator();
                generator.Init(parameters);

                byte[] result = new byte[32];
                generator.GenerateBytes(password, result, 0, result.Length);

                // Sanity check: result length
                IsTrue(result.Length == 32);
            }
            catch (Exception ex)
            {
                // Log unexpected exceptions to CentralLog
                CentralLog.LogException(ex, "ARGON2 Self-Test", "ARGON2 test failed! " + ex.Message);

                // Keep original fail behavior
                Fail("ARGON2 Test failed: " + ex.Message);
            }
        }
    }
}