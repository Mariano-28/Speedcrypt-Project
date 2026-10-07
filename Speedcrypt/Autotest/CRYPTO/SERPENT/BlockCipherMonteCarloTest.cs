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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Encoders;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Autotest.CRYPTO.Serpent
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// BlockCipherMonteCarloTest: Unit test class for Monte Carlo testing of a block cipher engine.
    /// Validates encryption and decryption correctness over multiple iterations using expected outputs.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class ensures:
    /// - Correct block cipher processing with padding disabled
    /// - Proper encryption and decryption over a specified number of Monte Carlo iterations
    /// - Validation against expected outputs
    /// - Any exception is logged centrally and treated as a critical test failure
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>  
    public class BlockCipherMonteCarloTest : SimpleTest
    {
        private int id;
        private int iterations;
        private IBlockCipher engine;
        private ICipherParameters param;
        private byte[] input;
        private byte[] output;
        public BlockCipherMonteCarloTest(int id, int iterations,  IBlockCipher engine, ICipherParameters param, string input, string output)
        {
            this.id = id;
            this.iterations = iterations;
            this.engine = engine;
            this.param = param;
            this.input = Hex.Decode(input);
            this.output = Hex.Decode(output);
        }
        public override string Name => engine.AlgorithmName + " Monte Carlo Test " + id;
        public override void PerformTest()
        {
            try
            {
                // Create cipher without padding for Monte Carlo
                BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

                // Encryption Monte Carlo
                cipher.Init(true, param);
                byte[] encBytes = new byte[input.Length];
                Array.Copy(input, 0, encBytes, 0, encBytes.Length);

                for (int i = 0; i < iterations; i++)
                {
                    int len = cipher.ProcessBytes(encBytes, 0, encBytes.Length, encBytes, 0);
                    cipher.DoFinal(encBytes, len);
                }

                if (!AreEqual(encBytes, output))
                {
                    CentralLog.LogException(
                        new InvalidOperationException("Encryption mismatch"),
                                                      "BlockCipher Monte Carlo Test",
                                                      "Encryption failed: expected " + Hex.ToHexString(output) +
                                                      " got " + Hex.ToHexString(encBytes));
                    return;
                }

                // Decryption Monte Carlo
                cipher.Init(false, param);
                byte[] decBytes = new byte[encBytes.Length];
                Array.Copy(encBytes, 0, decBytes, 0, decBytes.Length);

                for (int i = 0; i < iterations; i++)
                {
                    int len = cipher.ProcessBytes(decBytes, 0, decBytes.Length, decBytes, 0);
                    cipher.DoFinal(decBytes, len);
                }

                if (!AreEqual(input, decBytes))
                {
                    CentralLog.LogException(new InvalidOperationException("Decryption reversal failed"), "BlockCipher Monte Carlo Test","Decryption failed for Monte Carlo test " + id);
                    return;
                }

                // Success: non loggato, come negli altri test Speedcrypt
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "BlockCipher Monte Carlo Test", "Cipher Monte Carlo test failed!");
                Fail("Cipher Monte Carlo test failed - " + ex);
            }
        }
    }
}