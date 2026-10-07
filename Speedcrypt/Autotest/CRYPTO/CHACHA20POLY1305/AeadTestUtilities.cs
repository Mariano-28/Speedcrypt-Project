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
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

// Speescrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Autotest.CRYPTO.CHACHA20POLY1305
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// AeadTestUtilities: Utility class for testing AEAD cipher robustness.
    /// Provides tampering, truncation, and key reuse tests to verify
    /// authentication enforcement and integrity protection.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class validates that AEAD ciphers correctly detect:
    /// - Single-byte ciphertext tampering
    /// - Ciphertext truncation below authentication tag length
    /// - Improper reuse of parameters with missing keys
    /// Any failure to detect manipulation is treated as a critical test failure.
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class AeadTestUtilities
    {
        internal static void TestTampering(ITest test, IAeadCipher cipher, ICipherParameters parameters)
        {
            byte[] plaintext = new byte[1000];
            for (int i = 0; i < plaintext.Length; i++)
            {
                plaintext[i] = (byte)i;
            }

            try
            {
                cipher.Init(true, parameters);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "AEAD Self-Test", "AEAD failed initialisation!");
                Fail(test, "AEAD failed initialisation - " + ex);
            }

            byte[] ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);

            try
            {
                cipher.DoFinal(ciphertext, len);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "AEAD Self-Test", "AEAD failed encryption!");
                Fail(test, "AEAD failed encryption - " + ex);
            }

            int macLength = cipher.GetMac().Length;

            // Test single-byte tampering detection
            try
            {
                cipher.Init(false, parameters);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "AEAD Self-Test", "AEAD failed initialisation!");
                Fail(test, "AEAD failed initialisation - " + ex);
            }

            byte[] tampered = new byte[ciphertext.Length];
            byte[] output = new byte[plaintext.Length];
            Array.Copy(ciphertext, 0, tampered, 0, tampered.Length);
            tampered[0] += 1;

            cipher.ProcessBytes(tampered, 0, tampered.Length, output, 0);
            try
            {
                cipher.DoFinal(output, 0);
                Fail(test, "tampering of ciphertext not detected.");
            }
            catch (InvalidCipherTextException)
            {
                // Expected
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "AEAD Self-Test", "AEAD failed tampering test!");
                Fail(test, "AEAD failed tampering test - " + ex);
            }

            // Test truncation below authentication tag length
            try
            {
                cipher.Init(false, parameters);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "AEAD Self-Test", "AEAD failed initialisation!");
                Fail(test, "AEAD failed initialisation - " + ex);
            }

            byte[] truncated = new byte[macLength - 1];
            Array.Copy(ciphertext, 0, truncated, 0, truncated.Length);

            cipher.ProcessBytes(truncated, 0, truncated.Length, output, 0);
            try
            {
                cipher.DoFinal(output, 0);
                Fail(test, "tampering of ciphertext not detected.");
            }
            catch (InvalidCipherTextException)
            {
                // Expected
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "AEAD Self-Test", "AEAD failed truncation test!");
                Fail(test, "AEAD failed truncation test - " + ex);
            }
        }
        private static void Fail(ITest test, string message)
        {
            throw new TestFailedException(SimpleTestResult.Failed(test, message));
        }
        private static void Fail(ITest test, string message, string expected, string result)
        {
            throw new TestFailedException(SimpleTestResult.Failed(test, message, expected, result));
        }

        /// <summary>
        /// Creates a new AeadParameters instance reusing nonce and associated data,
        /// but without a key, to validate improper key reuse handling.
        /// </summary>
        internal static AeadParameters ReuseKey(AeadParameters p)
        {
            return new AeadParameters(null, p.MacSize, p.GetNonce(), p.GetAssociatedText());
        }
    }
}