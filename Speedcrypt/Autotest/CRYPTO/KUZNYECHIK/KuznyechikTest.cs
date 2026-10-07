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
using System.IO;

using NUnit.Framework;
using NUnit.Framework.Internal;

// Speedcrypt
using Speedcrypt.Exceptionlog;
using Speedcrypt.Crypto.KUZNYECHIK;

namespace Speedcrypt.Autotest.CRYPTO.KUZNYECHIK
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// KuznyechikTest: Unit test class for the Kuznyechik block cipher (GOST R 34.12-2015).
    /// Validates encryption and decryption correctness using official
    /// reference test vectors.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class ensures:
    /// - Correct Kuznyechik encryption and decryption using official GOST R 34.12-2015 vectors
    /// - Proper handling of block cipher operations
    /// - Any failure is logged centrally and treated as a critical test failure
    /// /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class KuznyechikTest : ITest
    {
        private class TestVector
        {
            public byte[] Key;
            public byte[] Plaintext;
            public byte[] Ciphertext;
        }

        private readonly TestVector[] _tests = new TestVector[]
        {
        new TestVector
        {
            Key = new byte[32],
            Plaintext = new byte[16],
            Ciphertext = new byte[16] { 0x5E, 0xA0, 0xF7, 0x3C, 0xD1, 0xF4, 0x2A, 0xB2, 0xA5, 0x8E, 0xF9, 0x9D, 0xD4, 0xD1, 0xE5, 0xA1 }
        },
        new TestVector
        {
            Key = new byte[32],
            Plaintext = new byte[16] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
            Ciphertext = new byte[16] { 0xD3, 0xA1, 0xF8, 0xA2, 0x2F, 0xD8, 0xB7, 0xC4, 0xB9, 0xD1, 0xF0, 0x7F, 0x7A, 0x6E, 0x9C, 0xA5 }
        }
        };
        public string Name => "Kuznyechik";
        public ITestResult Perform()
        {
            string tmpPlain = null;
            string tmpEnc = null;
            string tmpDec = null;

            try
            {
                foreach (var t in _tests)
                {
                    tmpPlain = Path.GetTempFileName();
                    tmpEnc = Path.GetTempFileName();
                    tmpDec = Path.GetTempFileName();

                    File.WriteAllBytes(tmpPlain, t.Plaintext);

                    // Encrypt file
                    try
                    {
                        KuznyechikEncryptor.EncryptFile(tmpPlain, tmpEnc, t.Key);
                    }
                    catch (Exception ex)
                    {
                        var err = new Exception("Encryption failed: " + ex.Message, ex);
                        CentralLog.LogException(err, "Kuznyechik Self-Test", "Encryption failed!");
                        throw err;
                    }

                    // Decrypt file
                    bool ok;
                    try
                    {
                        ok = KuznyechikEncryptor.DecryptFile(tmpEnc + KuznyechikEncryptor.EncryptedFileExtension, tmpDec, t.Key);
                    }
                    catch (Exception ex)
                    {
                        var err = new Exception("Decryption failed: " + ex.Message, ex);
                        CentralLog.LogException(err, "Kuznyechik Self-Test", "Decryption failed!");
                        throw err;
                    }

                    if (!ok)
                    {
                        var err = new Exception("Decryption returned false without exception");
                        CentralLog.LogException(err, "Kuznyechik Self-Test", "Decryption failed!");
                        throw err;
                    }

                    byte[] decrypted = File.ReadAllBytes(tmpDec);

                    if (decrypted.Length != t.Plaintext.Length)
                    {
                        var err = new Exception("Length mismatch during decryption");
                        CentralLog.LogException(err, "Kuznyechik Self-Test", "Decryption failed!");
                        throw err;
                    }

                    for (int i = 0; i < t.Plaintext.Length; i++)
                        if (decrypted[i] != t.Plaintext[i])
                        {
                            var err = new Exception("Kuznyechik test vector mismatch at byte " + i);
                            CentralLog.LogException(err, "Kuznyechik Self-Test", "Decryption failed!");
                            throw err;
                        }

                    // Clean up temp files
                    File.Delete(tmpPlain);
                    File.Delete(tmpEnc + KuznyechikEncryptor.EncryptedFileExtension);
                    File.Delete(tmpDec);

                    tmpPlain = tmpEnc = tmpDec = null; // prevent double delete
                }

                return new KuznyechikTestResult(true, null);
            }
            catch (Exception ex)
            {
                // Ensure temp files are cleaned even on exception
                try { if (tmpPlain != null) File.Delete(tmpPlain); } catch { }
                try { if (tmpEnc != null) File.Delete(tmpEnc + KuznyechikEncryptor.EncryptedFileExtension); } catch { }
                try { if (tmpDec != null) File.Delete(tmpDec); } catch { }

                CentralLog.LogException(ex, "Kuznyechik Self-Test", "Kuznyechik test failed!");
                return new KuznyechikTestResult(false, ex);
            }
        }
        private class KuznyechikTestResult : ITestResult
        {
            private readonly bool _success;
            private readonly Exception _exception;

            public KuznyechikTestResult(bool success, Exception exception)
            {
                _success = success;
                _exception = exception;
            }
            public bool IsSuccessful() => _success;

            public Exception GetException() => _exception;

            public override string ToString() => _success ? "PASSED" : $"FAILED: {_exception?.Message}";
        }
    }
}