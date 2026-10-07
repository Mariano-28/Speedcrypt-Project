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
//https://www.gnu.org/licenses/gpl-3.0.html 

using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Crypto.Serpent
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SerpentEncryptor: Provides file encryption and decryption using the
    /// Serpent block cipher in CBC mode with PKCS7 padding.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements secure Serpent-based file encryption within the
    /// Speedcrypt framework:
    /// - Encrypts files using Serpent in CBC mode with PKCS7 padding
    /// - Supports 128, 192, and 256-bit keys
    /// - Normalizes and applies the provided key for encryption operations
    /// - Generates a cryptographically secure random 16-byte IV per encryption
    /// - Stores the IV at the beginning of the encrypted file
    /// - Appends an HMAC-SHA256 authentication tag at the end of the file
    /// - Verifies integrity using a constant-time comparison to prevent timing attacks
    /// - Performs a pre-decryption HMAC verification pass before decryption
    /// - Uses buffered stream processing for efficient handling of large files
    /// - Automatically appends the .SPCR extension to encrypted files
    /// - Invokes Passwerr.HandleDecryptionFailure() on integrity or decryption failure
    ///
    /// Security notes:
    /// - Encrypt-then-MAC construction ensures integrity before decryption
    /// - A unique IV is generated for every encryption operation
    /// - CBC mode ensures semantic security under proper IV usage
    /// - HMAC verification prevents tampering and padding-oracle style attacks
    /// - Sensitive buffers are handled in a streaming fashion to reduce exposure
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public class SerpentEncryptor
    {
        private string _encryptedFileExtension = ".SPCR"; // Speed Crypt default extension

        public string EncryptedFileExtension
        {
            get { return _encryptedFileExtension; }
        }

        // Generates a random 16-byte IV for CBC mode (Serpent block size)
        private static byte[] GenerateIV()
        {
            byte[] iv = new byte[16];
            new SecureRandom().NextBytes(iv);
            return iv;
        }

        // Constant-time comparison to prevent timing attacks
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        // Encrypts a file using Serpent CBC with PKCS7 padding and appends a streaming HMAC-SHA256
        public void EncryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            byte[] iv = GenerateIV();
            string encryptedFilePath = outputFilePath + this.EncryptedFileExtension;

            using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
            {
                using (FileStream fsOutput = new FileStream(encryptedFilePath, FileMode.Create))
                {
                    using (HMACSHA256 hmac = new HMACSHA256(key))
                    {
                        // Write IV directly to the output stream
                        fsOutput.Write(iv, 0, iv.Length);

                        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SerpentEngine()));
                        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

                        // Fixed 64KB buffer for stable performance on massive files
                        byte[] buffer = new byte[65536];
                        int bytesRead;

                        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            int updateSize = cipher.GetUpdateOutputSize(bytesRead);
                            byte[] outBuf = new byte[updateSize > 0 ? updateSize : cipher.GetOutputSize(bytesRead)];

                            int outLen = cipher.ProcessBytes(buffer, 0, bytesRead, outBuf, 0);
                            if (outLen > 0)
                            {
                                // Write to file and update HMAC hash state concurrently without buffering
                                fsOutput.Write(outBuf, 0, outLen);
                                hmac.TransformBlock(outBuf, 0, outLen, null, 0);
                            }
                        }

                        byte[] finalBuf = new byte[cipher.GetOutputSize(0)];
                        int finalLen = cipher.DoFinal(finalBuf, 0);
                        if (finalLen > 0)
                        {
                            fsOutput.Write(finalBuf, 0, finalLen);
                            hmac.TransformBlock(finalBuf, 0, finalLen, null, 0);
                        }

                        // Compute the final HMAC hash and append it to the end of the file
                        hmac.TransformFinalBlock(new byte[0], 0, 0);
                        byte[] hmacResult = hmac.Hash;
                        fsOutput.Write(hmacResult, 0, hmacResult.Length);
                    }
                }
            }
        }

        // Decrypts a file, verifying the trailing HMAC-SHA256 via a two-pass stream
        public bool DecryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            try
            {
                // First pass: Verify HMAC sequentially without loading ciphertext into RAM
                using (FileStream fsCheck = new FileStream(inputFilePath, FileMode.Open))
                {
                    using (HMACSHA256 hmac = new HMACSHA256(key))
                    {
                        byte[] iv = new byte[16];
                        fsCheck.Read(iv, 0, iv.Length);

                        long ciphertextLength = fsCheck.Length - iv.Length - 32;
                        if (ciphertextLength < 0) return false;

                        byte[] buffer = new byte[65536];
                        int bytesRead;
                        long totalBytesToHash = ciphertextLength;

                        while (totalBytesToHash > 0 && (bytesRead = fsCheck.Read(buffer, 0, (int)System.Math.Min((long)buffer.Length, totalBytesToHash))) > 0)
                        {
                            hmac.TransformBlock(buffer, 0, bytesRead, null, 0);
                            totalBytesToHash -= bytesRead;
                        }

                        hmac.TransformFinalBlock(new byte[0], 0, 0);
                        byte[] computedHmac = hmac.Hash;

                        byte[] storedHmac = new byte[32];
                        fsCheck.Read(storedHmac, 0, storedHmac.Length);

                        if (!FixedTimeEquals(storedHmac, computedHmac))
                            throw new CryptographicException("HMAC verification failed.");
                    }
                }

                // Second pass: Decrypt stream-to-stream securely
                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
                {
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create))
                    {
                        byte[] iv = new byte[16];
                        fsInput.Read(iv, 0, iv.Length);

                        long ciphertextLength = fsInput.Length - iv.Length - 32;

                        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SerpentEngine()));
                        cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

                        byte[] buffer = new byte[65536];
                        int bytesRead;
                        long totalBytesToDecrypt = ciphertextLength;

                        while (totalBytesToDecrypt > 0 && (bytesRead = fsInput.Read(buffer, 0, (int)System.Math.Min((long)buffer.Length, totalBytesToDecrypt))) > 0)
                        {
                            int updateSize = cipher.GetUpdateOutputSize(bytesRead);
                            byte[] outBuf = new byte[updateSize > 0 ? updateSize : cipher.GetOutputSize(bytesRead)];

                            int outLen = cipher.ProcessBytes(buffer, 0, bytesRead, outBuf, 0);
                            if (outLen > 0)
                            {
                                fsOutput.Write(outBuf, 0, outLen);
                            }
                            totalBytesToDecrypt -= bytesRead;
                        }

                        byte[] finalBuf = new byte[cipher.GetOutputSize(0)];
                        int finalLen = cipher.DoFinal(finalBuf, 0);
                        if (finalLen > 0)
                        {
                            fsOutput.Write(finalBuf, 0, finalLen);
                        }
                    }
                }

                return true;
            }
            catch (Exception)
            {
                Passwerr.HandleDecryptionFailure();
                return false;
            }
        }
    }
}