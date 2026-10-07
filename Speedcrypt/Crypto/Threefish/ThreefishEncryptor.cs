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
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Crypto.Threefish
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ThreeFishEncryptor: Provides file encryption and decryption using the
    /// Threefish block cipher in SIC (counter-like) mode with HMAC-SHA256 integrity protection.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements secure Threefish-based file encryption within the
    /// Speedcrypt framework:
    /// - Encrypts files using the Threefish block cipher in SIC mode
    /// - Supports 256, 512, and 1024-bit key sizes
    /// - Validates key length against the selected key size
    /// - Generates a cryptographically secure random IV matching the block size
    /// - Stores the IV at the beginning of the encrypted file
    /// - Appends an HMAC-SHA256 authentication tag at the end of the file
    /// - Verifies integrity using constant-time comparison to prevent timing attacks
    /// - Performs a pre-decryption HMAC verification pass before decrypting
    /// - Uses buffered stream processing for efficient handling of large files
    /// - Automatically appends the .SPCR extension to encrypted files
    /// - Invokes Passwerr.HandleDecryptionFailure() on authentication or decryption failures
    ///
    /// Security notes:
    /// - Encrypt-then-MAC construction ensures ciphertext integrity before decryption
    /// - SIC mode provides counter-based encryption suitable for stream processing
    /// - A unique IV is generated per encryption based on block size
    /// - Integrity verification prevents tampering and corruption attacks
    /// - Constant-time comparison mitigates timing side-channel leakage
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public class ThreeFishEncryptor
    {
        private string _encryptedFileExtension = ".SPCR"; // Speed Crypt default extension

        // Extension appended to all Threefish-encrypted files
        public string EncryptedFileExtension
        {
            get { return _encryptedFileExtension; }
        }

        // Generate a secure random IV matching the block size
        private static byte[] GenerateIV(int blockSize)
        {
            byte[] iv = new byte[blockSize];
            new SecureRandom().NextBytes(iv);
            return iv;
        }

        // Constant-time comparison for HMAC verification
        private static bool AreEqualConstantTime(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

        // Encrypts a file using Threefish in SIC mode, appends IV and HMAC (Stream-to-Stream)
        public void EncryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            if (key.Length != keySize / 8)
                throw new ArgumentException("Key length does not match keySize.");

            int blockSize = keySize / 8;
            byte[] iv = GenerateIV(blockSize);
            string encryptedFilePath = outputFilePath + this.EncryptedFileExtension;

            using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
            {
                using (FileStream fsOutput = new FileStream(encryptedFilePath, FileMode.Create))
                {
                    using (HMACSHA256 hmac = new HMACSHA256(key))
                    {
                        // Write IV directly to the output stream
                        fsOutput.Write(iv, 0, iv.Length);

                        BufferedBlockCipher cipher = new BufferedBlockCipher(new SicBlockCipher(new ThreefishEngine(keySize)));
                        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

                        // Fixed 64KB buffer for stable performance on massive files
                        byte[] inputBuffer = new byte[65536];
                        int bytesRead;

                        while ((bytesRead = fsInput.Read(inputBuffer, 0, inputBuffer.Length)) > 0)
                        {
                            int updateSize = cipher.GetUpdateOutputSize(bytesRead);
                            byte[] outputBuffer = new byte[updateSize > 0 ? updateSize : cipher.GetOutputSize(bytesRead)];

                            int length = cipher.ProcessBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
                            if (length > 0)
                            {
                                // Write encrypted chunk to disk and update HMAC state concurrently
                                fsOutput.Write(outputBuffer, 0, length);
                                hmac.TransformBlock(outputBuffer, 0, length, null, 0);
                            }
                        }

                        byte[] finalBlock = new byte[cipher.GetOutputSize(0)];
                        int finalLength = cipher.DoFinal(finalBlock, 0);
                        if (finalLength > 0)
                        {
                            fsOutput.Write(finalBlock, 0, finalLength);
                            hmac.TransformBlock(finalBlock, 0, finalLength, null, 0);
                        }

                        // Compute final HMAC hash and append it to the end of the file
                        hmac.TransformFinalBlock(new byte[0], 0, 0);
                        byte[] hmacResult = hmac.Hash;
                        fsOutput.Write(hmacResult, 0, hmacResult.Length);
                    }
                }
            }
        }

        // Decrypts a file encrypted with Threefish and verifies HMAC (Stream-to-Stream)
        public bool DecryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            try
            {
                if (key.Length != keySize / 8)
                    throw new ArgumentException("Key length does not match keySize.");

                int blockSize = keySize / 8;

                // First pass: Verify trailing HMAC sequentially without loading data into RAM
                using (FileStream fsCheck = new FileStream(inputFilePath, FileMode.Open))
                {
                    using (HMACSHA256 hmac = new HMACSHA256(key))
                    {
                        byte[] iv = new byte[blockSize];
                        fsCheck.Read(iv, 0, iv.Length);

                        long encryptedDataLength = fsCheck.Length - iv.Length - 32;
                        if (encryptedDataLength < 0) return false;

                        byte[] buffer = new byte[65536];
                        int bytesRead;
                        long totalBytesToHash = encryptedDataLength;

                        while (totalBytesToHash > 0 && (bytesRead = fsCheck.Read(buffer, 0, (int)Math.Min((long)buffer.Length, totalBytesToHash))) > 0)
                        {
                            hmac.TransformBlock(buffer, 0, bytesRead, null, 0);
                            totalBytesToHash -= bytesRead;
                        }

                        hmac.TransformFinalBlock(new byte[0], 0, 0);
                        byte[] computedHmac = hmac.Hash;

                        byte[] storedHmac = new byte[32];
                        fsCheck.Read(storedHmac, 0, storedHmac.Length);

                        if (!AreEqualConstantTime(storedHmac, computedHmac))
                            throw new CryptographicException("HMAC verification failed");
                    }
                }

                // Second pass: Decrypt stream-to-stream securely
                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
                {
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create))
                    {
                        byte[] iv = new byte[blockSize];
                        fsInput.Read(iv, 0, iv.Length);

                        long encryptedDataLength = fsInput.Length - iv.Length - 32;

                        BufferedBlockCipher cipher = new BufferedBlockCipher(new SicBlockCipher(new ThreefishEngine(keySize)));
                        cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

                        byte[] buffer = new byte[65536];
                        int bytesRead;
                        long totalBytesToDecrypt = encryptedDataLength;

                        while (totalBytesToDecrypt > 0 && (bytesRead = fsInput.Read(buffer, 0, (int)Math.Min((long)buffer.Length, totalBytesToDecrypt))) > 0)
                        {
                            int updateSize = cipher.GetUpdateOutputSize(bytesRead);
                            byte[] outputBuffer = new byte[updateSize > 0 ? updateSize : cipher.GetOutputSize(bytesRead)];

                            int length = cipher.ProcessBytes(buffer, 0, bytesRead, outputBuffer, 0);
                            if (length > 0)
                            {
                                fsOutput.Write(outputBuffer, 0, length);
                            }
                            totalBytesToDecrypt -= bytesRead;
                        }

                        byte[] finalBlock = new byte[cipher.GetOutputSize(0)];
                        int finalLength = cipher.DoFinal(finalBlock, 0);
                        if (finalLength > 0)
                        {
                            fsOutput.Write(finalBlock, 0, finalLength);
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