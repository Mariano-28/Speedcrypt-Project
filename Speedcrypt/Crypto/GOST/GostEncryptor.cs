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

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Crypto.GOST
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// GostEncryptor: Provides file encryption and decryption using GOST 28147-89
    /// in CBC mode with PKCS7 padding.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements secure GOST 28147-89 file encryption within the
    /// Speedcrypt framework:
    /// - Encrypts files using GOST 28147-89 in CBC mode with PKCS7 padding
    /// - Requires a fixed 256-bit (32-byte) symmetric key
    /// - Generates a cryptographically secure random 8-byte IV for every encryption
    /// - Stores the IV at the beginning of the encrypted file
    /// - Processes files using buffered stream I/O for efficient handling of large files
    /// - Automatically appends the .SPCR extension to encrypted files
    /// - Invokes Passwerr.HandleDecryptionFailure() on any decryption failure
    ///
    /// Security notes:
    /// - A unique IV is generated for every encryption operation
    /// - CBC mode ensures identical plaintext blocks encrypt differently under different IVs
    /// - PKCS7 padding allows encryption of files with arbitrary lengths
    /// - Independent cipher instances prevent cryptographic state reuse
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public class GostEncryptor
    {
        // Extension appended to encrypted files
        public string EncryptedFileExtension { get; private set; } = ".SPCR"; // Speed Crypt default extension

        // Generates a cryptographically secure 8-byte IV (block size of GOST 28147-89)
        private static byte[] GenerateIV()
        {
            byte[] iv = new byte[8];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }

        // Encrypts a file using GOST 28147-89 in CBC mode with PKCS7 padding
        // The key MUST be exactly 32 bytes (256 bits)
        public void EncryptFile(string inputFilePath, string outputFilePath, byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != 32)
                throw new ArgumentException("GOST 28147-89 requires a 256-bit (32-byte) key.");

            byte[] iv = GenerateIV();
            string encryptedFilePath = outputFilePath + EncryptedFileExtension;

            using (var fsOutput = new FileStream(encryptedFilePath, FileMode.Create))
            {
                // Write IV at the beginning of the file
                fsOutput.Write(iv, 0, iv.Length);

                var engine = new Gost28147Engine();
                var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));

                cipher.Init(true, new ParametersWithIV(new KeyParameter((byte[])key.Clone()), (byte[])iv.Clone()));

                // 64KB buffer for optimal performance on very large files (up to 100GB+)
                byte[] buffer = new byte[65536];

                using (var fsInput = new FileStream(inputFilePath, FileMode.Open))
                {
                    int bytesRead;
                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        // Dynamically allocate only the strict required size for the processed chunk
                        int updateSize = cipher.GetUpdateOutputSize(bytesRead);
                        byte[] output = new byte[updateSize > 0 ? updateSize : cipher.GetOutputSize(bytesRead)];

                        int len = cipher.ProcessBytes(buffer, 0, bytesRead, output, 0);
                        if (len > 0)
                        {
                            fsOutput.Write(output, 0, len);
                        }
                    }

                    byte[] finalBlock = new byte[cipher.GetOutputSize(0)];
                    int finalLen = cipher.DoFinal(finalBlock, 0);
                    if (finalLen > 0)
                    {
                        fsOutput.Write(finalBlock, 0, finalLen);
                    }
                }
            }
        }

        // Decrypts a file encrypted with GOST 28147-89 CBC + PKCS7
        // The key MUST be exactly 32 bytes (256 bits)
        public bool DecryptFile(string inputFilePath, string outputFilePath, byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != 32)
                throw new ArgumentException("GOST 28147-89 requires a 256-bit (32-byte) key.");

            try
            {
                using (var fsInput = new FileStream(inputFilePath, FileMode.Open))
                using (var fsOutput = new FileStream(outputFilePath, FileMode.Create))
                {
                    byte[] iv = new byte[8];
                    fsInput.Read(iv, 0, iv.Length);

                    var engine = new Gost28147Engine();
                    var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));

                    cipher.Init(false, new ParametersWithIV(new KeyParameter((byte[])key.Clone()), (byte[])iv.Clone()));

                    // 64KB buffer for optimal performance on very large files (up to 100GB+)
                    byte[] buffer = new byte[65536];
                    int bytesRead;

                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        // Dynamically allocate only the strict required size for the processed chunk
                        int updateSize = cipher.GetUpdateOutputSize(bytesRead);
                        byte[] output = new byte[updateSize > 0 ? updateSize : cipher.GetOutputSize(bytesRead)];

                        int len = cipher.ProcessBytes(buffer, 0, bytesRead, output, 0);
                        if (len > 0)
                        {
                            fsOutput.Write(output, 0, len);
                        }
                    }

                    byte[] finalBlock = new byte[cipher.GetOutputSize(0)];
                    int finalLen = cipher.DoFinal(finalBlock, 0);
                    if (finalLen > 0)
                    {
                        fsOutput.Write(finalBlock, 0, finalLen);
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