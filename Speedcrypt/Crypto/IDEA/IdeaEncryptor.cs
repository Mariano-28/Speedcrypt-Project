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
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Crypto.IDEA
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// IDEAEncryptor: Provides file encryption and decryption using the
    /// International Data Encryption Algorithm (IDEA) in CBC mode with PKCS7 padding.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements secure IDEA-based file encryption within the
    /// Speedcrypt framework:
    /// - Encrypts files using IDEA-CBC with PKCS7 padding
    /// - Requires a fixed 128-bit (16-byte) symmetric key
    /// - Generates a cryptographically secure random 8-byte IV for every encryption
    /// - Stores the IV at the beginning of the encrypted file
    /// - Processes files using buffered stream I/O for efficient handling of large files
    /// - Automatically appends the .SPCR extension to encrypted files
    ///
    /// Security notes:
    /// - A unique IV is generated for every encryption operation
    /// - CBC mode prevents identical plaintext blocks from producing identical ciphertext
    /// - PKCS7 padding allows encryption of files with arbitrary lengths
    /// - Independent cipher instances prevent cryptographic state reuse
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public class IDEAEncryptor
    {
        public string EncryptedFileExtension { get; private set; } = ".SPCR"; // Speed Crypt default extension
        private const int BufferSize = 65536; // 64KB buffer for optimal performance on very large files (up to 100GB+)

        // Generates a random 8-byte IV for CBC mode
        private static byte[] GenerateIV()
        {
            byte[] iv = new byte[8];
            new SecureRandom().NextBytes(iv);
            return iv;
        }

        // Encrypts a file using IDEA CBC with PKCS7 padding (Stream-to-Stream)
        public void EncryptFile(string inputFilePath, string outputFilePath, byte[] keyBytes)
        {
            string encryptedFilePath = outputFilePath.EndsWith(EncryptedFileExtension, StringComparison.OrdinalIgnoreCase)
                ? outputFilePath
                : outputFilePath + EncryptedFileExtension;

            byte[] iv = GenerateIV();

            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new IdeaEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(keyBytes), iv));

            using (FileStream fsOutput = new FileStream(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize))
            {
                // Write the IV directly to the output stream
                fsOutput.Write(iv, 0, iv.Length);

                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan))
                {
                    byte[] buffer = new byte[BufferSize];
                    // SINGLE ALLOCATION: Pre-allocate output buffer outside the loop to completely prevent inner-loop GC allocations
                    byte[] output = new byte[cipher.GetOutputSize(BufferSize)];
                    int bytesRead;

                    // Stream chunks directly to disk to prevent MemoryStream 2GB limit issues
                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        int length = cipher.ProcessBytes(buffer, 0, bytesRead, output, 0);
                        if (length > 0)
                        {
                            fsOutput.Write(output, 0, length);
                        }
                    }

                    int finalLength = cipher.DoFinal(output, 0);
                    if (finalLength > 0)
                    {
                        fsOutput.Write(output, 0, finalLength);
                    }
                }
            }
        }

        // Decrypts a file previously encrypted with IDEA CBC (Stream-to-Stream)
        public bool DecryptFile(string inputFilePath, string outputFilePath, byte[] keyBytes)
        {
            try
            {
                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan))
                using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize))
                {
                    byte[] iv = new byte[8];
                    if (fsInput.Read(iv, 0, iv.Length) != iv.Length) return false;

                    BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new IdeaEngine()));
                    cipher.Init(false, new ParametersWithIV(new KeyParameter(keyBytes), iv));

                    byte[] buffer = new byte[BufferSize];
                    // SINGLE ALLOCATION: Pre-allocate output buffer outside the loop to completely prevent inner-loop GC allocations
                    byte[] output = new byte[cipher.GetOutputSize(BufferSize)];
                    int bytesRead;

                    // Stream chunks directly to disk to prevent MemoryStream 2GB limit issues
                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        int length = cipher.ProcessBytes(buffer, 0, bytesRead, output, 0);
                        if (length > 0)
                        {
                            fsOutput.Write(output, 0, length);
                        }
                    }

                    int finalLength = cipher.DoFinal(output, 0);
                    if (finalLength > 0)
                    {
                        fsOutput.Write(output, 0, finalLength);
                    }
                }

                return true;
            }
            catch (Exception)
            {                
                return false;
            }
        }
    }
}