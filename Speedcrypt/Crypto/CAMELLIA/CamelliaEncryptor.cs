/// Speedcrypt software - The Open-Source for encrypt and decrypt files
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
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Crypto.CAMELLIA
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CamelliaEncryptor: Provides file encryption and decryption using Camellia
    /// in CBC mode with PKCS7 padding.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements secure Camellia-based file encryption within the
    /// Speedcrypt framework:
    /// - Encrypts files using Camellia-CBC with PKCS7 padding
    /// - Supports 128, 192, and 256-bit keys
    /// - Automatically pads or truncates keys to the required size
    /// - Generates a cryptographically secure random 16-byte IV for every encryption
    /// - Stores the IV at the beginning of the encrypted file
    /// - Processes files using buffered stream I/O for efficient handling of large files
    /// - Automatically appends the .SPCR extension to encrypted files
    ///
    /// Security notes:
    /// - A unique IV is generated for every encryption operation
    /// - CBC mode prevents identical plaintext blocks from producing identical ciphertext
    /// - PKCS7 padding ensures compatibility with arbitrary file sizes
    /// - Uses independent cipher instances for each encryption and decryption operation
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public class CamelliaEncryptor
    {
        // Extension appended to all encrypted files
        public string EncryptedFileExtension { get; private set; } = ".SPCR"; // Speed Crypt default extension
        private const int BufferSize = 65536; // 64KB buffer for optimal performance on large files up to 100GB+

        private void ValidateKey(ref byte[] key, int keySize)
        {
            int required = keySize / 8;
            if (key.Length != required)
            {
                byte[] k = new byte[required];
                System.Array.Copy(key, k, Math.Min(key.Length, required));
                key = k;
            }
        }

        // Generates a random 16-byte IV for CBC mode (Camellia block size)
        private static byte[] GenerateIV()
        {
            byte[] iv = new byte[16];
            new SecureRandom().NextBytes(iv);
            return iv;
        }

        // Encrypts a file using Camellia CBC with PKCS7 padding (Stream-to-Stream)
        public void EncryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            ValidateKey(ref key, keySize);
            byte[] iv = GenerateIV();

            string outFile = outputFilePath.EndsWith(EncryptedFileExtension, StringComparison.OrdinalIgnoreCase)
                ? outputFilePath
                : outputFilePath + EncryptedFileExtension;

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new CamelliaEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            // Use FileOptions.SequentialScan to optimize low-level sequential I/O operations for huge files
            using (var fsIn = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan))
            using (var fsOut = new FileStream(outFile, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize))
            {
                // Write the IV directly to the output stream
                fsOut.Write(iv, 0, iv.Length);

                byte[] inputBuffer = new byte[BufferSize];
                // SINGLE ALLOCATION: Allocate the maximum required output buffer once outside the loop to eliminate GC pressure
                byte[] outputBuffer = new byte[cipher.GetOutputSize(BufferSize)];
                int bytesRead;

                while ((bytesRead = fsIn.Read(inputBuffer, 0, inputBuffer.Length)) > 0)
                {
                    int len = cipher.ProcessBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
                    if (len > 0)
                    {
                        fsOut.Write(outputBuffer, 0, len);
                    }
                }

                // Process the final block and padding
                int finalLen = cipher.DoFinal(outputBuffer, 0);
                if (finalLen > 0)
                {
                    fsOut.Write(outputBuffer, 0, finalLen);
                }
            }
        }

        // Decrypts a file previously encrypted with Camellia CBC (Stream-to-Stream)
        public bool DecryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            try
            {
                ValidateKey(ref key, keySize);

                var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new CamelliaEngine()));

                // Use FileOptions.SequentialScan to optimize low-level sequential I/O operations for huge files
                using (var fsIn = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan))
                using (var fsOut = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize))
                {
                    byte[] iv = new byte[16];
                    if (fsIn.Read(iv, 0, iv.Length) != iv.Length) return false;

                    cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

                    byte[] inputBuffer = new byte[BufferSize];
                    // SINGLE ALLOCATION: Allocate the maximum required output buffer once outside the loop to eliminate GC pressure
                    byte[] outputBuffer = new byte[cipher.GetOutputSize(BufferSize)];
                    int bytesRead;

                    while ((bytesRead = fsIn.Read(inputBuffer, 0, inputBuffer.Length)) > 0)
                    {
                        int len = cipher.ProcessBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
                        if (len > 0)
                        {
                            fsOut.Write(outputBuffer, 0, len);
                        }
                    }

                    // Process the final decrypted block
                    int finalLen = cipher.DoFinal(outputBuffer, 0);
                    if (finalLen > 0)
                    {
                        fsOut.Write(outputBuffer, 0, finalLen);
                    }
                }

                return true;
            }
            catch
            {                
                return false;
            }
        }
    }
}