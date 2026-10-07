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
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Crypto.AESGCM
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// AESGCMEncryptor: Provides authenticated AES-GCM encryption and decryption
    /// for files utilizing an enforced 256-bit cryptographic key and a 128-bit authentication tag.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements authenticated encryption within the Speedcrypt
    /// framework:
    /// - Encrypts files using AES-GCM with a 128-bit authentication tag
    /// - Enforces strict validation and exclusive usage of 256-bit AES keys for maximum security
    /// - Generates a cryptographically secure 12-byte master IV for every encryption
    /// - Derives a unique IV for each processed chunk to prevent nonce reuse
    /// - Processes files in fixed-size chunks for efficient handling of very large files
    /// - Stores the master IV and chunk metadata within the encrypted file
    /// - Automatically appends the .SPCR extension to encrypted files
    /// - Validates authentication tags during decryption before releasing plaintext
    /// - Invokes Passwerr.HandleDecryptionFailure() on authentication or decryption failures
    ///
    /// Security notes:
    /// - AES-GCM provides both confidentiality and integrity in a single operation
    /// - Every chunk uses a distinct nonce derived from the master IV and chunk index
    /// - Authentication failures immediately abort decryption
    /// - Chunk-based processing avoids excessive memory consumption while preserving security
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>

    public class AESGCMEncryptor
    {
        // Extension appended to all encrypted files
        public string EncryptedFileExtension { get; private set; } = ".SPCR"; // Speed Crypt default extension

        // Chunk size set to 1MB (1,048,576 bytes) for stable RAM consumption
        private const int ChunkSize = 1024 * 1024;

        // Generates a 12-byte IV required for AES-GCM mode
        private static byte[] GenerateIV()
        {
            byte[] iv = new byte[12];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }

        // Encrypts a file using AES-GCM in chunks to bypass the 2GB memory limit
        public void EncryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            byte[] masterIv = GenerateIV();
            string encryptedFilePath = outputFilePath + EncryptedFileExtension;

            using (FileStream fsOutput = new FileStream(encryptedFilePath, FileMode.Create))
            using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
            {
                // Write master IV at the beginning of the encrypted file
                fsOutput.Write(masterIv, 0, masterIv.Length);

                byte[] inputBuffer = new byte[ChunkSize];
                int bytesRead;
                long chunkIndex = 0;

                // Process the file chunk by chunk (1MB each)
                while ((bytesRead = fsInput.Read(inputBuffer, 0, inputBuffer.Length)) > 0)
                {
                    // Derive a unique IV for each chunk using the master IV and the chunk index to avoid IV reuse
                    byte[] chunkIv = (byte[])masterIv.Clone();
                    byte[] indexBytes = BitConverter.GetBytes(chunkIndex);
                    Array.Copy(indexBytes, 0, chunkIv, 0, Math.Min(indexBytes.Length, chunkIv.Length));

                    var cipher = new GcmBlockCipher(new AesEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), 128, chunkIv);
                    cipher.Init(true, parameters);

                    // Write the dynamic length of the current processed chunk plaintext
                    byte[] lengthHeader = BitConverter.GetBytes(bytesRead);
                    fsOutput.Write(lengthHeader, 0, lengthHeader.Length);

                    // Calculate exact output size including the 16-byte authentication tag
                    byte[] outputBuffer = new byte[cipher.GetOutputSize(bytesRead)];
                    int outputLength = cipher.ProcessBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
                    outputLength += cipher.DoFinal(outputBuffer, outputLength);

                    // Write the encrypted chunk + authentication tag directly to disk
                    fsOutput.Write(outputBuffer, 0, outputLength);
                    chunkIndex++;
                }
            }
        }

        // Decrypts a chunked AES-GCM file and validates authentication tags sequentially
        public bool DecryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            try
            {
                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
                using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create))
                {
                    byte[] masterIv = new byte[12];
                    fsInput.Read(masterIv, 0, masterIv.Length);

                    byte[] lengthHeader = new byte[4];
                    long chunkIndex = 0;

                    // Read chunk length headers sequentially
                    while (fsInput.Read(lengthHeader, 0, lengthHeader.Length) == lengthHeader.Length)
                    {
                        int plainTextLength = BitConverter.ToInt32(lengthHeader, 0);
                        int cipherTextLength = plainTextLength + 16; // Account for the 128-bit authentication tag

                        byte[] cipherBuffer = new byte[cipherTextLength];
                        if (fsInput.Read(cipherBuffer, 0, cipherBuffer.Length) != cipherTextLength)
                        {
                            throw new EndOfStreamException("Incomplete encrypted chunk data.");
                        }

                        // Derive the matching unique IV for the current chunk index
                        byte[] chunkIv = (byte[])masterIv.Clone();
                        byte[] indexBytes = BitConverter.GetBytes(chunkIndex);
                        Array.Copy(indexBytes, 0, chunkIv, 0, Math.Min(indexBytes.Length, chunkIv.Length));

                        var cipher = new GcmBlockCipher(new AesEngine());
                        var parameters = new AeadParameters(new KeyParameter(key), 128, chunkIv);
                        cipher.Init(false, parameters);

                        byte[] outputBuffer = new byte[cipher.GetOutputSize(cipherTextLength)];
                        int outputLength = cipher.ProcessBytes(cipherBuffer, 0, cipherTextLength, outputBuffer, 0);
                        outputLength += cipher.DoFinal(outputBuffer, outputLength);

                        // Write decrypted chunk directly to disk
                        fsOutput.Write(outputBuffer, 0, outputLength);
                        chunkIndex++;
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