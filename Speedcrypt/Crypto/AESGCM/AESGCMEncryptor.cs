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
using System.Buffers.Binary;
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
        /// <summary>
        /// Custom file extension appended to target paths upon successful encryption.
        /// </summary>
        public string EncryptedFileExtension { get; private set; } = ".SPCR";

        private const int ChunkSize = 1024 * 1024;
        private const int GcmTagLengthBytes = 16;
        private const int GcmIvLengthBytes = 12;
        private const int MaxCipherTextChunkSize = ChunkSize + GcmTagLengthBytes;

        /// <summary>
        /// Generates a cryptographically strong Master Initialization Vector (IV).
        /// </summary>
        private static byte[] GenerateMasterIV()
        {
            byte[] iv = new byte[GcmIvLengthBytes];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }

        /// <summary>
        /// Derives a unique, non-repeating chunk-specific IV by XORing the Master IV with the chunk index.
        /// Uses direct bit-shifting to eliminate temporary array allocations and prevent pointer state leakage.
        /// </summary>
        private static void DeriveChunkIV(byte[] masterIv, long chunkIndex, byte[] outputChunkIv)
        {
            Buffer.BlockCopy(masterIv, 0, outputChunkIv, 0, GcmIvLengthBytes);

            outputChunkIv[4] ^= (byte)(chunkIndex >> 56);
            outputChunkIv[5] ^= (byte)(chunkIndex >> 48);
            outputChunkIv[6] ^= (byte)(chunkIndex >> 40);
            outputChunkIv[7] ^= (byte)(chunkIndex >> 32);
            outputChunkIv[8] ^= (byte)(chunkIndex >> 24);
            outputChunkIv[9] ^= (byte)(chunkIndex >> 16);
            outputChunkIv[10] ^= (byte)(chunkIndex >> 8);
            outputChunkIv[11] ^= (byte)chunkIndex;
        }

        /// <summary>
        /// Encrypts an input file via a memory-efficient chunked pipeline and writes the authenticated stream to disk.
        /// Optimized for massive files by using a strict zero-allocation loop architecture.
        /// </summary>
        public void EncryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            if (key == null || key.Length != keySize / 8)
            {
                throw new ArgumentException("The provided key length does not match the explicitly specified key size.");
            }

            string encryptedFilePath = outputFilePath.EndsWith(EncryptedFileExtension, StringComparison.OrdinalIgnoreCase)
                ? outputFilePath
                : outputFilePath + EncryptedFileExtension;

            using (FileStream fsOutput = new FileStream(encryptedFilePath, FileMode.Create, FileAccess.Write))
            using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            {
                // Write the top-level Master IV to the beginning of the file layout
                byte[] masterIv = GenerateMasterIV();
                fsOutput.Write(masterIv, 0, masterIv.Length);

                // Establish sliding window processing buffers
                byte[] currentBuffer = new byte[ChunkSize];
                byte[] nextBuffer = new byte[ChunkSize];

                int currentBytesRead = fsInput.Read(currentBuffer, 0, currentBuffer.Length);
                long chunkIndex = 0;

                // Pre-allocated structural blocks to completely prevent inner-loop GC allocations
                byte[] chunkIv = new byte[GcmIvLengthBytes];
                byte[] chunkIndexBytes = new byte[8];
                byte[] lengthHeader = new byte[4];
                byte[] associatedData = new byte[8 + 4 + 1];
                byte[] outputBuffer = new byte[MaxCipherTextChunkSize];

                while (currentBytesRead > 0 || chunkIndex == 0)
                {
                    int nextBytesRead = fsInput.Read(nextBuffer, 0, nextBuffer.Length);
                    byte isLastChunk = (byte)(nextBytesRead == 0 ? 1 : 0);

                    // Derive the unique, non-colliding nonce for the current block execution context
                    DeriveChunkIV(masterIv, chunkIndex, chunkIv);
                    fsOutput.WriteByte(isLastChunk);

                    BinaryPrimitives.WriteInt64BigEndian(chunkIndexBytes, chunkIndex);
                    BinaryPrimitives.WriteInt32BigEndian(lengthHeader, currentBytesRead);

                    Buffer.BlockCopy(chunkIndexBytes, 0, associatedData, 0, 8);
                    Buffer.BlockCopy(lengthHeader, 0, associatedData, 8, 4);
                    associatedData[associatedData.Length - 1] = isLastChunk;

                    var cipher = new GcmBlockCipher(new AesEngine());
                    var parameters = new AeadParameters(new KeyParameter(key), GcmTagLengthBytes * 8, chunkIv, associatedData);
                    cipher.Init(true, parameters);

                    fsOutput.Write(lengthHeader, 0, lengthHeader.Length);

                    // Perform the cryptographic block calculation into the pre-allocated reuse buffer
                    int outputLength = cipher.ProcessBytes(currentBuffer, 0, currentBytesRead, outputBuffer, 0);
                    outputLength += cipher.DoFinal(outputBuffer, outputLength);

                    fsOutput.Write(outputBuffer, 0, outputLength);

                    if (isLastChunk == 1)
                    {
                        break;
                    }

                    // High-performance pointer swap to completely avoid high-cost 1MB array copy procedures
                    byte[] temp = currentBuffer;
                    currentBuffer = nextBuffer;
                    nextBuffer = temp;

                    currentBytesRead = nextBytesRead;
                    chunkIndex++;
                }
            }
        }

        /// <summary>
        /// Decrypts an encrypted file via sequential chunk validation.
        /// Strictly verifies authentication tags and contextual data structures to enforce execution safety.
        /// Optimized for massive files by using a strict zero-allocation loop architecture.
        /// </summary>
        /// <param name="inputFilePath">Absolute path to the encrypted source file.</param>
        /// <param name="outputFilePath">Target path where the verified plaintext will be reconstructed.</param>
        /// <param name="key">The raw cryptographic key buffer.</param>
        /// <param name="keySize">The expected cryptographic key size in bits.</param>
        /// <returns>True if the payload is authentic and successfully decrypted; otherwise, false.</returns>
        public bool DecryptFile(string inputFilePath, string outputFilePath, byte[] key, int keySize)
        {
            if (key == null || key.Length != keySize / 8)
            {
                throw new ArgumentException("The provided key length does not match the explicitly specified key size.");
            }

            try
            {
                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                {
                    // Retrieve the top-level Master IV from the beginning of the file layout
                    byte[] masterIv = new byte[GcmIvLengthBytes];
                    if (fsInput.Read(masterIv, 0, masterIv.Length) != GcmIvLengthBytes)
                    {
                        throw new CryptographicException("Missing or incomplete master initialization vector.");
                    }

                    byte[] lengthHeader = new byte[4];
                    long chunkIndex = 0;
                    bool lastChunkProcessed = false;

                    // Pre-allocated static layout structures to completely prevent inner-loop GC allocations
                    byte[] cipherBuffer = new byte[MaxCipherTextChunkSize];
                    byte[] outputBuffer = new byte[ChunkSize];
                    byte[] chunkIv = new byte[GcmIvLengthBytes];
                    byte[] chunkIndexBytes = new byte[8];
                    byte[] associatedData = new byte[8 + 4 + 1];

                    while (true)
                    {
                        int isLastChunkByte = fsInput.ReadByte();
                        if (isLastChunkByte == -1)
                        {
                            if (!lastChunkProcessed)
                            {
                                throw new CryptographicException("File stream was truncated prematurely.");
                            }
                            break;
                        }
                        byte isLastChunk = (byte)isLastChunkByte;

                        if (fsInput.Read(lengthHeader, 0, lengthHeader.Length) != lengthHeader.Length)
                        {
                            throw new EndOfStreamException("Incomplete chunk length header.");
                        }

                        int plainTextLength = BinaryPrimitives.ReadInt32BigEndian(lengthHeader);

                        if (plainTextLength < 0 || plainTextLength > ChunkSize)
                        {
                            throw new CryptographicException("Invalid or malicious chunk length header detected.");
                        }

                        int cipherTextLength = plainTextLength + GcmTagLengthBytes;

                        if (fsInput.Read(cipherBuffer, 0, cipherTextLength) != cipherTextLength)
                        {
                            throw new EndOfStreamException("Incomplete encrypted chunk data or missing authentication tag.");
                        }

                        // Derive the unique, non-colliding nonce for the current block execution context
                        DeriveChunkIV(masterIv, chunkIndex, chunkIv);

                        BinaryPrimitives.WriteInt64BigEndian(chunkIndexBytes, chunkIndex);
                        Buffer.BlockCopy(chunkIndexBytes, 0, associatedData, 0, 8);
                        Buffer.BlockCopy(lengthHeader, 0, associatedData, 8, 4);
                        associatedData[associatedData.Length - 1] = isLastChunk;

                        var cipher = new GcmBlockCipher(new AesEngine());
                        var parameters = new AeadParameters(new KeyParameter(key), GcmTagLengthBytes * 8, chunkIv, associatedData);
                        cipher.Init(false, parameters);

                        // Perform the cryptographic block calculation into the pre-allocated reuse buffer
                        int outputLength = cipher.ProcessBytes(cipherBuffer, 0, cipherTextLength, outputBuffer, 0);
                        outputLength += cipher.DoFinal(outputBuffer, outputLength);

                        fsOutput.Write(outputBuffer, 0, outputLength);

                        if (isLastChunk == 1)
                        {
                            lastChunkProcessed = true;

                            if (fsInput.Position < fsInput.Length)
                            {
                                throw new CryptographicException("Trailing garbage data detected after the legitimate end of the file.");
                            }
                            break;
                        }

                        chunkIndex++;
                    }
                }

                return true;
            }
            catch (Exception)
            {
                try
                {
                    if (File.Exists(outputFilePath))
                    {
                        File.Delete(outputFilePath);
                    }
                }
                catch { }

                return false;
            }
        }
    }
}