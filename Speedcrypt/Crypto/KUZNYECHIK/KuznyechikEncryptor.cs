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

using OpenGost.Security.Cryptography;

namespace Speedcrypt.Crypto.KUZNYECHIK
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// KuznyechikEncryptor: Provides authenticated file encryption and decryption
    /// using GOST R 34.12-2015 (Kuznyechik/Grasshopper) in CBC mode with PKCS7 padding.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements secure Kuznyechik-based file encryption within the
    /// Speedcrypt framework:
    /// - Encrypts files using Kuznyechik (Grasshopper) in CBC mode with PKCS7 padding
    /// - Normalizes keys to the required 256-bit (32-byte) size
    /// - Generates a cryptographically secure random 16-byte IV for every encryption
    /// - Stores the IV at the beginning of the encrypted file
    /// - Protects ciphertext integrity with an appended HMAC-SHA256 authentication tag
    /// - Verifies integrity before accepting decrypted output
    /// - Processes files using buffered sequential stream I/O for efficient handling of very large files
    /// - Uses temporary-file replacement to prevent corrupted plaintext from being exposed
    /// - Automatically appends the .SPCR extension to encrypted files
    /// - Uses constant-time HMAC comparison to mitigate timing attacks
    ///
    /// Security notes:
    /// - A unique IV is generated for every encryption operation
    /// - Encrypt-then-MAC provides strong confidentiality and integrity guarantees
    /// - Authentication is verified before decrypted data is committed
    /// - Independent cryptographic instances prevent state reuse
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public static class KuznyechikEncryptor
    {
        public static string EncryptedFileExtension { get; private set; } = ".SPCR"; // Speed Crypt default extension

        private const int IvLength = 16;
        private const int HmacLength = 32;
        private const int BufferSize = 1024 * 1024; // 1 MB buffer for high-speed sequential disk I/O

        /// <summary>
        /// Custom Write-Only stream that calculates the HMAC-SHA256 automatically 
        /// on the ciphertext while it is being written to the disk.
        /// </summary>
        private sealed class HmacAppendWriteStream : Stream
        {
            private readonly Stream _baseStream;
            private readonly HMACSHA256 _hmac;

            public HmacAppendWriteStream(Stream baseStream, HMACSHA256 hmac)
            {
                _baseStream = baseStream;
                _hmac = hmac;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                _baseStream.Write(buffer, offset, count);
                _hmac.TransformBlock(buffer, offset, count, null, 0);
            }
            public override bool CanWrite => true;
            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() => _baseStream.Flush();
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }

        /// <summary>
        /// Encrypts files of any size (10GB+) in a single sequential pass.
        /// The HMAC is calculated concurrently during encryption and appended at the end of the file,
        /// avoiding any stream rewinding or position corruption.
        /// </summary>
        public static void EncryptFile(string inputFilePath, string outputFilePath, byte[] key)
        {
            key = NormalizeKey(key);
            byte[] iv = GenerateIV();
            string encryptedFilePath = outputFilePath + EncryptedFileExtension;

            using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan))
            using (FileStream fsOutput = new FileStream(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize))
            using (var hmac = new HMACSHA256(key))
            {
                // 1. Write the 16-byte Initialization Vector at the very beginning
                fsOutput.Write(iv, 0, iv.Length);

                // 2. Wrap the output stream into our custom HMAC calculator stream
                using (var hmacStream = new HmacAppendWriteStream(fsOutput, hmac))
                using (var kuz = new GrasshopperManaged())
                {
                    kuz.Key = key;
                    kuz.IV = iv;
                    kuz.Mode = CipherMode.CBC;
                    kuz.Padding = PaddingMode.PKCS7;

                    using (var encryptor = kuz.CreateEncryptor())
                    using (var cryptoStream = new CryptoStream(hmacStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] buffer = new byte[BufferSize];
                        int bytesRead;

                        // 3. Encrypt and stream blocks sequentially
                        while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            cryptoStream.Write(buffer, 0, bytesRead);
                        }

                        cryptoStream.FlushFinalBlock();
                    }
                }

                // 4. Finalize the HMAC calculation over all the written ciphertext data
                hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                byte[] computedHmac = hmac.Hash;

                // 5. Append the 32-byte HMAC signature directly at the tail of the file
                fsOutput.Write(computedHmac, 0, computedHmac.Length);
            }
        }

        /// <summary>
        /// Custom Read-Only stream that calculates the HMAC-SHA256 automatically 
        /// on the ciphertext while it is being read from the disk for decryption.
        /// </summary>
        private sealed class HmacReadStream : Stream
        {
            private readonly Stream _baseStream;
            private readonly HMACSHA256 _hmac;
            private long _cipherBytesRemaining;

            public HmacReadStream(Stream baseStream, HMACSHA256 hmac, long cipherLength)
            {
                _baseStream = baseStream;
                _hmac = hmac;
                _cipherBytesRemaining = cipherLength;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_cipherBytesRemaining <= 0) return 0;

                int toRead = (int)Math.Min(count, _cipherBytesRemaining);
                int bytesRead = _baseStream.Read(buffer, offset, toRead);

                if (bytesRead > 0)
                {
                    _hmac.TransformBlock(buffer, offset, bytesRead, null, 0);
                    _cipherBytesRemaining -= bytesRead;
                }

                return bytesRead;
            }
            public override bool CanRead => true;
            public override bool CanWrite => false;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        /// <summary>
        /// Decrypts a file of any size sequentially while ensuring integrity using an encrypt-then-mac approach.
        /// Employs a temporary file pattern to mitigate Padding Oracle attacks and prevent data corruption.
        /// </summary>
        /// <param name="inputFilePath">The path to the encrypted file.</param>
        /// <param name="outputFilePath">The target path for the decrypted file.</param>
        /// <param name="key">The encryption/HMAC key.</param>
        /// <returns>True if decryption and integrity verification succeed; otherwise, false.</returns>
        public static bool DecryptFile(string inputFilePath, string outputFilePath, byte[] key)
        {
            bool isIntegrityValid = false;

            // Generate a unique temporary path in the same directory to ensure fast metadata-only file moving
            string tempFilePath = outputFilePath + ".tmp_" + Guid.NewGuid().ToString("N");

            try
            {
                key = NormalizeKey(key);

                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, FileOptions.SequentialScan))
                {
                    // Minimum required size: IV (16) + HMAC (32) + at least 1 ciphertext block (16)
                    if (fsInput.Length < IvLength + HmacLength + 16)
                    {
                        return false;
                    }

                    byte[] iv = new byte[IvLength];
                    fsInput.Read(iv, 0, iv.Length);

                    long cipherLength = fsInput.Length - IvLength - HmacLength;

                    using (var hmac = new HMACSHA256(key))
                    using (var hmacStream = new HmacReadStream(fsInput, hmac, cipherLength))
                    using (var kuz = new GrasshopperManaged())
                    {
                        kuz.Key = key;
                        kuz.IV = iv;
                        kuz.Mode = CipherMode.CBC;
                        kuz.Padding = PaddingMode.PKCS7;

                        using (var decryptor = kuz.CreateDecryptor())
                        using (var cryptoStream = new CryptoStream(hmacStream, decryptor, CryptoStreamMode.Read))
                        using (FileStream fsTempOutput = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write, FileShare.None, BufferSize))
                        {
                            // Stream decrypted data into the isolated temporary file
                            cryptoStream.CopyTo(fsTempOutput, BufferSize);
                        }

                        // Finalize the continuous ciphertext HMAC calculation
                        hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                        byte[] calculatedHmac = hmac.Hash;

                        // Seek to the end to read the authentic trailing HMAC signature
                        fsInput.Position = fsInput.Length - HmacLength;
                        byte[] storedHmac = new byte[HmacLength];
                        fsInput.Read(storedHmac, 0, storedHmac.Length);

                        // Constant-time verification to prevent timing side-channel attacks
                        isIntegrityValid = FixedTimeEquals(storedHmac, calculatedHmac);
                    }
                }

                // File operations handled outside of stream scopes to avoid active file locks
                if (isIntegrityValid)
                {
                    if (File.Exists(outputFilePath))
                    {
                        File.Delete(outputFilePath);
                    }

                    // Atomic file system swap: instantaneous operation even for massive files (10GB+)
                    File.Move(tempFilePath, outputFilePath);
                    return true;
                }
                else
                {
                    // Purge unauthenticated decrypted data immediately if integrity check fails
                    if (File.Exists(tempFilePath))
                    {
                        File.Delete(tempFilePath);
                    }
                    return false;
                }
            }
            catch
            {
                // Safe cleanup cascade for unexpected runtime faults or cryptographic padding failures
                try
                {
                    if (File.Exists(tempFilePath)) { File.Delete(tempFilePath); }
                }
                catch { }

                return false;
            }
        }
        private static byte[] NormalizeKey(byte[] key)
        {
            byte[] normalized = new byte[32];
            if (key != null)
            {
                Array.Copy(key, normalized, Math.Min(key.Length, 32));
            }
            return normalized;
        }
        private static byte[] GenerateIV()
        {
            byte[] iv = new byte[IvLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }    
}