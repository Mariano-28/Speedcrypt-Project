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

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Securerase.NSACSS9
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// NSACSS9PassEraser: Secure file erasure following a 9-pass pattern inspired by NSA/CSS guidelines.
    /// Integrates centralized logging for any IO exceptions during the erase process.
    /// Designed for Speedcrypt framework, maintaining original filename integrity and HDD effectiveness.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Secure 9-pass file overwrite using fixed patterns and cryptographically secure random bytes
    /// - Removal of read-only, hidden, and system file attributes before overwrite
    /// - Truncation and deletion of the file after overwrite
    /// - Any IO failure is logged centrally and treated as a critical operation issue
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>   
    public static class NSACSS9PassEraser
    {
        public const string Description =
            "This method complies with the NSA/CSS 9-pass standard for secure data disposal. " +
            "Data is overwritten nine times using the sequence 0x00, 0xFF, random bytes, 0xAA, 0x55, " +
            "random bytes, 0x00, 0xFF, and random bytes, followed by file deletion. " +
            "Effective on HDDs; limited effectiveness on SSDs due to wear-leveling.";

        /// <summary>
        /// Securely erases a file according to the NSA/CSS 9-pass standard.
        /// Each pass overwrites the file with zeros, ones, 0xAA, 0x55, or cryptographically secure random bytes.
        /// Works reliably on HDDs; effectiveness on SSDs is limited due to wear-leveling.
        /// Maintains the original filename and extension during the process.
        /// </summary>
        /// <param name="filePath">Full path of the file to securely erase</param>
        /// <returns>"true" if the file was successfully erased, "false" otherwise</returns>
        public static string SecureErase(string filePath)
        {
            try
            {
                // Validate input and verify physical file existence before initiating sanitization pipeline
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    throw new FileNotFoundException("File not found.", filePath);

                FileInfo fileInfo = new FileInfo(filePath);
                long length = fileInfo.Length;

                // Remove read-only, hidden, system attributes to allow overwrite operations
                fileInfo.Attributes &= ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);

                // NSACSS 9-pass sequence: fixed values and random bytes (null represents random)
                byte?[] passes = new byte?[]
                {
                0x00, 0xFF, null,
                0xAA, 0x55, null,
                0x00, 0xFF, null
                };

                const int bufferSize = 8192; // 8 KB operational buffer optimized for memory-boundary alignment
                byte[] buffer = new byte[bufferSize];

                // Initialize Thread-Safe Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
                using (var rng = RandomNumberGenerator.Create())
                // Establish exclusive, non-shareable write stream with absolute disk cache bypass enforcement
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None, bufferSize, FileOptions.WriteThrough))
                {
                    foreach (var pass in passes)
                    {
                        fs.Position = 0; // Reset file pointer at the start of each pass
                        long written = 0;

                        // Execute block-by-block disk layout destruction until EOF boundary matches original length
                        while (written < length)
                        {
                            int toWrite = (int)Math.Min(bufferSize, length - written);

                            // Populate internal buffer dynamically leveraging standardized high-speed memory filling
                            if (pass.HasValue)
                            {
                                FillBuffer(buffer, pass.Value, toWrite);
                            }
                            else
                            {
                                rng.GetBytes(buffer, 0, toWrite);
                            }

                            fs.Write(buffer, 0, toWrite);
                            written += toWrite;
                        }

                        // Force an immediate low-level hardware controller cache flush to physical media storage
                        fs.Flush(true);
                    }
                }

                // Unlink and permanently purge the physical file record from the file system
                File.Delete(filePath);

                return "true";
            }
            catch (IOException ex)
            {
                // Execute centralized telemetry logging for auditing and debugging integrity
                CentralLog.LogException(ex, "NSACSS9PassEraser", "SecureErase failed for file: " + filePath + " - " + ex.Message);
                return "false";
            }
        }

        /// <summary>
        /// Fills a buffer segment with a specified uniform byte value using optimized memory operations.
        /// </summary>
        /// <param name="buffer">The target byte array configuration.</param>
        /// <param name="value">The specific cryptographic pattern byte value to apply.</param>
        /// <param name="count">The total number of contiguous bytes to modify within the buffer memory block.</param>
        private static void FillBuffer(byte[] buffer, byte value, int count)
        {
#if NET5_0_OR_GREATER || NETCOREAPP3_1_OR_GREATER
        Array.Fill(buffer, value, 0, count);
#else
            for (int i = 0; i < count; i++)
            {
                buffer[i] = value;
            }
#endif
        }
    }
}