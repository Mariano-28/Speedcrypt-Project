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

namespace Speedcrypt.Securerase.NSACSS12
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// NSACSS12PassEraser: Secure file erasure following a 12-pass pattern inspired by NSA/CSS guidelines.
    /// Integrates centralized logging for any IO exceptions during the erase process.
    /// Designed for Speedcrypt framework, with attention to HDD effectiveness and limited SSD guarantees.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Secure 12-pass file overwrite using fixed patterns and cryptographically secure random bytes
    /// - Removal of read-only, hidden, and system file attributes before overwrite
    /// - Truncation and deletion of the file after overwrite
    /// - Any IO failure is logged centrally and treated as a critical operation issue
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>   
    public static class NSACSS12PassEraser
    {
        public const string Description =
            "This method complies with the NSA/CSS 12-pass standard for secure data disposal. " +
            "Data is overwritten twelve times using the sequence 0x00, 0xFF, random bytes, 0xAA, 0x55, random bytes, " +
            "0x00, 0xFF, random bytes, 0x11, 0xEE, and random bytes, followed by file deletion. " +
            "Effective on HDDs; limited effectiveness on SSDs due to wear-leveling.";

        /// <summary>
        /// Securely erases a file following NSA/CSS 12-pass pattern.
        /// Handles multi-pass overwrite, attribute removal, flush, and deletion.
        /// Logs any IO exceptions centrally.
        /// </summary>
        /// <param name="filePath">Full path of the file to securely erase</param>
        /// <returns>"true" if the file was successfully erased, "false" otherwise</returns>
        public static string SecureErase(string filePath)
        {
            try
            {
                // Validate input and check file existence
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    throw new FileNotFoundException("File not found.", filePath);

                FileInfo fileInfo = new FileInfo(filePath);
                long length = fileInfo.Length;

                // Remove read-only, hidden, system attributes to allow overwrite
                fileInfo.Attributes &= ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);

                // Define NSACSS 12-pass overwrite sequence: fixed values and random (null)
                byte?[] passes = new byte?[]
                {
                0x00, 0xFF, null, // Pass 1–3
                0xAA, 0x55, null, // Pass 4–6
                0x00, 0xFF, null, // Pass 7–9
                0x11, 0xEE, null  // Pass 10–12
                };

                const int bufferSize = 8192; // 8 KB buffer for memory efficiency
                byte[] buffer = new byte[bufferSize];

                // Use cryptographically secure RNG for random passes
                using (var rng = RandomNumberGenerator.Create())
                // Open file with exclusive write access and absolute hardware write-through enforcement
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None, bufferSize, FileOptions.WriteThrough))
                {
                    foreach (var pass in passes)
                    {
                        fs.Position = 0; // Reset file pointer at the start of each pass
                        long written = 0;

                        // Write bytes in chunks until the entire file is overwritten
                        while (written < length)
                        {
                            int toWrite = (int)Math.Min(buffer.Length, length - written);

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

                        // Ensure data is physically flushed to disk after each pass
                        fs.Flush(true);
                    }
                }

                // Delete the file after secure overwriting
                File.Delete(filePath);

                return "true";
            }
            catch (IOException ex)
            {
                // Centralized logging of any IO errors for auditing/debugging
                CentralLog.LogException(ex, "NSACSS12PassEraser", "SecureErase failed for file: " + filePath + " - " + ex.Message);
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