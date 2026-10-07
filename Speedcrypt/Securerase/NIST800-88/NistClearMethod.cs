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

namespace Speedcrypt.Securerase.NIST800_88
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// NistClearMethod: Implements NIST SP 800-88 Rev.1 media sanitization guidelines for secure file erasure.
    /// Integrates centralized logging for any IO exceptions encountered during the clearing process.
    /// Designed for Speedcrypt framework with multi-pass overwrite and truncation.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Secure multi-pass file overwrite following NIST SP 800-88 Rev.1
    /// - Proper removal of read-only, hidden, and system attributes
    /// - File renaming to reduce trace of original name
    /// - File truncation and deletion after overwrite
    /// - Any IO failure is logged centrally and treated as a critical operation issue
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    
    public static class NistClearMethod
    {
        public const string Description = "This algorithm follows the NIST Special Publication 800-88 Revision 1 guidelines for media sanitization...";

        /// <summary>
        /// Securely clears a file following NIST SP 800-88 Rev.1 guidelines.
        /// Handles multi-pass overwrite, attribute removal, renaming, truncation, and deletion.
        /// Logs any IO exceptions centrally with deterministic path traceability.
        /// </summary>
        /// <param name="filePath">Path of the file to be cleared.</param>
        /// <returns>Returns "Success" if operation completes, "Fail" otherwise.</returns>
        public static string ClearFile(string filePath)
        {
            // Preserve original path target to guarantee strict compliance auditing in case of runtime failure
            string originalFilePath = filePath;

            try
            {
                // Validate input and verify physical file existence before initiating sanitization pipeline
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    throw new FileNotFoundException("File not found.", filePath);

                FileInfo fileInfo = new FileInfo(filePath);
                long length = fileInfo.Length;

                // Strip restrictive file attributes to prevent access-denied exceptions during block overwrite
                fileInfo.Attributes &= ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);

                // Obfuscate metadata footprint by renaming the physical file allocation table entry
                string directory = fileInfo.DirectoryName ?? throw new IOException("Unable to determine directory.");
                string tempName = Path.Combine(directory, Path.GetRandomFileName());
                File.Move(filePath, tempName);
                filePath = tempName;

                // Standardized multi-pass sanitization sequence executing a tactical mix of static blocks and hardware entropy
                var passes = new (bool isRandom, byte? fixedValue)[]
                {
                (false, 0x00), // Pass 1: Zero-fill baseline
                (false, 0xFF), // Pass 2: High-state inversion
                (true,  null), // Pass 3: Cryptographic noise injection
                (false, 0xAA), // Pass 4: Alternating bit pattern Alpha
                (false, 0x55), // Pass 5: Alternating bit pattern Beta
                (true,  null), // Pass 6: Cryptographic noise injection
                (false, 0x00), // Pass 7: Zero-fill purge
                (false, 0xFF), // Pass 8: High-state inversion purge
                (true,  null)  // Final high-entropy randomization pass
                };

                // High-throughput 8 KB operational buffer optimized for memory-boundary alignment
                const int bufferSize = 8192;
                byte[] buffer = new byte[bufferSize];

                // Initialize Thread-Safe Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
                using (var rng = RandomNumberGenerator.Create())
                // Establish exclusive, non-shareable write stream with absolute disk cache bypass enforcement
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None, bufferSize, FileOptions.WriteThrough))
                {
                    foreach (var pass in passes)
                    {
                        // Seek back to zero-origin position for the subsequent overwriting pass
                        fs.Position = 0;
                        long written = 0;

                        // Execute block-by-block disk layout destruction until EOF boundary matches original length
                        while (written < length)
                        {
                            int toWrite = (int)Math.Min(buffer.Length, length - written);

                            // Populate internal buffer dynamically based on pass-level cryptographic configuration
                            if (pass.isRandom)
                            {
                                rng.GetBytes(buffer, 0, toWrite);
                            }
                            else
                            {
                                FillBuffer(buffer, pass.fixedValue.Value, toWrite);
                            }

                            fs.Write(buffer, 0, toWrite);
                            written += toWrite;
                        }

                        // Force an immediate low-level hardware controller cache flush to physical media storage
                        fs.Flush(true);
                    }

                    // Truncate high-level allocation entry table size down to zero bytes to clear physical geometry indicators
                    fs.SetLength(0);
                }

                // Unlink and permanently purge the temporary obfuscated file record from the file system
                File.Delete(filePath);
                return "Success";
            }
            catch (IOException ex)
            {
                // Execute centralized telemetry logging using original target reference for regulatory auditing integrity
                CentralLog.LogException(ex, "NistClearMethod", "ClearFile failed for file: " + originalFilePath + " - " + ex.Message);
                return "Fail";
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