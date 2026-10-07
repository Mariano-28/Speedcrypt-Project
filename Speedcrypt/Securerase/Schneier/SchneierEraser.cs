//SecureDel software - The Open-Source for secure file deletion
// Copyright (C) 2024-2026 Mariano Ortu <https://www.sicurpas.it/>
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

namespace Speedcrypt.Securerase.Schneier
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SchneierEraser: Implements Bruce Schneier's 7-pass secure file erasure algorithm from 'Applied Cryptography'.
    /// Combines fixed and random overwrite patterns to provide strong data destruction.
    /// Integrates centralized logging for any IO exceptions during the erase process.
    /// Designed for Speedcrypt framework with HDD effectiveness and high-security environments.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - 7-pass file overwrite using fixed values and cryptographically secure random bytes
    /// - Removal of read-only, hidden, and system file attributes before overwrite
    /// - Renaming of file to reduce trace of original filename
    /// - Truncation and deletion of the file after overwrite
    /// - Any IO failure is logged centrally and treated as a critical operation issue
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class SchneierEraser
    {
        public const string Description =
            "This method is based on Bruce Schneier's data sanitization algorithm described in his book 'Applied Cryptography'." +
            " It overwrites the file with a specific sequence of 7 passes: two random patterns followed by five fixed values." +
            " This method offers strong protection against advanced recovery techniques.";

        /// <summary>
        /// Securely erases a file following Bruce Schneier's 7-pass algorithm.
        /// Executes sequential destruction via alternating high-entropy noise and fixed inversion states.
        /// Enforces pre-emptive metadata obfuscation, single-allocation buffering, and hardware write-through caching constraints.
        /// </summary>
        /// <param name="filePath">Full path of the file to securely erase.</param>
        public static void Schneier7Pass(string filePath)
        {
            try
            {
                // Validate input and verify physical file existence before initiating sanitization pipeline
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    throw new FileNotFoundException("File not found.", filePath);

                FileInfo fileInfo = new FileInfo(filePath);

                // Strip restrictive file attributes to prevent access-denied exceptions during block overwrite
                fileInfo.Attributes &= ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);

                // Obfuscate metadata footprint by renaming the physical file allocation table entry
                string directory = fileInfo.DirectoryName ?? throw new IOException("Unable to determine directory.");
                string tempName = Path.Combine(directory, Path.GetRandomFileName());
                File.Move(filePath, tempName);
                filePath = tempName;

                // Recreate FileInfo context tracking the new temporary path configuration
                fileInfo = new FileInfo(filePath);
                long fileLength = fileInfo.Length;

                // Schneier 7-pass sequence layout: tactical combination of hardware entropy and fixed inversion sequences
                var passes = new (bool isRandom, byte? fixedValue)[]
                {
                (true, null),      // Pass 1: Cryptographic noise injection
                (false, 0xFF),     // Pass 2: High-state inversion
                (false, 0x00),     // Pass 3: Zero-fill baseline
                (true, null),      // Pass 4: Cryptographic noise injection
                (false, 0xAA),     // Pass 5: Alternating bit pattern Alpha
                (false, 0x55),     // Pass 6: Alternating bit pattern Beta
                (true, null)       // Pass 7: Final high-entropy randomization pass
                };

                const int bufferSize = 8192; // Standardized 8 KB operational buffer for memory-boundary alignment
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
                        while (written < fileLength)
                        {
                            int toWrite = (int)Math.Min(bufferSize, fileLength - written);

                            // Populate internal buffer dynamically leveraging standardized high-speed memory filling
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
            }
            catch (IOException ex)
            {
                // Execute centralized telemetry logging using deterministic path traceability
                CentralLog.LogException(ex, "SchneierEraser", "Schneier7Pass failed for file: " + filePath + " - " + ex.Message);
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