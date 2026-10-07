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

namespace Speedcrypt.Securerase.RCMPTSSITOPSII
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// RCMPTSSIT: Implements RCMP TSSIT OPS-II secure file erasure standard.
    /// Multiple fixed and random overwrite passes ensure high-security destruction of sensitive data.
    /// Integrates centralized logging for any IO exceptions during the erase process.
    /// Designed for Speedcrypt framework with attention to HDD effectiveness and high-security environments.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Multiple overwrite passes using fixed patterns and cryptographically secure random bytes
    /// - Truncation and deletion of the file after overwrite
    /// - Proper handling of read-only, hidden, and system attributes (via FileInfo prior to overwrite)
    /// - Any IO failure is logged centrally and treated as a critical operation issue
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    
    public static class RCMPTSSIT
    {
        public const string Description =
            "This method adheres to the RCMP TSSIT OPS-II standard used by the ROYAL CANADIAN MOUNTED POLICE. " +
            "It performs multiple passes using a combination of fixed and random data to ensure secure erasure. " +
            "Designed for high-security environments where classified data must be permanently destroyed.";

        /// <summary>
        /// Securely erases a file following the RCMP TSSIT OPS-II standard via a unified file stream context.
        /// Executes a 7-pass sequence (0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, and random noise).
        /// Enforces hardware write-through constraints and memory-efficient single-allocation buffering.
        /// </summary>
        /// <param name="filePath">Full path of the file to securely erase.</param>
        public static void RCMP_TSSIT_OPS_II(string filePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    throw new FileNotFoundException("File not found.", filePath);

                FileInfo fileInfo = new FileInfo(filePath);
                long fileLength = fileInfo.Length;

                // Strip restrictive file attributes to prevent access-denied exceptions during block overwrite
                fileInfo.Attributes &= ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);

                // RCMP TSSIT OPS-II sequence: 6 alternating fixed passes followed by 1 final random pass
                var passes = new (bool isRandom, byte value)[]
                {
                (false, 0x00), // Pass 1: Zeros
                (false, 0xFF), // Pass 2: Ones
                (false, 0x00), // Pass 3: Zeros
                (false, 0xFF), // Pass 4: Ones
                (false, 0x00), // Pass 5: Zeros
                (false, 0xFF), // Pass 6: Ones
                (true,  0x00)  // Pass 7: Cryptographic noise
                };

                const int bufferSize = 8192; // Standardized 8 KB buffer for optimal memory-boundary alignment
                byte[] buffer = new byte[bufferSize];

                // Initialize Thread-Safe Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
                using (var rng = RandomNumberGenerator.Create())
                // Open file exactly ONCE to mitigate I/O descriptor overhead across high-volume sequential batch operations
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
                            int toWrite = (int)Math.Min(buffer.Length, fileLength - written);

                            if (pass.isRandom)
                            {
                                rng.GetBytes(buffer, 0, toWrite);
                            }
                            else
                            {
                                FillBuffer(buffer, pass.value, toWrite);
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

                // Unlink and permanently purge the physical record from the file system
                File.Delete(filePath);
            }
            catch (IOException ex)
            {
                // Execute centralized telemetry logging using deterministic path traceability
                CentralLog.LogException(ex, "RCMPTSSIT", "RCMP_TSSIT_OPS_II failed for file: " + filePath + " - " + ex.Message);
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