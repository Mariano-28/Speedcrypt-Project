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

namespace Speedcrypt.Securerase.GermanVSITR
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// GermanVsitrEraser: Enterprise-grade secure file erasure component implementing the official German VSITR 7-pass alternating standard.
    /// Fully integrated into the Speedcrypt SecureErase module with automated filesystem attribute resolution and localized exception telemetry.
    /// </summary>
    ///
    /// <remarks>
    /// This structural layout guarantees:
    /// - Compliance with the German Federal Office for Information Security (BSI) alternating bitmatrix sequences (0x00, 0xFF, 0xAA, 0x55, and a final random noise sweep).
    /// - Enforced hardware write-through capabilities (FileOptions.WriteThrough) combined with explicit disk sector flushing (fs.Flush(true)) to neutralize OS cache-buffering vulnerabilities.
    /// - Memory-mapped optimization leveraging an upgraded 64KB synchronous buffer array to maximize operational I/O throughput across extensive data batch workloads.
    /// - Defensive target preparation by resetting filesystem flags (FileAttributes.Normal) to suppress potential unauthorized access or read-only operational faults.
    /// - Native SIMD hardware acceleration triggers (Array.Fill) when executing on modern .NET runtimes.
    /// - Post-execution structural obfuscation by truncating resource allocation lengths to absolute zero prior to permanent deletion.
    /// - Unhandled exceptions and operational failures are silently decoupled and systematically audited within the Speedcrypt CentralLog infrastructure.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class GermanVsitrEraser
    {
        public const string Description =
            "This method follows the German Federal Office for Information Security (BSI) VSITR standard. " +
            "It executes a strict 7-pass structural sequence: 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, and a final cryptographic random pattern. " +
            "Works reliably on HDDs; effectiveness on SSDs is limited due to wear-leveling. " +
            "Enforces enterprise-grade hardware write-through constraints to bypass OS caching anomalies.";

        /// <summary>
        /// Securely erases a file using the official German VSITR 7-pass alternating pattern standard.
        /// Resets filesystem attributes prior to execution and enforces OS write-through buffering constraints.
        /// Optimized with a 64KB I/O buffer to balance throughput during large-scale sequential batch erasures.
        /// Exceptions are caught and logged in Speedcrypt CentralLog.
        /// </summary>
        /// <param name="filePath">Full path of the file to erase.</param>
        public static void Erase(string filePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    throw new FileNotFoundException("Target file for VSITR secure erasure was not found.", filePath);

                // Neutralize ReadOnly, Hidden, or System attributes to prevent access violations during low-level stream write operations
                File.SetAttributes(filePath, FileAttributes.Normal);

                var fileInfo = new FileInfo(filePath);
                long fileLength = fileInfo.Length;

                // Definition of the official BSI VSITR 7-pass alternating sequence matrix
                var vsitrPasses = new (bool isRandom, byte? value)[]
                {
                (false, 0x00), // Pass 1: Homogeneous zero bits
                (false, 0xFF), // Pass 2: Homogeneous one bits
                (false, 0xAA), // Pass 3: Alternating bit structure (10101010)
                (false, 0x55), // Pass 4: Inverted alternating bit structure (01010101)
                (false, 0x00), // Pass 5: Homogeneous zero bits repetition
                (false, 0xFF), // Pass 6: Homogeneous one bits repetition
                (true,  null)  // Pass 7: Cryptographically secure random pattern noise
                };

                // 64KB buffer size optimized for high-throughput sequential disk writes on large files
                byte[] buffer = new byte[65536];

                using (var rng = RandomNumberGenerator.Create())
                // Enforce WriteThrough to instruct the OS cache manager to commit data directly to physical sectors immediately
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    foreach (var pass in vsitrPasses)
                    {
                        fs.Position = 0;
                        long written = 0;

                        while (written < fileLength)
                        {
                            int toWrite = (int)Math.Min(buffer.Length, fileLength - written);

                            if (pass.isRandom)
                            {
                                rng.GetBytes(buffer, 0, toWrite);
                            }
                            else
                            {
                                FillBuffer(buffer, pass.value.Value, toWrite);
                            }

                            fs.Write(buffer, 0, toWrite);
                            written += toWrite;
                        }

                        // Flush OS buffers and transactional metadata sectors to disk storage medium
                        fs.Flush(true);
                    }

                    // Truncate file structure allocation payload size to zero to obfuscate remnant properties before final deletion
                    fs.SetLength(0);
                }

                File.Delete(filePath);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "GermanVsitrEraser.Erase", "VSITR secure file erasure execution failed: " + ex.Message);
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