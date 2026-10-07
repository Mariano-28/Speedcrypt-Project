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

namespace Speedcrypt.Securerase.BritishHMGIS5
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// HmgIs5Eraser: Enterprise-grade secure file erasure class implementing the British HMG Infosec Standard No. 5.
    /// Designed for Speedcrypt SecureErase module supporting Baseline (3-pass) and Enhanced (7-pass) overwrite methodologies.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Secure erasure of files using official HMG IS5 overwrite patterns combining fixed values and cryptographic random noise.
    /// - Baseline mode sequence: 3 passes utilizing structural overwrites (0x00, 0xFF, followed by random bytes generation).
    /// - Enhanced mode sequence: 7 passes enforcing an extended sequence of alternative fixed patterns and cryptographic random sweeping.
    /// - Enforced hardware write-through capabilities (FileOptions.WriteThrough) coupled with low-level disk sector flushing (fs.Flush(true)) to eliminate OS cache evasion.
    /// - Optimized high-performance architecture using an expanded 64 KB buffer array to maximize data throughput during massive serial file erasures.
    /// - Adaptive system safety that clears file system blockades (FileAttributes.Normal) to mitigate unauthorized access or read-only execution faults.
    /// - Native SIMD vector optimizations leveraging Array.Fill routines on modern .NET environments.
    /// - Post-overwrite physical security that truncates byte stream lengths to absolute zero prior to invoking the terminal OS file deletion.
    /// - Fully insulated exception handling routing error tracking metadata into the centralized Speedcrypt CentralLog architecture.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    public static class HmgIs5Eraser
    {
        public const string Description =
            "This method follows the British HMG Infosec Standard No. 5. " +
            "It supports two modes: Baseline (3-pass) and Enhanced (7-pass). " +
            "Baseline overwrites the file 3 times: 0x00, 0xFF, and random data. " +
            "Enhanced overwrites the file 7 times using a defined sequence of fixed and random patterns. " +
            "Works reliably on HDDs; effectiveness on SSDs is limited due to wear-leveling. " +
            "Suitable for confidential and secret data removal across magnetic and solid-state storage.";
        public static void Erase(string filePath, bool enhanced = false)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    throw new FileNotFoundException("Target file for secure erasure was not found.", filePath);

                // Neutralize ReadOnly, Hidden, or System attributes to prevent access violations during low-level stream write operations
                File.SetAttributes(filePath, FileAttributes.Normal);

                var fileInfo = new FileInfo(filePath);
                long fileLength = fileInfo.Length;

                var baselinePasses = new (bool isRandom, byte? value)[]
                {
                (false, 0x00),
                (false, 0xFF),
                (true,  null)
                };

                var enhancedPasses = new (bool isRandom, byte? value)[]
                {
                (false, 0x00),
                (false, 0xFF),
                (true,  null),
                (false, 0x00),
                (false, 0xFF),
                (true,  null),
                (true,  null)
                };

                var passes = enhanced ? enhancedPasses : baselinePasses;

                // 64KB buffer size optimized for high-throughput sequential disk writes on large files
                byte[] buffer = new byte[65536];

                using (var rng = RandomNumberGenerator.Create())
                // Enforce WriteThrough to instruct the OS cache manager to commit data directly to physical sectors immediately
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    foreach (var pass in passes)
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
                CentralLog.LogException(ex, "HmgIs5Eraser.Erase", "Secure file erasure execution failed: " + ex.Message);
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