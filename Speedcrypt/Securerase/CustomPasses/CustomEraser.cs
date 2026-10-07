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
using System.Threading;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Securerase.CustomPasses
{
    // CustomEraser - Secure File Deletion Class
    // Copyright (C) 2023–2026 Mariano Ortu <https://www.sicurpas.it/>
    //
    // This class is free software: you can redistribute it and/or modify
    // it under the terms of the GNU General Public License as published by
    // the Free Software Foundation, either version 3 of the License, or
    // (at your option) any later version.
    //
    // This class is distributed in the hope that it will be useful,
    // but WITHOUT ANY WARRANTY; without even the implied warranty of
    // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    // GNU General Public License for more details.
    //
    // You should have received a copy of the GNU General Public License
    // along with this class. If not, see <https://www.gnu.org/licenses/gpl-3.0.html>.

    //*************************************************************************************

    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CustomEraser: Highly flexible enterprise-grade file destruction component allowing user-defined byte pattern execution.
    /// Supports programmatic injection of custom sequences using zeros, ones, and cryptographic random sweeps.
    /// Fully integrated into the Speedcrypt framework utilizing hardware write-through capabilities and centralized telemetry logging.
    /// </summary>
    ///
    /// <remarks>
    /// This architecture ensures:
    /// - Custom sequence execution through an injected array parameter configuration mapping to specialized data destruction topologies.
    /// - Hardened structural metadata obfuscation by executing a randomized filesystem rename routine (Path.GetRandomFileName) prior to low-level byte stream overwriting.
    /// - Enforced hardware write-through capabilities (FileOptions.WriteThrough) combined with explicit disk sector flushing (fs.Flush(true)) to neutralize OS cache-buffering vulnerabilities.
    /// - Memory-mapped optimization leveraging an upgraded 64KB synchronous buffer array to maximize operational I/O throughput across extensive data batch workloads.
    /// - Integrated thread cancellation token monitoring (CancellationToken) to support immediate and clean operational abort triggers.
    /// - Unhandled exceptions and operational failures are systematically decoupled from the presentation layer and captured directly into the Speedcrypt CentralLog infrastructure.
    ///
    /// Responsibility for this C# production implementation, structural design, integration layer, and runtime validation 
    /// lies entirely with the author.
    /// </remarks>
    /// 
    //*************************************************************************************

    // NOTE FOR INTEGRATION:
    // CustomEraser originates from Mariano Ortu's "Custom Erase Algorithm" project:
    // - Technical documentation: https://www.sicurpas.it/my-algorithms.html
    // - Official GitHub repository: https://github.com/Mariano-28/CustomEraseAlgorithm
    // - SourceForge download: https://sourceforge.net/projects/custom-erase-algorithm/
    //
    // Integrated into Speedcrypt SecureErase module for advanced file deletion.
    // All original licensing, authorship, and functionality fully preserved.

    public static class CustomEraser
    {
        public const string Description =
            "This method allows users to define a custom sequence of overwrite passes using zeros, ones, and random data. " +
            "The flexibility of this mode lets users balance between speed and security depending on their specific needs. " +
            "Best suited for advanced users who want full control over the erasure process.";

        /// <summary>
        /// Securely erases a file using an arbitrary user-defined sequence matrix.
        /// Obfuscates metadata via filesystem tracking mutation and enforces direct-to-disk write structures.
        /// Telemetry and processing faults are committed directly to CentralLog to prevent UI thread execution stalls.
        /// </summary>
        /// <param name="filePath">Full path of the file to erase.</param>
        /// <param name="passSequence">An array representing the structural order of custom pass execution targets.</param>
        /// <param name="cancellationToken">An evaluation token utilized to propagate asynchronous task interruption requests.</param>
        /// <returns>True if the file was successfully decoupled and destroyed; otherwise, false.</returns>
        public static bool SecureErase(string filePath, CustomPassType[] passSequence, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                CentralLog.LogException(new FileNotFoundException("Target file for custom erasure was not found."), "CustomEraser.SecureErase", filePath);
                return false;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);

                // Neutralize ReadOnly, Hidden, or System attributes to prevent access violations during low-level stream write operations
                fileInfo.Attributes &= ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System);

                // Mutate the original file name within the directory allocation table to reduce structural remnant footprints
                string directory = fileInfo.DirectoryName ?? throw new IOException("Unable to determine localized file directory layout context.");
                string randomFileName = Path.Combine(directory, Path.GetRandomFileName());

                while (File.Exists(randomFileName))
                {
                    randomFileName = Path.Combine(directory, Path.GetRandomFileName());
                }

                File.Move(filePath, randomFileName);

                // Remap target tracking reference to point directly to the mutated file structure configuration
                filePath = randomFileName;
                fileInfo = new FileInfo(filePath);
                long length = fileInfo.Length;

                // 64KB buffer size optimized for high-throughput sequential disk writes on large files
                byte[] buffer = new byte[65536];

                using (var rng = RandomNumberGenerator.Create())
                // Enforce WriteThrough to instruct the OS cache manager to commit data directly to physical sectors immediately
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    foreach (var pass in passSequence)
                    {
                        fs.Seek(0, SeekOrigin.Begin);
                        long totalWritten = 0;

                        while (totalWritten < length)
                        {
                            cancellationToken.ThrowIfCancellationRequested();

                            int toWrite = (int)Math.Min(buffer.Length, length - totalWritten);

                            switch (pass)
                            {
                                case CustomPassType.Zeros:
                                    Array.Clear(buffer, 0, toWrite);
                                    break;

                                case CustomPassType.Ones:
                                    FillBuffer(buffer, 0xFF, toWrite);
                                    break;

                                case CustomPassType.Random:
                                    rng.GetBytes(buffer, 0, toWrite);
                                    break;
                            }

                            fs.Write(buffer, 0, toWrite);
                            totalWritten += toWrite;
                        }

                        // Flush OS buffers and transactional metadata sectors to disk storage medium
                        fs.Flush(true);
                    }

                    // Truncate file structure allocation payload size to zero to obfuscate remnant properties before final deletion
                    fs.SetLength(0);
                }

                // Perform terminal deletion of the obfuscated and structurally scrubbed resource container
                File.Delete(filePath);
                return true;
            }
            catch (Exception ex)
            {
                // Decouple error telemetry from UI layer to guarantee unhindered multi-file sequential background processing loop execution
                CentralLog.LogException(ex, "CustomEraser.SecureErase", $"Secure erasure execution failed for path target: {filePath}");
                return false;
            }
        }

        /// <summary>
        /// Fills a buffer segment with a specified uniform byte value using optimized memory operations.
        /// </summary>
        /// <param name="buffer">The target byte array configuration.</param>
        /// <param name="value">The specific typographic pattern byte value to apply.</param>
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

    /// <summary>
    /// Supported custom overwrite pass byte configurations.
    /// </summary>
    public enum CustomPassType
    {
        /// <summary>
        /// Overwrites data fields using homogeneous zero bit allocations (0x00).
        /// </summary>
        Zeros,

        /// <summary>
        /// Overwrites data fields using homogeneous one bit allocations (0xFF).
        /// </summary>
        Ones,

        /// <summary>
        /// Overwrites data fields leveraging cryptographically secure pseudo-random noise sweeps.
        /// </summary>
        Random
    }
}