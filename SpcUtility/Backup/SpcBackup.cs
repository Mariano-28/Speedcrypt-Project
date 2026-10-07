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
// https://www.gnu.org/licenses/gpl-3.0.html

using System.IO;
using System.IO.Compression;

namespace SpcUtility.Backup
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SpcBackup: Backup management class for Speedcrypt.
    /// Provides automatic and manual backup of critical application files
    /// by creating secure ZIP archives of essential program components.
    /// Designed for the Speedcrypt framework to ensure reliable recovery
    /// and preservation of core application binaries.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Secure backup of critical Speedcrypt executable and dependency files
    /// - Automatic creation of a protected internal backup in the application directory
    /// - Optional manual backup allowing the user to select a custom destination
    /// - Integrity of essential program components required for proper operation
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class SpcBackup
    {
        // List of critical files to backup
        private static readonly string[] CriticalFiles = new string[]
        {
        "OpenGost.Security.Cryptography.dll",
        "SpcShell.dll",
        "Speedcrypt.exe",
        "Speedcrypt.exe.config",
        "SpcUtility.exe",
        "Blake3Core.dll",
        "BouncyCastle.Cryptography.dll",
        "GostCryptography.dll",
        "Konscious.Security.Cryptography.Argon2.dll",
        "Konscious.Security.Cryptography.Blake2.dll",
        "Microsoft.ApplicationInsights.dll",
        "System.Reflection.Metadata.dll",
        "System.Runtime.CompilerServices.Unsafe.dll",
        "System.Threading.Tasks.Extensions.dll",
        "System.ValueTuple.dll",
        "Newtonsoft.Json.dll",
        "System.Buffers.dll",
        "System.Collections.Immutable.dll",
        "System.Diagnostics.DiagnosticSource.dll",
        "System.Formats.Asn1.dll",
        "System.Memory.dll",
        "System.Numerics.Vectors.dll"
        };

        /// <summary>
        /// Performs an automatic backup to the internal "Backup" folder in the Speedcrypt directory.
        /// Creates the folder if it does not exist.
        /// </summary>
        /// <param name="basePath">Base directory of Speedcrypt</param>
        public static void BackupAutomatic(string basePath)
        {
            string backupDir = Path.Combine(basePath, "Backup");

            if (!Directory.Exists(backupDir))
            {
                Directory.CreateDirectory(backupDir);
            }

            string backupPath = Path.Combine(backupDir, "SpeedcryptBackup.zip");
            CreateZipArchive(basePath, backupPath);
        }

        /// <summary>
        /// Performs a manual backup, allowing the user to choose the destination path.
        /// Also executes the automatic backup for maximum safety.
        /// </summary>
        /// <param name="basePath">Base directory of Speedcrypt</param>
        /// <param name="manualPath">Full path where the user wants to save the backup ZIP</param>
        public static void BackupManual(string basePath, string manualPath)
        {
            BackupAutomatic(basePath);
            CreateZipArchive(basePath, manualPath);
        }

        /// <summary>
        /// Generates the ZIP archive using defensive shared streams to bypass active background handles.
        /// </summary>
        private static void CreateZipArchive(string basePath, string targetZipPath)
        {
            using (FileStream zipToOpen = new FileStream(targetZipPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (ZipArchive archive = new ZipArchive(zipToOpen, ZipArchiveMode.Create))
            {
                foreach (string fileName in CriticalFiles)
                {
                    string fullPath = Path.Combine(basePath, fileName);
                    if (File.Exists(fullPath))
                    {
                        ZipArchiveEntry entry = archive.CreateEntry(fileName, CompressionLevel.Optimal);

                        // Enforces permissive shared locks during ingestion to prevent race conditions with background tamper checkers
                        using (FileStream fileStream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (Stream entryStream = entry.Open())
                        {
                            fileStream.CopyTo(entryStream);
                        }
                    }
                }
            }
        }
    }
}