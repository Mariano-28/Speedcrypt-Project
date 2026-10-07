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

using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;

namespace SpcUtility.Backup
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SpcRestore: Automated restore management class for Speedcrypt.
    /// Handles recovery of critical application files from update sources,
    /// ensuring safe restoration of the program environment.
    /// Designed for the Speedcrypt framework with controlled process handling
    /// and automatic recovery of essential components.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Reliable restoration of Speedcrypt critical files using a Rename-on-Conflict strategy
    /// - Safe handling of running Speedcrypt instances to prevent Windows OS file locks
    /// - Automatic synchronization with the application lifecycle and safe restart
    /// - Fully automated restore pipeline, optimized for production environment stability
    ///    
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class SpcRestore
    {
        private const string SpeedcryptExe = "Speedcrypt.exe";

        // Windows API to delete the file automatically on the next system reboot if it's strictly locked
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);
        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

        /// <summary>
        /// Executes a completely redesigned automatic restore pipeline.
        /// </summary>
        public static void RestoreAutomatic(string basePath)
        {
            // 1. Terminate conflicting processes immediately
            ForceCloseProcess("Speedcrypt");
            ForceCloseProcess("Spcutility");

            // 2. Validate backup archive path
            string backupDir = Path.Combine(basePath, "Backup");
            string backupPath = Path.Combine(backupDir, "SpeedcryptBackup.zip");

            if (!File.Exists(backupPath))
                throw new FileNotFoundException("Required automatic backup archive was not found.", backupPath);

            // 3. Perform the fresh extraction using the rename-on-conflict strategy
            using (ZipArchive archive = ZipFile.OpenRead(backupPath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (string.IsNullOrEmpty(entry.Name)) continue;

                    string destinationPath = Path.Combine(basePath, entry.FullName);
                    ExtractWithRenameStrategy(entry, destinationPath);
                }
            }

            // 4. Respawn the main Speedcrypt executable
            try
            {
                Process.Start(Path.Combine(basePath, SpeedcryptExe));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Ecosystem rollback succeeded, but failed to restart Speedcrypt: " + ex.Message);
            }
        }

        /// <summary>
        /// Extracts a file by renaming any existing target to bypass Windows file locking mechanics.
        /// </summary>
        private static void ExtractWithRenameStrategy(ZipArchiveEntry entry, string destinationPath)
        {
            string directory = Path.GetDirectoryName(destinationPath);
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // If the file already exists, neutralize it by renaming it first
            if (File.Exists(destinationPath))
            {
                string uniqueSuffix = DateTime.UtcNow.Ticks.ToString();
                string tombstonePath = destinationPath + "." + uniqueSuffix + ".bak";

                try
                {
                    File.Move(destinationPath, tombstonePath);

                    // Try an immediate aggressive deletion of the neutralized file
                    try { File.Delete(tombstonePath); } catch { /* Ignored: handled by OS or reboot */ }
                }
                catch
                {
                    // If even renaming fails due to extreme kernel locks, register for deletion on reboot
                    MoveFileEx(destinationPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                }
            }

            // Extract cleanly into the now-unblocked path
            entry.ExtractToFile(destinationPath, true);
        }

        /// <summary>
        /// Forcefully kills all running instances of a process by name.
        /// </summary>
        private static void ForceCloseProcess(string processName)
        {
            try
            {
                var processes = Process.GetProcessesByName(processName)
                                       .Where(p => p.Id != Process.GetCurrentProcess().Id);

                foreach (var proc in processes)
                {
                    proc.Kill();
                    proc.WaitForExit(3000);
                }
            }
            catch
            {
                // Fail-safe: secure execution flow continues even if process handles are restricted
            }
        }
    }
}