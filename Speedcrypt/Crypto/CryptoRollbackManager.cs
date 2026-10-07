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
using System.Windows.Forms;
using System.Collections.Generic;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Crypto{

    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CryptoRollbackManager: Provides utilities for managing file cleanup during failed cryptographic operations.
    /// </summary>
    /// 
    /// <remarks>
    /// This static class is responsible for handling the automated file-system rollback when encryption or decryption processes fail.
    /// Features:
    /// - Cleaning up temporary workspace files (.tmp) left behind by interrupted operations
    /// - Verifying and removing incomplete or corrupted encrypted output files (.SPCR) based on file size evaluation
    /// - Securely deleting partially decrypted output files to prevent data corruption exposure
    /// - Integrating defensive try-catch blocks with central exception logging to prevent cleanup failures from halting the application
    /// 
    /// Technical note:
    /// - Designed to be execution-safe, guaranteeing that file I/O exceptions do not crash the primary cryptographic engine.
    /// - Errors encountered during the file deletion process are securely forwarded to `CentralLog` with specific operation tags.
    /// - The rollback logic protects the user's storage integrity by ensuring no corrupted artifacts or raw byte residues remain on the disk.
    /// 
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    public static class CryptoRollbackManager
    {
        // Universal path inside Windows Temp directory - secure for both Setup and Portable versions
        private static readonly string JournalFilePath = Path.Combine(Path.GetTempPath(), "speedcrypt_session.journal");

        /// <summary>
        /// Scans the ListView, extracts unique directory paths from SubItems, and creates the rollback log file.
        /// </summary>
        public static void CreateSessionJournal(ListView fileListView)
        {
            if (fileListView == null || fileListView.Items.Count == 0) return;

            try
            {
                HashSet<string> uniqueDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (ListViewItem item in fileListView.Items)
                {
                    // Safety check: ensure the subitem index 2 exists
                    if (item.SubItems.Count > 2)
                    {
                        // Accesses the specific file path column directly
                        string filePath = item.SubItems[2].Text;

                        if (!string.IsNullOrWhiteSpace(filePath))
                        {
                            string directoryPath = Path.GetDirectoryName(filePath);
                            if (!string.IsNullOrWhiteSpace(directoryPath))
                            {
                                uniqueDirectories.Add(directoryPath);
                            }
                        }
                    }
                }

                if (uniqueDirectories.Count > 0)
                {
                    File.WriteAllLines(JournalFilePath, uniqueDirectories);
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "JOURNAL_CREATION_FAILED", "Failed to create the session recovery journal file");
            }
        }

        /// <summary>
        /// Deletes the session journal file upon successful completion of the operation.
        /// </summary>
        public static void ClearSessionJournal()
        {
            try
            {
                if (File.Exists(JournalFilePath))
                {
                    File.Delete(JournalFilePath);
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "JOURNAL_DELETION_FAILED", "Failed to delete the session recovery journal file");
            }
        }

        /// <summary>
        /// Processes the session journal file at startup to clean up all orphaned residues from the interrupted directories.
        /// </summary>
        public static void RunStartupRecovery()
        {
            // Guard clause: If the journal file does not exist, no crash happened - exit immediately
            if (!File.Exists(JournalFilePath)) return;

            try
            {
                // Read all tracked unique directories from the last crash session
                string[] directoriesToClean = File.ReadAllLines(JournalFilePath);

                foreach (string directoryPath in directoriesToClean)
                {
                    if (!Directory.Exists(directoryPath)) continue;

                    // 1. Clean up standard encryption residues (.SPCR and .SPCR.tmp)
                    string[] spcrFiles = Directory.GetFiles(directoryPath, "*.SPCR", SearchOption.TopDirectoryOnly);
                    foreach (string spcrFile in spcrFiles)
                    {
                        // Reconstruct the original file path by removing the .SPCR extension
                        string originalPath = spcrFile.Substring(0, spcrFile.Length - 5);

                        // Run your tested encryption rollback logic
                        RollbackEncryption(originalPath);
                    }

                    // 2. Clean up temporary stream files safely (only explicit temporary extensions)
                    string[] allFiles = Directory.GetFiles(directoryPath, "*.*", SearchOption.TopDirectoryOnly);
                    foreach (string file in allFiles)
                    {
                        string extension = Path.GetExtension(file);

                        // Explicitly target only verified temporary extensions (.tmp or staging extensions)
                        if (extension.Equals(".tmp", StringComparison.OrdinalIgnoreCase) ||
                            file.EndsWith(".SPCR.tmp", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                File.Delete(file);
                            }
                            catch (Exception)
                            {
                                // Avoid blocking the loop if a file is genuinely locked by another process
                            }
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "STARTUP_RECOVERY_FAILED", "Failed to complete the automatic session recovery process");
            }
            finally
            {
                // Always delete the journal file at the end to prevent boot loops
                ClearSessionJournal();
            }
        }

        /// <summary>
        /// Cleans up temporary and corrupted files if an encryption operation fails.
        /// </summary>
        public static void RollbackEncryption(string originalSourcePath)
        {
            if (string.IsNullOrWhiteSpace(originalSourcePath)) return;

            try
            {
                string spcrFilePath = originalSourcePath + ".SPCR";
                string tempFilePath = spcrFilePath + ".tmp";

                // Delete temporary workspace file if it exists
                if (File.Exists(tempFilePath))
                {
                    File.Delete(tempFilePath);
                }

                // Validate and remove corrupted encryption output
                if (File.Exists(spcrFilePath))
                {
                    FileInfo originalInfo = new FileInfo(originalSourcePath);
                    FileInfo spcrInfo = new FileInfo(spcrFilePath);

                    // Check if the encrypted file is incomplete based on original size
                    if (spcrInfo.Length <= originalInfo.Length)
                    {
                        File.Delete(spcrFilePath);
                    }
                }
            }
            catch (Exception cleanupEx)
            {
                CentralLog.LogException(cleanupEx, "ROLLBACK_ENCRYPT", "Failed to clean up corrupted encryption residues");
            }
        }

        /// <summary>
        /// Removes the corrupted output file if a decryption operation fails.
        /// </summary>
        public static void RollbackDecryption(string targetOutputPath)
        {
            if (string.IsNullOrWhiteSpace(targetOutputPath)) return;

            try
            {
                // Delete the incomplete decrypted file to prevent data corruption exposure
                if (File.Exists(targetOutputPath))
                {
                    File.Delete(targetOutputPath);
                }
            }
            catch (Exception cleanupEx)
            {
                CentralLog.LogException(cleanupEx, "ROLLBACK_DECRYPT", "Failed to remove corrupted decryption output");
            }
        }
    }
}