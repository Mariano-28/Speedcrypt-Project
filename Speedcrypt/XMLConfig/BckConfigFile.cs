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

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.XMLConfig
{
    /// Created by Mariano Ortu
    /// 
    /// BckConfigFile: Governs the automated replication, structural restoration, and 
    /// chronological history logging of the configuration file matrix across Speedcrypt deployment environments.
    /// </summary>
    ///
    /// <remarks>
    /// This architectural component ensures:
    /// - Centralized emergency backup and structural rollback pipelines for localized configuration XML schemas.
    /// - Dynamic post-process chronological history capture, generating time-stamped recovery checkpoints embedding active engine names upon task completion.
    /// - Automated file-system directory allocation ('History') to isolate historical configuration snapshots.
    /// - Self-managing housekeeping algorithms tracking partition metrics to purge oldest artifacts and manage storage boundaries.
    /// - Invariant dictionary stream generation compiling human-readable recovery index mappings to drive automated interface dialog modules.
    /// - Atomic snapshot restoration techniques enforcing defensive state preservation layers before executing destructive file overwrites.
    /// - Fault-tolerant execution handling, routing internal I/O exceptions safely to telemetry logs without destabilizing application lifecycles.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class BckConfigFile
    {
        private static readonly string ConfigFileName = "Speedcrypt.config.xml";
        private static readonly string BackupFileName = "Speedcrypt.config.xml.Bck";
        private static readonly string HistoryFolderName = "History";

        // GLOBAL ENTERPRISE STATE REGISTRY: Holds the active cryptographic engine name updated in real-time by UI execution layers
        public static string ActiveEngine = "AES";

        /// <summary>
        /// Creates a standard safety backup of the configuration file in the execution folder.
        /// </summary>
        public static void CreateBackup()
        {
            string basePath = AppDomain.CurrentDomain.BaseDirectory;
            string configPath = Path.Combine(basePath, ConfigFileName);
            string backupPath = Path.Combine(basePath, BackupFileName);

            try
            {
                if (File.Exists(configPath))
                {
                    File.Copy(configPath, backupPath, true);
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "CONFIG", "Error creating config backup!");
            }
        }

        /// <summary>
        /// Generates a time-stamped chronological history snapshot of the active configuration file within a dedicated security directory sub-layer.
        /// </summary>
        public static void CreateChronologicalHistoryBackup()
        {
            string basePath = AppDomain.CurrentDomain.BaseDirectory;
            string configPath = Path.Combine(basePath, ConfigFileName);
            string historyDirectoryPath = Path.Combine(basePath, HistoryFolderName);

            try
            {
                if (!File.Exists(configPath))
                    return;

                if (!Directory.Exists(historyDirectoryPath))
                {
                    Directory.CreateDirectory(historyDirectoryPath);
                }

                // High-resolution timestamp extraction
                string timestamp = DateTime.Now.ToString("yyyy_MM_dd_HHmmss");

                // Standardize and normalize the shared engine identifier by stripping utility prefixes
                string cleanEngineName = !string.IsNullOrEmpty(ActiveEngine)
                    ? ActiveEngine.Replace("Engine", "").Trim().ToUpper()
                    : "AES";

                // Structural naming patterns embedding both the timeline marker AND the shared operational cipher token
                string historyFileName = $"Speedcrypt_{timestamp}_{cleanEngineName}.config.xml";
                string historyFilePath = Path.Combine(historyDirectoryPath, historyFileName);

                // Commits a permanent historical byte-level replica to safeguard user decryption capabilities
                File.Copy(configPath, historyFilePath, true);

                // Housekeeping pipeline to prevent directory bloat by retaining only the last 50 historical entries
                CleanOldHistoryFiles(historyDirectoryPath, maxFiles: 50);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "CONFIG_HISTORY", "Failed to generate dynamic time-stamped configuration history snapshot with embedded token.");
            }
        }

        /// <summary>
        /// Evaluates storage item density inside the history folder and purges old historical records to manage disk space.
        /// </summary>
        private static void CleanOldHistoryFiles(string folderPath, int maxFiles)
        {
            try
            {
                DirectoryInfo dir = new DirectoryInfo(folderPath);
                FileInfo[] files = dir.GetFiles("Speedcrypt_*.config.xml");

                if (files.Length > maxFiles)
                {
                    var filesToDelete = System.Linq.Enumerable.ToList(
                        System.Linq.Enumerable.Select(
                            System.Linq.Enumerable.OrderBy(files, f => f.CreationTime),
                            f => f.FullName
                        )
                    );

                    int excessCount = files.Length - maxFiles;
                    for (int i = 0; i < excessCount; i++)
                    {
                        if (File.Exists(filesToDelete[i]))
                        {
                            File.Delete(filesToDelete[i]);
                        }
                    }
                }
            }
            catch { /* Fallback silent guard preventing housekeeping routines from disrupting core execution states */ }
        }

        /// <summary>
        /// Restores the configuration file from the standard safety backup.
        /// </summary>
        public static void RestoreFromBackup()
        {
            string basePath = AppDomain.CurrentDomain.BaseDirectory;
            string configPath = Path.Combine(basePath, ConfigFileName);
            string backupPath = Path.Combine(basePath, BackupFileName);

            try
            {
                if (File.Exists(backupPath))
                {
                    File.Copy(backupPath, configPath, true);
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "CONFIG", "Error restoring config from backup!");
            }
        }

        /// <summary>
        /// Retrieves a collection of all available chronological history backup files, ordered from newest to oldest.
        /// </summary>
        /// <returns>A dictionary containing file paths as keys and formatted timestamps as values.</returns>
        public static System.Collections.Generic.Dictionary<string, string> GetAvailableHistoryBackups()
        {
            var historyList = new System.Collections.Generic.Dictionary<string, string>();
            string basePath = AppDomain.CurrentDomain.BaseDirectory;
            string historyDirectoryPath = Path.Combine(basePath, HistoryFolderName);

            try
            {
                if (!Directory.Exists(historyDirectoryPath))
                    return historyList;

                DirectoryInfo dir = new DirectoryInfo(historyDirectoryPath);
                FileInfo[] files = dir.GetFiles("Speedcrypt_*.config.xml");

                var sortedFiles = System.Linq.Enumerable.OrderByDescending(files, f => f.CreationTime);

                foreach (var file in sortedFiles)
                {
                    // Converts the filesystem timestamp into a clean, human-readable display string for the UI
                    string readableDate = file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss");
                    historyList.Add(file.FullName, readableDate);
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "CONFIG_RECOVERY", "Failed to compile the list of available historical configuration snapshots.");
            }

            return historyList;
        }

        /// <summary>
        /// Overwrites the active production configuration file with a selected historical backup snapshot.
        /// </summary>
        /// <param name="historyFilePath">The absolute physical path of the historical XML file to restore.</param>
        /// <returns>True if the restoration succeeded; otherwise, false.</returns>
        public static bool RestoreFromHistorySnapshot(string historyFilePath)
        {
            string basePath = AppDomain.CurrentDomain.BaseDirectory;
            string configPath = Path.Combine(basePath, ConfigFileName);

            try
            {
                if (!File.Exists(historyFilePath))
                    return false;

                // Step 1: Create an immediate dynamic backup of the current state before overwriting (just in case)
                CreateBackup();

                // Step 2: Atomic overwrite - replace the production XML file with the selected historical artifact
                File.Copy(historyFilePath, configPath, true);
                return true;
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "CONFIG_RECOVERY", $"Failed to restore configuration from specific snapshot: {historyFilePath}");
                return false;
            }
        }
    }
}