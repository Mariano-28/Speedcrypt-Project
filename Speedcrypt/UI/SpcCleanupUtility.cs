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

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// SpcCleanupUtility: Provides global utility methods to manage and purge 
    /// persistent temporary assets (.tmp) and backup remnants (.bak) from the application directory.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Consistent global cleanup sequence triggering during application startup.
    /// - Low-level file-system defensive enumeration to bypass structural lock states.
    /// - Use of targeted purge operations to execute system-wide native maintenance seamlessly on .tmp and .bak extensions.
    /// - Clean separation between lifecycle maintenance routines and core cryptographic logic.
    /// - Reusable, centralized logic to avoid code duplication across the project.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    using System.IO;
    internal static class SpcCleanupUtility
    {
        /// <summary>
        /// Purges lingering temporary shadow files (.tmp) and backup remnants (.bak) from the application directory tree during startup sequence.
        /// </summary>
        /// <param name="basePath">The root operational directory of Speedcrypt.</param>
        public static void PurgeTemporaryFiles(string basePath)
        {
            if (string.IsNullOrWhiteSpace(basePath) || !Directory.Exists(basePath))
            {
                return;
            }

            // Define the target extensions to clean up from the workspace
            string[] targetExtensions = { "*.tmp", "*.bak" };

            try
            {
                foreach (string extension in targetExtensions)
                {
                    // Enumerates all files matching the structure defensively across the directory tree
                    string[] targetFiles = Directory.GetFiles(basePath, extension, SearchOption.AllDirectories);

                    foreach (string filePath in targetFiles)
                    {
                        try
                        {
                            if (File.Exists(filePath))
                            {
                                File.Delete(filePath);
                            }
                        }
                        catch
                        {
                            // Operational silent suppression: Locked elements will be collected on the next boot cycle
                        }
                    }
                }
            }
            catch
            {
                // Top-level failure suppression to guarantee application startup pipeline continuity
            }
        }
    }
}