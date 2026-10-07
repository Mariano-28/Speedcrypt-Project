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
using System.Linq;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// FolderPathValidator provides strict and reusable validation logic
    /// for Windows directory paths intended for creation or registration
    /// within application workflows.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Structural validation of root format (e.g., "C:\").
    /// - Verification that the referenced drive physically exists on the system.
    /// - Normalization of paths using Path.GetFullPath to guarantee canonical form.
    /// - Detection of invalid path and filename characters.
    /// - Validation of each directory segment independently.
    /// - Rejection of reserved Windows device names (CON, PRN, AUX, NUL, COMx, LPTx).
    /// - Prevention of trailing spaces or dots in directory names.
    /// - Optional duplicate detection against existing path collections.
    /// - Case-insensitive comparison aligned with Windows filesystem behavior.
    /// - Complete exception safety during validation operations.
    /// 
    /// The class is UI-agnostic and designed for reuse across ComboBox,
    /// TextBox, services, or background components.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class FolderPathValidator
    {
        // Reserved Windows device names that cannot be used as folder names
        private static readonly string[] ReservedNames =
        {
        "CON","PRN","AUX","NUL",
        "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
        "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"
    };

        /// <summary>
        /// Validates whether a given folder path is suitable for creation or registration.
        /// Optionally checks for duplicates against an existing collection of paths.
        /// </summary>
        /// <param name="path">The folder path to validate.</param>
        /// <param name="existingPaths">Optional collection of paths to check for duplicates.</param>
        /// <returns>True if the path is valid and unique; false otherwise.</returns>
        public static bool IsValidNewFolderPath(string path,
                                                System.Collections.Generic.IEnumerable<string> existingPaths = null)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            path = path.Trim();

            // Ensure the root format is correct (e.g., C:\)
            if (!HasValidRootFormat(path))
                return false;

            // Check for invalid path characters
            if (path.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
                return false;

            try
            {
                string fullPath = Path.GetFullPath(path);
                string root = Path.GetPathRoot(fullPath);

                // Verify that the root exists
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
                    return false;

                fullPath = EnsureTrailingBackslash(fullPath);

                // Validate each directory segment
                if (!ValidateSegments(fullPath, root))
                    return false;

                // Optional duplicate detection
                if (existingPaths != null)
                {
                    bool duplicate = existingPaths.Any(p =>
                        string.Equals(
                            EnsureTrailingBackslash(p),
                            fullPath,
                            StringComparison.OrdinalIgnoreCase));

                    if (duplicate)
                        return false;
                }

                return true;
            }
            catch
            {
                // Exception-safe: any unexpected error results in invalid path
                return false;
            }
        }

        // Checks if the path starts with a valid drive letter and backslash
        private static bool HasValidRootFormat(string path)
        {
            return path.Length >= 3 && char.IsLetter(path[0]) &&  path[1] == ':' &&  path[2] == '\\';
        }

        // Validates all segments of the path after the root
        private static bool ValidateSegments(string fullPath, string root)
        {
            string[] segments = fullPath.Substring(root.Length).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string segment in segments)
            {
                // No empty or whitespace-only segments
                if (string.IsNullOrWhiteSpace(segment))
                    return false;

                // No invalid filename characters
                if (segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                    return false;

                // Reject reserved Windows names
                if (ReservedNames.Contains(segment.ToUpperInvariant()))
                    return false;

                // Prevent trailing spaces or dots
                if (segment.EndsWith(" ") || segment.EndsWith("."))
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Ensures the path ends with a backslash.
        /// </summary>
        /// <param name="path">The input path.</param>
        /// <returns>The path guaranteed to end with a backslash.</returns>
        public static string EnsureTrailingBackslash(string path)
        {
            if (string.IsNullOrEmpty(path))
                return path;

            return path.EndsWith("\\") ? path : path + "\\";
        }
    }
}