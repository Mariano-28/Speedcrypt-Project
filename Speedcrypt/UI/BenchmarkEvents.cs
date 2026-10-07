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
    /// BenchmarkEvents: Provides simple file header management utilities for
    /// benchmark or log files. Includes methods to write a header to a file,
    /// validate the header against an expected value, and ensure the header
    /// is present without overwriting unnecessarily.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - WriteHeader: Safely writes the provided header string to the specified file,
    ///   followed by a newline. Returns true if successful, false on any exception.
    /// - ValidateHeader: Reads the first line of the file and compares it to the expected
    ///   header after trimming. Returns true if it matches, false on mismatch or error.
    /// - EnsureHeader: Writes the header only if the file is missing or the header is
    ///   different. Returns true if header is now correct, false on error.
    /// - All exceptions are handled gracefully, avoiding unhandled crashes.
    /// - File operations are simple, deterministic, and suitable for benchmark/log usage.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class BenchmarkEvents
    {
        /// <summary>
        /// Writes the header string to the specified file, followed by a newline.
        /// </summary>
        /// <param name="filePath">Target file path</param>
        /// <param name="header">Header string to write</param>
        /// <returns>True if successful, false on error</returns>
        public static bool WriteHeader(string filePath, string header)
        {
            try
            {
                File.WriteAllText(filePath, header + Environment.NewLine);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates that the first line of the file matches the expected header.
        /// </summary>
        /// <param name="filePath">Target file path</param>
        /// <param name="expectedHeader">Expected header string</param>
        /// <returns>True if header matches, false on mismatch or error</returns>
        public static bool ValidateHeader(string filePath, string expectedHeader)
        {
            try
            {
                var firstLine = File.ReadLines(filePath).FirstOrDefault();
                return firstLine != null && firstLine.Trim() == expectedHeader;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Ensures that the file exists with the expected header.
        /// Writes the header only if the file is missing or the header is incorrect.
        /// </summary>
        /// <param name="filePath">Target file path</param>
        /// <param name="header">Expected header string</param>
        /// <returns>True if the header is now correct, false on error</returns>
        public static bool EnsureHeader(string filePath, string header)
        {
            try
            {
                if (!File.Exists(filePath))
                    return WriteHeader(filePath, header);

                var firstLine = File.ReadLines(filePath).FirstOrDefault();
                if (firstLine == null || firstLine.Trim() != header)
                    return WriteHeader(filePath, header);

                return true; // Header already correct
            }
            catch
            {
                return false;
            }
        }
    }
}