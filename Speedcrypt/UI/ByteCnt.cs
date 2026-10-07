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

using System.IO;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ByteCnt: Provides utility methods for converting byte counts into
    /// human-readable strings with appropriate size suffixes (B, KB, MB, GB, TB).
    /// Includes extension method for FileInfo objects to get formatted size strings.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Strbytes(FileInfo): Extension method returning the file size as a human-readable string.
    /// - FromBytes(long): Converts a byte count into the largest possible unit while maintaining
    ///   precision up to two decimal places.
    /// - Proper handling of large files, ensuring suffixes from B to TB are correctly applied.
    /// - Purely deterministic and safe string formatting without side effects or exceptions.
    /// - No sensitive data is processed; utility is designed for display/logging purposes.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class ByteCnt
    {
        /// <summary>
        /// Returns the file size of a FileInfo object as a human-readable string.
        /// </summary>
        /// <param name="info">FileInfo object</param>
        /// <returns>Formatted size string, e.g., "2.34 MB"</returns>
        public static string Strbytes(this FileInfo info)
        {
            return FromBytes(info.Length);
        }

        /// <summary>
        /// Converts a byte count into a human-readable string using the largest possible unit.
        /// Supports B, KB, MB, GB, TB with up to two decimal places.
        /// </summary>
        /// <param name="bytes">Byte count</param>
        /// <returns>Formatted string, e.g., "1.23 GB"</returns>
        public static string FromBytes(long bytes)
        {
            string[] Suffix = { "B", "KB", "MB", "GB", "TB" };
            int i = 0;
            double dblSByte = bytes;

            while (dblSByte >= 1024 && i < Suffix.Length - 1)
            {
                dblSByte /= 1024;
                i++;
            }

            return string.Format("{0:0.##} {1}", dblSByte, Suffix[i]);
        }
    }
}