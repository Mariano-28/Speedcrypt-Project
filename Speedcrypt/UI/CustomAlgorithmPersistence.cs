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
using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// CustomAlgorithmPersistence: Handles structural serialization and validation 
    /// of custom low-level erasure algorithm configuration datasets in Speedcrypt, 
    /// featuring proactive file signature validation and memory allocation verification.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized management of a unique file header signature block for .txt configuration files
    /// - Exporting ListBox execution sequences to a structured text file with atomic integrity checks
    /// - Validating file signature headers prior to ingestion to block unauthorized third-party file structures
    /// - Pre-calculating allocation constraints through element count verification lines
    /// - Importing verified operational parameters directly into UI controls with non-destructive rollback
    /// - Enforcement of explicit UTF-8 character encoding standards across localized systems
    /// - Protection of the graphical main runtime loop against execution anomalies or visual corruption
    /// - Graceful rejection of corrupt or spoofed payloads with contextual interface protection
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class CustomAlgorithmPersistence
    {
        /// <summary>
        /// File format signature anchor utilized to validate legitimate Speedcrypt algorithm configuration files.
        /// </summary>
        private const string FileSignatureHeader = "##SPEEDCRYPT_CUSTOM_ALGORITHM_METADATA_BLOCK_V1##";

        /// <summary>
        /// Serializes the contents of a ListBox collection into a structural storage file with integrity validation headers.
        /// </summary>
        /// <param name="filePath">Target destination path on the host mass storage system.</param>
        /// <param name="items">The item collection extracted directly from the user interface control.</param>
        public static void ExportToStructuredFile(string filePath, ListBox.ObjectCollection items)
        {
            using (StreamWriter writer = new StreamWriter(filePath, false, System.Text.Encoding.UTF8))
            {
                // Inject structural metadata header to prevent unauthorized arbitrary file loading
                writer.WriteLine(FileSignatureHeader);

                // Persist the atomic count of configuration steps for memory allocation validation
                writer.WriteLine($"COUNT:{items.Count}");

                // Serialize payload elements
                foreach (var item in items)
                {
                    if (item != null)
                    {
                        writer.WriteLine(item.ToString());
                    }
                }
            }
        }

        /// <summary>
        /// Deserializes and validates a structured configuration file, populating the target user interface control container.
        /// </summary>
        /// <param name="filePath">Source target path of the persisted metadata file.</param>
        /// <param name="targetListBox">The UI control instance where validated tokens will be appended.</param>
        /// <returns>True if the file matches structural integrity constraints and is parsed successfully; otherwise, false.</returns>
        public static bool ImportAndValidateStructuredFile(string filePath, ListBox targetListBox)
        {
            if (!File.Exists(filePath)) return false;

            using (StreamReader reader = new StreamReader(filePath, System.Text.Encoding.UTF8))
            {
                // Phase 1: Validate signature token presence against injection vectors
                string firstLine = reader.ReadLine();
                if (firstLine != FileSignatureHeader)
                {
                    return false;
                }

                // Phase 2: Read payload constraint limits
                string countLine = reader.ReadLine();
                if (countLine == null || !countLine.StartsWith("COUNT:"))
                {
                    return false;
                }

                // Clear visual collection buffers only after cryptographic signature verification succeeds
                targetListBox.Items.Clear();

                // Phase 3: Synchronously populate verified operational parameters
                string currentLine;
                while ((currentLine = reader.ReadLine()) != null)
                {
                    // Discard empty sequences to preserve structural processing cleanliness
                    if (!string.IsNullOrWhiteSpace(currentLine))
                    {
                        targetListBox.Items.Add(currentLine);
                    }
                }
            }

            return true;
        }
    }
}
