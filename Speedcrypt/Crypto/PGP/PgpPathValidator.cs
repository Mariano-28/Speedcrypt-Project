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

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// PgpPathValidator: Validates that a specified folder path corresponds
    /// to a registered EnginePGP key path stored inside the Speedcrypt configuration file.
    /// </summary>
    ///
    /// <remarks>
    /// This class performs strict validation of a PGP key folder used by the Speedcrypt
    /// internal PGP engine. The validation process ensures that the provided folder path
    /// exactly matches a path registered in the Speedcrypt configuration file
    /// (Speedcrypt.config.xml).
    ///
    /// Validation process:
    /// - Locates the configuration file in the executable directory
    /// - Parses the XML configuration entries containing a Value attribute
    /// - Identifies entries associated with the EnginePGP fingerprint
    /// - Extracts the stored folder path from the configuration entry
    /// - Normalizes both stored and input paths for deterministic comparison
    /// - Performs a case-insensitive ordinal comparison
    ///
    /// Security characteristics:
    /// - Fail-safe design: any error automatically results in validation failure
    /// - Path normalization ensures consistent comparisons
    /// - No external dependencies beyond .NET Base Class Library
    /// - Does not expose internal configuration structures
    ///
    /// Technical notes:
    /// - Uses System.Xml.XmlDocument for compatibility with .NET Framework
    /// - Designed for deterministic and safe validation inside Speedcrypt
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public sealed class PgpPathValidator
    {
        // Configuration file name
        private const string ConfigFileName = "Speedcrypt.config.xml";

        // Required fingerprint identifier for PGP engine keys
        private const string RequiredFingerprint = "EnginePGP";

        // Public validation method
        public bool IsValid(string folderPath)
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(folderPath))
                return false;

            // Normalize input path for strict comparison
            string normalizedInput = NormalizePath(folderPath);

            try
            {
                // Build full path to configuration file located in executable directory
                string exeDirectory = System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                if (string.IsNullOrEmpty(exeDirectory))
                    return false;

                string configPath = System.IO.Path.Combine(exeDirectory, ConfigFileName);

                // Ensure configuration file exists
                if (!System.IO.File.Exists(configPath))
                    return false;

                // Load XML document
                System.Xml.XmlDocument doc = new System.Xml.XmlDocument();
                doc.Load(configPath);

                // Select all nodes with Value attribute
                System.Xml.XmlNodeList nodes = doc.SelectNodes("//*[@Value]");

                if (nodes == null)
                    return false;

                // Iterate through all configuration entries
                foreach (System.Xml.XmlNode node in nodes)
                {
                    System.Xml.XmlAttribute attr = node.Attributes["Value"];
                    if (attr == null)
                        continue;

                    string value = attr.Value;
                    if (string.IsNullOrEmpty(value))
                        continue;

                    // Fast check to ensure this entry belongs to EnginePGP
                    if (!value.EndsWith("|" + RequiredFingerprint, System.StringComparison.Ordinal))
                        continue;

                    // Extract first field before first pipe separator
                    int pipeIndex = value.IndexOf('|');
                    if (pipeIndex <= 0)
                        continue;

                    string storedPath = value.Substring(0, pipeIndex);

                    // Normalize stored path
                    string normalizedStored = NormalizePath(storedPath);

                    // Compare using strict ordinal comparison
                    if (string.Equals(normalizedStored, normalizedInput, System.StringComparison.OrdinalIgnoreCase))
                    {
                        // Valid match found
                        return true;
                    }
                }
            }
            catch
            {
                // Any error results in validation failure for safety
                return false;
            }

            // No valid match found
            return false;
        }

        // Normalize path to ensure consistent comparison
        private static string NormalizePath(string path)
        {
            // Trim spaces
            string result = path.Trim();

            // Ensure trailing backslash exists
            if (!result.EndsWith("\\"))
                result += "\\";

            return result;
        }
    }
}