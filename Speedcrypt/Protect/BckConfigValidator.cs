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
using System.Xml;
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.UI;

namespace Speedcrypt.Protect
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// BckConfigValidator: Configuration integrity checker and automatic restore helper.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the configuration
    /// protection and recovery subsystem.
    ///
    /// Purpose:
    /// - Validate the structural integrity of the Speedcrypt configuration file.
    /// - Detect missing, corrupted, or malformed XML configurations.
    /// - Automatically restore the configuration from a backup file when possible.
    /// - Provide immediate visual feedback through UI elements (Label and PictureBox).
    ///
    /// Design notes:
    /// - Validation is intentionally structural, not semantic.
    /// - The goal is early detection of corruption, not deep configuration analysis.
    /// - Backup restoration is attempted only when strictly necessary.
    /// - All operations are fail-safe and UI-friendly.
    ///
    /// Security scope and limits:
    /// - This class protects against accidental corruption, disk errors,
    ///   and basic tampering of the configuration file.
    /// - It does not claim resistance against a fully privileged attacker.
    /// - It does everything reasonably achievable at application level,
    ///   but no configuration protection is absolute.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and overall security validation lies entirely with the author.
    /// </remarks>
    public static class BckConfigValidator
    {
        /// <summary>
        /// Validates the configuration file and restores it from backup if needed.
        /// Updates the provided Label and PictureBox with result.
        /// </summary>
        /// <param name="basePath">Base directory of Speedcrypt</param>
        /// <param name="statusLabel">Label to show test result</param>
        /// <param name="statusIcon">PictureBox (16x16) to show green/red icon</param>
        public static void ValidateAndRestore(string basePath, Label statusLabel, PictureBox statusIcon)
        {
            string configPath = Path.Combine(basePath, "Speedcrypt.config.xml");
            string backupPath = Path.Combine(basePath, "Speedcrypt.config.xml.Bck");

            bool success = true;
            string message = "Config File Test: Passed!";

            // If config file is missing or invalid, attempt restore
            if (!File.Exists(configPath) || !IsValidXml(configPath))
            {
                success = false;
                message = "Config File Test: Failed! Restoring backup...";

                if (File.Exists(backupPath))
                {
                    try
                    {
                        string tempPath = configPath + ".tmp";
                        File.Copy(backupPath, tempPath, true);
                        File.Replace(tempPath, configPath, null);
                        success = IsValidXml(configPath);
                        message = success
                            ? "Config File Test: Restored from Backup"
                            : "Config File Test: Failed even after restore!";
                    }
                    catch (Exception ex)
                    {
                        message = $"Config File Test: Restore Failed! {ex.Message}";
                    }
                }
            }

            // Update Label
            statusLabel.Text = message;

            // Update PictureBox with 16x16 icon
            statusIcon.Image?.Dispose();
            statusIcon.Image = success
                ? ForAllUnits.Ledgreen16 // green icon
                : ForAllUnits.Ledred16;   // red icon
        }

        /// <summary>
        /// Quick XML structural validation
        /// </summary>
        private static bool IsValidXml(string path)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(path);

                XmlNode root = doc.SelectSingleNode("/Configuration");
                if (root == null) return false;

                XmlNodeList keyNodes = root.SelectNodes("Key");
                if (keyNodes == null) return true; // empty valid config

                foreach (XmlNode keyNode in keyNodes)
                {
                    XmlAttribute nameAttr = keyNode.Attributes["Name"];
                    XmlAttribute valueAttr = keyNode.Attributes["Value"];
                    if (nameAttr == null || valueAttr == null) return false;

                    foreach (XmlNode child in keyNode.ChildNodes)
                    {
                        if (child.Name != "Child") return false;
                        if (child.Attributes["Name"] == null || child.Attributes["Value"] == null)
                            return false;
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}