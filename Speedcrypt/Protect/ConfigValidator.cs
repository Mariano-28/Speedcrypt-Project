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

namespace Speedcrypt.Protect
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ConfigValidator: Configuration structural validation engine.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the configuration
    /// validation and integrity checking subsystem.
    ///
    /// Purpose:
    /// - Validate the structural integrity of the Speedcrypt configuration file.
    /// - Detect missing, corrupted, or malformed XML structures.
    /// - Provide a detailed validation report through a ListView UI component.
    /// - Offer immediate visual feedback using predefined status icons.
    ///
    /// Design notes:
    /// - Validation is strictly structural, not semantic.
    /// - Each configuration element is checked independently.
    /// - The validation process is non-destructive and read-only.
    /// - UI updates are optimized to prevent flickering and ensure clarity.
    ///
    /// Security scope and limits:
    /// - This class detects accidental corruption, malformed XML,
    ///   and basic structural inconsistencies.
    /// - It does not attempt to protect against intentional tampering
    ///   by a fully privileged attacker.
    /// - It performs everything reasonably achievable at application level,
    ///   but no configuration validation is absolute.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and overall security validation lies entirely with the author.
    /// </remarks>
    public sealed class ConfigValidator
    {
        private readonly string _configPath;
        private readonly ListView _listView;
        private readonly ImageList _imageList;
        public ConfigValidator(string configPath, ListView listView, ImageList imageList)
        {
            _configPath = configPath;
            _listView = listView;
            _imageList = imageList;

            _listView.SmallImageList = _imageList;
        }

        /// <summary>
        /// Validates the Speedcrypt configuration file.
        /// Populates the ListView with validation results.
        /// Returns true if the configuration is structurally valid.
        /// </summary>
        public bool Validate()
        {
            bool globalResult = true;

            // Prevent ListView flickering during update
            _listView.BeginUpdate();
            _listView.Items.Clear();

            try
            {
                if (!File.Exists(_configPath))
                {
                    AddItem("Speedcrypt.config.xml", false, "Configuration file not found");
                    return false;
                }

                XmlDocument doc = new XmlDocument();

                try
                {
                    doc.Load(_configPath);
                }
                catch (Exception ex)
                {
                    AddItem("Speedcrypt.config.xml", false, "XML parse error: " + ex.Message);
                    return false;
                }

                XmlNode root = doc.SelectSingleNode("/Configuration");
                if (root == null)
                {
                    AddItem("Configuration", false, "Missing <Configuration> root node");
                    return false;
                }

                AddItem("Configuration", true, "Root node verified");

                XmlNodeList keyNodes = root.SelectNodes("Key");
                if (keyNodes == null || keyNodes.Count == 0)
                {
                    AddItem("Key nodes", true, "No keys defined (valid initial state)");
                    return true;
                }

                foreach (XmlNode keyNode in keyNodes)
                {
                    ValidateKeyNode(keyNode, ref globalResult);
                }

                return globalResult;
            }
            finally
            {
                // Re-enable redraw
                _listView.EndUpdate();

                // Always scroll to the last record
                if (_listView.Items.Count > 0)
                    _listView.Items[_listView.Items.Count - 1].EnsureVisible();
            }
        }

        /// <summary>
        /// Validates a single <Key> node and its optional children.
        /// </summary>
        private void ValidateKeyNode(XmlNode keyNode, ref bool globalResult)
        {
            XmlAttribute nameAttr = keyNode.Attributes?["Name"];
            XmlAttribute valueAttr = keyNode.Attributes?["Value"];

            if (nameAttr == null || string.IsNullOrWhiteSpace(nameAttr.Value))
            {
                AddItem("Unnamed Key", false, "Missing or empty Name attribute");
                globalResult = false;
                return;
            }

            string keyName = nameAttr.Value;

            if (valueAttr == null)
            {
                AddItem(keyName, false, "Missing Value attribute");
                globalResult = false;
            }
            else
            {
                AddItem(keyName, true, "Key structure verified");
            }

            // Validate child nodes (if any)
            foreach (XmlNode child in keyNode.ChildNodes)
            {
                if (child.Name != "Child")
                {
                    AddItem(keyName, false, "Invalid child node detected");
                    globalResult = false;
                    continue;
                }

                XmlAttribute childName = child.Attributes?["Name"];
                XmlAttribute childValue = child.Attributes?["Value"];

                if (childName == null || childValue == null)
                {
                    AddItem(keyName, false, "Malformed <Child> entry");
                    globalResult = false;
                }
            }
        }

        /// <summary>
        /// Adds a validation result row to the ListView.
        /// Uses a predefined icon and color-coded status.
        /// </summary>
        private void AddItem(string file, bool success, string details)
        {
            ListViewItem item = new ListViewItem
            {
                ImageIndex = 2,
                Text = string.Empty
            };

            item.SubItems.Add(file);
            item.SubItems.Add(success ? "OK" : "FAIL");
            item.SubItems.Add(details);

            item.SubItems[2].ForeColor = success
                ? System.Drawing.Color.DarkGreen
                : System.Drawing.Color.DarkRed;

            _listView.Items.Add(item);
        }
    }
}