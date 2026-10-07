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
using System.Collections;
using System.Windows.Forms;
using System.Collections.Generic;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// FileListHandler: Provides synchronous, visually smooth methods to add files
    /// and directories to a ListView with icons and file details. Prevents duplicate
    /// entries based on full path and updates a progress bar while processing files.
    /// Designed for stable, production-ready integration within Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - AddFiles: Safely adds files from directories or individual paths to a ListView,
    ///   skipping duplicates and Speedcrypt-encrypted (.SPCR) files. Updates a progress bar
    ///   and status label in real time to reflect processing progress.
    /// - RefreshTotals: Computes total file sizes and updates the status label, progress bar,
    ///   and context menu visibility based on current ListView contents.
    /// - CreateListViewItem: Generates ListViewItem objects with file metadata, including
    ///   size, creation time, and icons extracted from the file.
    /// - UpdateStatusLabel: Aggregates file counts and total sizes for UI display.
    /// - Batch processing is tuned (batch size = 35) to balance smooth scrolling and performance.
    /// - Fully synchronous operations designed to avoid visual jumps or UI instability.
    /// - No cryptographic data is processed here; the class is focused purely on UI/file management.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class FileListHandler
    {
        /// <summary>
        /// Adds files or directories to the specified ListView, processing batches and handling encryption/decryption modes.
        /// </summary>
        public static void AddFiles(ListView lv, ImageList imageList, IEnumerable paths, ToolStripLabel statusLabel, ToolStripProgressBar progressBar)
        {
            var allFiles = new List<string>();

            // Enumerate all files from the provided paths (handling directories recursively)
            foreach (string path in paths)
            {
                if (Directory.Exists(path))
                    allFiles.AddRange(Directory.EnumerateFiles(path, "*.*", SearchOption.AllDirectories));
                else if (File.Exists(path))
                    allFiles.Add(path);
            }

            if (allFiles.Count == 0)
            {
                UpdateStatusLabel(lv, statusLabel);
                return;
            }

            var existingPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Populate existing paths to prevent duplicate entries in the ListView
            foreach (ListViewItem item in lv.Items)
            {
                if (item.SubItems.Count > 2)
                    existingPaths.Add(item.SubItems[2].Text);
            }

            bool isDecryptMode;

            // Determine operation mode (Encryption vs Decryption) based on the first item or file extension
            if (lv.Items.Count > 0)
            {
                string firstPath = lv.Items[0].SubItems[2].Text;
                string ext = Path.GetExtension(firstPath);
                isDecryptMode = string.Equals(ext, ".SPCR", StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                isDecryptMode = false;
                foreach (string file in allFiles)
                {
                    try
                    {
                        if (string.IsNullOrWhiteSpace(file))
                            continue;

                        string normalized = file.Trim().Trim('"');
                        if (!Path.IsPathRooted(normalized))
                            continue;

                        string fullPath = Path.GetFullPath(normalized);
                        if (!File.Exists(fullPath))
                            continue;

                        string ext = Path.GetExtension(fullPath);
                        if (string.Equals(ext, ".SPCR", StringComparison.OrdinalIgnoreCase))
                        {
                            isDecryptMode = true;
                            break;
                        }

                        isDecryptMode = false;
                        break;
                    }
                    catch
                    {
                        continue;
                    }
                }
            }

            var newFiles = new List<string>();

            // Filter and validate files based on path rules, attributes, and operational mode
            foreach (string file in allFiles)
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(file))
                        continue;

                    string cleaned = file.Trim();
                    if (cleaned.IndexOfAny(new[] { '&', '|', '<', '>' }) >= 0)
                        continue;

                    string normalized = cleaned.Trim('"');
                    if (!Path.IsPathRooted(normalized))
                        continue;

                    string fullPath = Path.GetFullPath(normalized);
                    if (!File.Exists(fullPath))
                        continue;

                    var fi = new FileInfo(fullPath);
                    if ((fi.Attributes & FileAttributes.Directory) == FileAttributes.Directory)
                        continue;

                    if ((fi.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint)
                        continue;

                    if (fi.Length <= 0)
                        continue;

                    string ext = Path.GetExtension(fullPath);

                    // Skip system and shortcut links
                    if (string.Equals(ext, ".LNK", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(ext, ".URL", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(ext, ".PIF", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(ext, ".SCF", StringComparison.OrdinalIgnoreCase))
                        continue;

                    bool isSpcr = string.Equals(ext, ".SPCR", StringComparison.OrdinalIgnoreCase);

                    if (isDecryptMode)
                    {
                        if (!isSpcr)
                            continue;
                    }
                    else
                    {
                        if (isSpcr)
                            continue;
                    }

                    if (!existingPaths.Contains(fullPath))
                        newFiles.Add(fullPath);
                }
                catch
                {
                    continue;
                }
            }

            if (newFiles.Count == 0)
            {
                UpdateStatusLabel(lv, statusLabel);
                return;
            }

            // Configure progress bar for processing UI feedback
            progressBar.Minimum = 0;
            progressBar.Maximum = newFiles.Count;
            progressBar.Value = 0;

            const int batchSize = 35;
            var batchItems = new List<ListViewItem>();
            int processed = 0;

            // Process files in batches and update UI dynamically
            foreach (string file in newFiles)
            {
                var item = CreateListViewItem(file, imageList);

                if (item != null)
                {
                    batchItems.Add(item);
                    existingPaths.Add(file);
                    processed++;
                    progressBar.Value = processed;
                }

                if (batchItems.Count >= batchSize)
                {
                    lv.Items.AddRange(batchItems.ToArray());
                    batchItems.Clear();

                    if (lv.Items.Count > 0)
                        lv.EnsureVisible(lv.Items.Count - 1);

                    UpdateStatusLabel(lv, statusLabel);
                    Application.DoEvents();
                }
            }

            if (batchItems.Count > 0)
            {
                lv.Items.AddRange(batchItems.ToArray());
                if (lv.Items.Count > 0)
                    lv.EnsureVisible(lv.Items.Count - 1);
            }

            progressBar.Value = progressBar.Maximum;
            UpdateStatusLabel(lv, statusLabel);
        }
        /// <summary>
        /// Recalculates total file counts, sizes, and dynamically updates context menu visibility options.
        /// </summary>
        /// <summary>
        /// Recalculates total file counts, sizes, and dynamically updates context menu visibility options.
        /// </summary>
        public static void RefreshTotals(ListView lv, ToolStripLabel statusLabel, ToolStripProgressBar progressBar, ContextMenuStrip contextMenu)
        {
            long totalBytes = 0;

            foreach (ListViewItem item in lv.Items)
            {
                if (item.Tag is long size)
                    totalBytes += size;
            }

            statusLabel.Text = lv.Items.Count == 0
                ? "File Selection"
                : $"File list: {lv.Items.Count} files, {ByteCnt.FromBytes(totalBytes)} total";

            progressBar.Value = lv.Items.Count == 0 ? 0 : progressBar.Maximum;

            if (contextMenu != null)
            {
                bool hasItems = lv.Items.Count > 0;

                foreach (ToolStripItem menuItem in contextMenu.Items)
                {
                    if (menuItem is ToolStripSeparator)
                    {
                        menuItem.Visible = hasItems;
                        continue;
                    }

                    // Clean the text by removing the mnemonic ampersand for absolute identity checking
                    string cleanText = (menuItem.Text ?? string.Empty).Replace("&", "");

                    // Precise structural filtering: isolate only the explicit insertion commands
                    if (cleanText.StartsWith("Add File", StringComparison.OrdinalIgnoreCase) ||
                        cleanText.StartsWith("Add Folder", StringComparison.OrdinalIgnoreCase) ||
                        menuItem.Name.Equals("addFileToolStripMenuItem", StringComparison.OrdinalIgnoreCase) ||
                        menuItem.Name.Equals("addFolderToolStripMenuItem", StringComparison.OrdinalIgnoreCase))
                    {
                        menuItem.Visible = true;
                        continue;
                    }

                    menuItem.Visible = hasItems;
                }

                // Radical structural fix: Explicitly re-bind the ContextMenuStrip to the targeted control container instance 
                // to force instant window rendering synchronization and prevent Win32 state loss upon clearing operations.
                lv.ContextMenuStrip = contextMenu;
            }
        }  

        /// <summary>
        /// Creates and configures a ListViewItem for a specific file, extracting metadata and configuration details.
        /// </summary>
        private static ListViewItem CreateListViewItem(string filePath, ImageList imageList)
        {
            if (!File.Exists(filePath))
                return null;

            if (!imageList.Images.ContainsKey(filePath))
            {
                var icon = System.Drawing.Icon.ExtractAssociatedIcon(filePath);
                imageList.Images.Add(filePath, icon);
            }

            var fi = new FileInfo(filePath);

            var item = new ListViewItem
            {
                Text = "",
                ImageKey = filePath,
                Tag = fi.Length
            };

            // SubItem 1 (Index 1) represents the visible name of the file
            item.SubItems.Add(fi.Name);
            item.SubItems.Add(fi.FullName);
            item.SubItems.Add(string.Format("{0:#,##0} KB", Math.Max(1, fi.Length / 1024)));
            item.SubItems.Add(fi.CreationTime.ToString("dd/MM/yyyy HH:mm:ss"));
            item.SubItems.Add(fi.Strbytes());

            // For encrypted files, parse the XML configuration to extract tracking metadata
            if (string.Equals(Path.GetExtension(filePath), ".SPCR", StringComparison.OrdinalIgnoreCase))
            {
                string[] tail = GetSpcrTail(filePath);

                if (tail != null)
                {
                    // Override the displayed file name with the full GUID-prefixed name found in the XML 'Name' attribute
                    item.SubItems[1].Text = tail[0];

                    // Append trailing metadata metrics (Algorithm, Key Size, Engine Type)
                    item.SubItems.Add(tail[1]);
                    item.SubItems.Add(tail[2]);
                    item.SubItems.Add(tail[3]);
                }
            }

            return item;
        }

        /// <summary>
        /// Helper method to update the status text displaying total items and collective size.
        /// </summary>
        private static void UpdateStatusLabel(ListView lv, ToolStripLabel statusLabel)
        {
            long totalBytes = 0;

            foreach (ListViewItem item in lv.Items)
            {
                if (item.Tag is long size)
                    totalBytes += size;
            }

            statusLabel.Text = $"File list: {lv.Items.Count} files, {ByteCnt.FromBytes(totalBytes)} total";
        }

        // ==========================================
        // CONFIGURATION READER SPECIFIC TO XML (.SPCR)
        // ==========================================

        /// <summary>
        /// Scans the Speedcrypt configuration XML file to find the matching entry, 
        /// validating against both file paths and physical SPCR header metadata.
        /// </summary>
        /// <param name="filePath">The file path to cross-reference within the XML map.</param>
        /// <returns>An array containing [Full XML Name, Crypto Algorithm, Key Size, Crypto Engine] or null.</returns>
        private static string[] GetSpcrTail(string filePath)
        {
            try
            {
                string configPath = Path.Combine(Application.StartupPath, "Speedcrypt.config.xml");

                if (!File.Exists(configPath))
                    return null;

                // Extract real metadata attributes directly from the physical file header before inspecting XML
                string fileActualAlgorithm = null;
                string fileActualGroupId = null;

                if (File.Exists(filePath))
                {
                    try
                    {
                        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (var reader = new StreamReader(fs))
                        {
                            string header = reader.ReadLine();
                            if (!string.IsNullOrEmpty(header))
                            {
                                string[] headerParts = header.Split('|');
                                if (headerParts.Length >= 3)
                                {
                                    fileActualAlgorithm = headerParts[1]?.Trim();
                                    fileActualGroupId = headerParts[2]?.Trim();
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Fail silently to guarantee thread execution fallback safety
                    }
                }

                var doc = new System.Xml.XmlDocument();
                doc.Load(configPath);

                string normalizedTarget = Path.GetFullPath(filePath).Trim().Trim('"');
                string targetFileName = Path.GetFileName(normalizedTarget);

                var nodes = doc.SelectNodes("//Child");

                foreach (System.Xml.XmlNode node in nodes)
                {
                    var nameAttr = node.Attributes?["Name"];
                    var valueAttr = node.Attributes?["Value"];

                    if (valueAttr == null || nameAttr == null)
                        continue;

                    string[] parts = valueAttr.Value.Split('|');

                    if (parts.Length < 3)
                        continue;

                    string storedXmlName = nameAttr.Value.Trim();

                    // Direct check: Verify if the file being loaded matches the unique GUID-prefixed name inside the 'Name' attribute
                    bool match = string.Equals(targetFileName, storedXmlName, StringComparison.OrdinalIgnoreCase);

                    // Fallback check: Perform legacy parsing via absolute path matching in the 'Value' pipeline tokens
                    if (!match)
                    {
                        string storedPath = parts[0].Trim().Trim('"');
                        string normalizedStored;

                        try
                        {
                            normalizedStored = Path.GetFullPath(storedPath);
                        }
                        catch
                        {
                            continue;
                        }

                        match = string.Equals(normalizedStored, normalizedTarget, StringComparison.OrdinalIgnoreCase);

                        if (!match)
                        {
                            match = string.Equals(Path.GetFileName(normalizedStored), targetFileName, StringComparison.OrdinalIgnoreCase);
                        }
                    }

                    // If a structural path match is found, enforce strict cross-validation against the physical file header metadata
                    if (match)
                    {
                        int len = parts.Length;

                        // Extract engine registration metadata from the parent node configuration string if applicable
                        string parentValue = node.ParentNode?.Attributes?["Value"]?.Value;
                        string xmlGroupId = "1"; // Default fallback value

                        if (!string.IsNullOrEmpty(parentValue))
                        {
                            string[] parentParts = parentValue.Split('|');
                            if (parentParts.Length >= 2)
                            {
                                // In your configuration scheme, the second-to-last item contains the sequential Group ID parameter
                                xmlGroupId = parentParts[parentParts.Length - 2].Trim();
                            }
                        }

                        // Extract the registration algorithm token from the Child node (the 5th token in your specific XML payload format)
                        string xmlAlgorithm = parts[4]?.Trim();

                        // Reject this XML record node entry if it doesn't match the physical file header algorithm or group sequence index
                        if (!string.IsNullOrEmpty(fileActualAlgorithm) && xmlAlgorithm != fileActualAlgorithm)
                            continue;

                        if (!string.IsNullOrEmpty(fileActualGroupId) && xmlGroupId != fileActualGroupId)
                            continue;

                        return new[]
                        {
                        storedXmlName,  // Unique full field entry containing the GUID identifier prefix
                        parts[len - 3], // Algorithm name or cipher specification metrics
                        parts[len - 2], // Key bit size constraint parameter
                        parts[len - 1]  // Target crypto core engine architecture indicator
                    };
                    }
                }
            }
            catch
            {
                // Fail-safe logic context optimization to prevent thread or processing routine failure
            }

            return null;
        }
    }
}