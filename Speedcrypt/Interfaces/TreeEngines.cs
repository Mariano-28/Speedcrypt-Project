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
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.XMLConfig;
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Interfaces
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// TreeEngines: Infrastructure and UI coordination class responsible
    /// for visualizing encryption engines, groups, and encrypted files
    /// within the Speedcrypt application.
    /// </summary>
    ///
    /// <remarks>
    /// This class is NOT a cryptographic component.
    /// It does not perform encryption, decryption, hashing, or validation.
    ///
    /// Its responsibility is limited to:
    /// - Building and maintaining the TreeView structure for encryption engines
    /// - Synchronizing engine and group nodes with the XML configuration
    /// - Reflecting encrypted file groups into the ListView UI
    /// - Updating status and accounting information for visualization purposes
    ///
    /// All operations are UI-driven and configuration-based.
    /// No cryptographic material is generated, processed, or evaluated.
    ///
    /// The TreeView hierarchy represents logical grouping and engine association,
    /// not cryptographic strength, trust, or security guarantees.
    ///
    /// Designed exclusively for visualization, consistency,
    /// and user interface coordination within Speedcrypt.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>  
    public class TreeEngines
    {
        // Native Win32 API declarations to suppress TreeView rendering flicker
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wp, IntPtr lp);

        // Encryption flag
        public static bool decrypted = false;

        private const int TVM_SETEXTENDEDSTYLE = 0x1100 + 44;
        private const int TVS_EX_DOUBLEBUFFER = 0x0004;

        private TreeView _treeEngines;
        private ListView _listViewFiles;
        private PrivateXmlConfig _config;
        private TreeNode _filesEncryptedNode;
        private ToolStripLabel _statusLabel;
        private ListViewRowAlternator _alternator;
        public TreeEngines(TreeView treeEngines, ToolStripLabel statusLabel, ListView listViewFiles, PrivateXmlConfig config)
        {
            _treeEngines = treeEngines;
            _listViewFiles = listViewFiles;
            _config = config;
            _statusLabel = statusLabel;

            // Force native Win32 double buffering on the TreeView control to eliminate layout redraw flicker
            if (_treeEngines.IsHandleCreated)
            {
                SendMessage(_treeEngines.Handle, TVM_SETEXTENDEDSTYLE, (IntPtr)TVS_EX_DOUBLEBUFFER, (IntPtr)TVS_EX_DOUBLEBUFFER);
            }
            else
            {
                _treeEngines.HandleCreated += (s, e) =>
                {
                    SendMessage(_treeEngines.Handle, TVM_SETEXTENDEDSTYLE, (IntPtr)TVS_EX_DOUBLEBUFFER, (IntPtr)TVS_EX_DOUBLEBUFFER);
                };
            }

            _treeEngines.AfterSelect += TreeEngines_AfterSelect;
            _treeEngines.BeforeExpand += TreeEngines_BeforeExpand;
            _treeEngines.BeforeCollapse += TreeEngines_BeforeCollapse;
            _treeEngines.Click += _treeEngines_Click;
        }
        public TreeView TreeViewControl
        {
            get { return _treeEngines; }
        }
        public void Initialize()
        {
            _treeEngines.BeginUpdate();
            _treeEngines.Nodes.Clear();

            // --- ROOT: ENGINES ---
            TreeNode rootNode = _treeEngines.Nodes.Add("ENGINES     ");
            rootNode.NodeFont = new System.Drawing.Font("Verdana", 10);
            rootNode.ForeColor = System.Drawing.Color.DarkRed;
            rootNode.ImageIndex = 0;
            rootNode.SelectedImageIndex = 0;
            rootNode.Tag = string.Empty;

            CreateEngineNode(rootNode, "AES", "EngineAES");
            CreateEngineNode(rootNode, "PGP", "EnginePGP");
            CreateEngineNode(rootNode, "IDEA", "EngineIDEA");
            CreateEngineNode(rootNode, "GOST", "EngineGOST");
            CreateEngineNode(rootNode, "AES-GCM", "EngineAESGCM");
            CreateEngineNode(rootNode, "SERPENT", "EngineSERPENT");
            CreateEngineNode(rootNode, "TWOFISH", "EngineTWOFISH");
            CreateEngineNode(rootNode, "CAMELLIA", "EngineCAMELLIA");
            CreateEngineNode(rootNode, "THREEFISH", "EngineTHREEFISH");
            CreateEngineNode(rootNode, "KUZNYECHIK", "EngineKUZNYECHIK");
            CreateEngineNode(rootNode, "XCHACHA20-POLY1305", "EngineXCHACHA20-POLY1305");

            // --- ROOT: FILES ENCRYPTED ---
            _filesEncryptedNode = _treeEngines.Nodes.Add("Encrypted Files: 0     ");
            _filesEncryptedNode.NodeFont = new System.Drawing.Font("Verdana", 9);
            _filesEncryptedNode.ForeColor = System.Drawing.Color.DarkRed;
            _filesEncryptedNode.ImageIndex = 12;
            _filesEncryptedNode.SelectedImageIndex = 12;
            _filesEncryptedNode.Tag = "files_encrypted";

            rootNode.Expand();
            _treeEngines.EndUpdate();

            LoadGroups();
            UpdateFilesEncryptedCount();
        }
        private void LoadGroups()
        {
            _treeEngines.BeginUpdate();
            TreeNode enginesRoot = _treeEngines.Nodes[0];

            foreach (var key in _config.GetAllKeyValuePairs())
            {
                string parentValue = key.Value;
                if (string.IsNullOrEmpty(parentValue))
                    continue;

                string engineTagXml = parentValue.Split('|')[parentValue.Split('|').Length - 1].Trim();
                if (string.IsNullOrEmpty(engineTagXml))
                    continue;

                // Map XML engine tags to TreeView node tags
                string engineTagTree;
                if (engineTagXml == "EngineAES-GCM")
                    engineTagTree = "EngineAESGCM";
                else if (engineTagXml == "EngineAES")
                    engineTagTree = "EngineAES";
                else if (engineTagXml == "EnginePGP")
                    engineTagTree = "EnginePGP";
                else if (engineTagXml == "EngineIDEA")
                    engineTagTree = "EngineIDEA";
                else if (engineTagXml == "EngineGOST")
                    engineTagTree = "EngineGOST";
                else if (engineTagXml == "EngineSERPENT")
                    engineTagTree = "EngineSERPENT";
                else if (engineTagXml == "EngineTWOFISH")
                    engineTagTree = "EngineTWOFISH";
                else if (engineTagXml == "EngineCAMELLIA")
                    engineTagTree = "EngineCAMELLIA";
                else if (engineTagXml == "EngineTHREEFISH")
                    engineTagTree = "EngineTHREEFISH";
                else if (engineTagXml == "EngineKUZNYECHIK")
                    engineTagTree = "EngineKUZNYECHIK";
                else if (engineTagXml == "EngineXCHACHA20-POLY1305")
                    engineTagTree = "EngineXCHACHA20-POLY1305";
                else
                    engineTagTree = engineTagXml;

                TreeNode engineNode = null;
                foreach (TreeNode n in enginesRoot.Nodes)
                {
                    if ((n.Tag ?? "").ToString() == engineTagTree)
                    {
                        engineNode = n;
                        break;
                    }
                }

                if (engineNode == null)
                    continue;

                var children = _config.GetChildNodes(key.Key);
                foreach (var child in children)
                {
                    string[] parts = child.Value.Split('|');
                    string groupId = parts[parts.Length - 1].Trim();
                    GetOrCreateGroupNode(engineNode, groupId);
                }
            }

            _treeEngines.EndUpdate();
        }
        private void TreeEngines_AfterSelect(object sender, TreeViewEventArgs e)
        {
            var selectedNode = e.Node;
            if (selectedNode == null)
                return;

            // Enforce immediate textual state deployment on the UI thread surface
            if (_statusLabel != null)
            {
                _statusLabel.Text = "Updating encrypted files, please wait...";
                _statusLabel.ForeColor = Color.Gray;

                // ENTERPRISE UI REFRESH: Force the parent container control to synchronously repaint its surface immediately
                _statusLabel.GetCurrentParent()?.Update();
            }

            if (selectedNode == _treeEngines.Nodes[0] ||
                selectedNode == _treeEngines.Nodes[_treeEngines.Nodes.Count - 1])
            {
                _listViewFiles.Items.Clear();
                _statusLabel.Text = "File Selection";
                _statusLabel.ForeColor = Color.Black;

                // ENTERPRISE UI DISPATCH: Leverage the control instance directly to defer the collapse execution safely
                _treeEngines.BeginInvoke((System.Windows.Forms.MethodInvoker)delegate
                {
                    // Local recursive function to traverse and isolate containing parent structures
                    void CollapseGroupContainers(TreeNodeCollection nodes)
                    {
                        foreach (TreeNode node in nodes)
                        {
                            // If the node identifies as a Group, target its containing parent for structural collapse
                            if (node.Text != null && node.Text.ToLower().Contains("group"))
                            {
                                if (node.Parent != null)
                                {
                                    // Enforce structural collapse on the container node immediately
                                    node.Parent.Collapse();
                                }
                            }

                            // Continue deep traversal down the visual tree hierarchy
                            if (node.Nodes.Count > 0)
                            {
                                CollapseGroupContainers(node.Nodes);
                            }
                        }
                    }

                    // Initiate the recursive layout optimization across the entire tree surface
                    CollapseGroupContainers(_treeEngines.Nodes);
                });

                return;
            }
            else
            {
                _statusLabel.Text = "File Selection";
                _statusLabel.ForeColor = Color.Black;
            }

            _listViewFiles.Items.Clear();

            if (selectedNode.Tag == null || selectedNode.Tag.ToString().StartsWith("Engine"))
                return;

            string groupId = selectedNode.Tag.ToString();
            TreeNode engineNode = selectedNode.Parent;

            if (engineNode == null || engineNode.Tag == null)
                return;

            string engineTag = engineNode.Tag.ToString();

            // =========================================================================
            // POST-DECRYPTION STATE INTERCEPTION & UX FEEDBACK PIPELINE
            // =========================================================================
            if (decrypted)
            {
                // Intercept volatile state and enforce an immediate textual state acknowledgment on the UI surface
                if (_statusLabel != null)
                {
                    _statusLabel.Text = "Updating encrypted files, please wait...";
                    _statusLabel.ForeColor = Color.Gray;
                }

                // Consume the structural synchronization token immediately to stabilize subsequent ordinary tab navigations
                decrypted = false;

                // Force synchronous visual message execution context dispatch to suppress unresponsiveness perception
                Application.DoEvents();
            }

            // Map TreeView tag back to XML tag
            string engineTagXml;
            if (engineTag == "EngineAESGCM")
                engineTagXml = "EngineAES-GCM";
            else if (engineTag == "EngineAES")
                engineTagXml = "EngineAES";
            else if (engineTag == "EnginePGP")
                engineTagXml = "EnginePGP";
            else if (engineTag == "EngineIDEA")
                engineTagXml = "EngineIDEA";
            else if (engineTag == "EngineGOST")
                engineTagXml = "EngineGOST";
            else if (engineTag == "EngineSERPENT")
                engineTagXml = "EngineSERPENT";
            else if (engineTag == "EngineTWOFISH")
                engineTagXml = "EngineTWOFISH";
            else if (engineTag == "EngineCAMELLIA")
                engineTagXml = "EngineCAMELLIA";
            else if (engineTag == "EngineTHREEFISH")
                engineTagXml = "EngineTHREEFISH";
            else if (engineTag == "EngineKUZNYECHIK")
                engineTagXml = "EngineKUZNYECHIK";
            else if (engineTag == "EngineXCHACHA20-POLY1305")
                engineTagXml = "EngineXCHACHA20-POLY1305";
            else
                engineTagXml = engineTag;

            // 1. Suppress visual redrawing and layout recalculations before processing items
            _listViewFiles.BeginUpdate();

            try
            {
                // Local cache to aggregate items and minimize Win32 message queue overhead
                var itemsToAdd = new System.Collections.Generic.List<ListViewItem>();

                foreach (var key in _config.GetAllKeyValuePairs())
                {
                    string parentValue = key.Value;
                    if (string.IsNullOrEmpty(parentValue))
                        continue;

                    string parentEngineTag = parentValue.Split('|').Last().Trim();
                    if (parentEngineTag != engineTagXml)
                        continue;

                    var children = _config.GetChildNodes(key.Key);
                    foreach (var child in children)
                    {
                        string[] parts = child.Value.Split('|');
                        string childGroupId = parts[parts.Length - 1].Trim();
                        if (childGroupId != groupId)
                            continue;

                        ListViewItem item = new ListViewItem(string.Empty);
                        item.ImageIndex = 12;

                        item.SubItems.Add(child.Key);
                        item.SubItems.Add(parts[0]);
                        item.SubItems.Add(parts[1]);
                        item.SubItems.Add(parts[2]);
                        item.SubItems.Add(parts[3]);
                        item.SubItems.Add(parts[4]);
                        item.SubItems.Add(parts[5]);
                        item.SubItems.Add(parts[6]);

                        // File existence and cryptographic engine header validation
                        string encryptedFilePath = parts[0];

                        // Extract the targeting Group ID for the current XML record item
                        string recordGroupId = groupId?.Trim();

                        bool isFileValid = false;

                        if (File.Exists(encryptedFilePath))
                        {
                            try
                            {
                                // Open the file in shared non-blocking read/write mode to prevent multi-thread lock collisions
                                using (var fs = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                                using (var reader = new StreamReader(fs))
                                {
                                    string header = reader.ReadLine();
                                    if (!string.IsNullOrEmpty(header))
                                    {
                                        string[] headerParts = header.Split('|');
                                        if (headerParts.Length >= 3)
                                        {
                                            // Extract actual engine and group ID from the physical SPCR file header
                                            string actualAlgorithm = headerParts[1]?.Trim();
                                            string actualGroupId = headerParts[2]?.Trim();

                                            // Normalize the UI engine token by stripping out the "Engine" prefix string
                                            string cleanEngineTag = engineTagXml.Replace("Engine", "");

                                            // Validation condition: both cryptographic engine AND sequential Group ID must match perfectly
                                            if (cleanEngineTag == actualAlgorithm && recordGroupId == actualGroupId)
                                            {
                                                isFileValid = true;
                                            }
                                        }
                                    }
                                }
                            }
                            catch
                            {
                                // Fallback to invalid state if the storage media fails to read or the file is temporarily locked
                                isFileValid = false;
                            }
                        }
                        // Enforce gray-out styling across all sub-items if validation yields a negative match
                        if (!isFileValid)
                        {
                            item.ForeColor = Color.Gray;

                            foreach (ListViewItem.ListViewSubItem subItem in item.SubItems)
                                subItem.ForeColor = Color.Gray;
                        }

                        // Stash item in memory list instead of updating the UI hierarchy sequentially
                        itemsToAdd.Add(item);
                    }
                }

                // 2. Inject the collected items in a single atomic memory operation
                if (itemsToAdd.Count > 0)
                {
                    _listViewFiles.Items.AddRange(itemsToAdd.ToArray());

                    // Alternate row
                    _alternator = new ListViewRowAlternator(_listViewFiles);
                    _alternator.Enable();
                }
            }
            catch (Exception ex)
            {
                // Capture unexpected file system or parser faults without interrupting the main application thread
                CentralLog.LogException(ex, "UI LOAD", "Critical error during File ListView bulk population sequence.");
            }
            finally
            {
                // 3. Enforce immediate UI redraw execution; guarantees the control unfreezes under any condition
                _listViewFiles.EndUpdate();
            }

            UpdateStatusLabel(_listViewFiles, _statusLabel);
            UpdateFilesEncryptedCount();
        }
        private TreeNode GetOrCreateGroupNode(TreeNode engineNode, string groupId)
        {
            foreach (TreeNode node in engineNode.Nodes)
                if ((string)node.Tag == groupId)
                    return node;

            TreeNode groupNode = engineNode.Nodes.Add("Group " + groupId);
            groupNode.NodeFont = new Font("Verdana", 9, FontStyle.Italic);
            groupNode.ForeColor = Color.DarkGreen;
            groupNode.ImageIndex = 1;
            groupNode.SelectedImageIndex = 1;
            groupNode.Tag = groupId;

            return groupNode;
        }
        private void CreateEngineNode(TreeNode parent, string name, string tag)
        {
            TreeNode node = parent.Nodes.Add(name + " ");
            node.NodeFont = new Font("Verdana", 9);
            node.ForeColor = Color.Indigo;
            node.ImageIndex = 11;
            node.SelectedImageIndex = 11;
            node.Tag = tag;
        }
        public void UpdateFilesEncryptedCount()
        {
            int totalFiles = 0;
            foreach (var key in _config.GetAllKeyValuePairs())
            {
                var children = _config.GetChildNodes(key.Key);
                if (children != null)
                    totalFiles += children.Count;
            }

            if (_filesEncryptedNode != null)
                _filesEncryptedNode.Text = "Encrypted Files: " + totalFiles + "     ";

            _treeEngines.BeginUpdate();

            _treeEngines.EndUpdate();
        }
        private void TreeEngines_BeforeExpand(object sender, TreeViewCancelEventArgs e)
        {
            if (e.Node.Tag != null && e.Node.Tag.ToString().StartsWith("Engine"))
            {
                e.Node.ImageIndex = 14;
                e.Node.SelectedImageIndex = 14;
            }
        }
        private void TreeEngines_BeforeCollapse(object sender, TreeViewCancelEventArgs e)
        {
            if (e.Node.Tag != null && e.Node.Tag.ToString().StartsWith("Engine"))
            {
                e.Node.ImageIndex = 11;
                e.Node.SelectedImageIndex = 11;
            }
        }
        private void _treeEngines_Click(object sender, EventArgs e)
        {
            // ENTERPRISE EXTENSION SLOT: Reserved placeholder for future client-side interaction models.
            // Developers may utilize this execution hook to implement custom overlay behaviors or secondary
            // telemetry monitoring on the core tree navigation surface without breaking the main state pipeline.
        }
        public static void UpdateStatusLabel(ListView lv, ToolStripLabel statusLabel)
        {
            long totalBytes = 0;

            foreach (ListViewItem item in lv.Items)
            {
                string[] parts = item.SubItems[3].Text.Split(' ');
                if (parts.Length == 2 &&
                    double.TryParse(parts[0].Replace(",", "."), out double size))
                {
                    switch (parts[1].ToUpper())
                    {
                        case "KB": totalBytes += (long)(size * 1024); break;
                        case "MB": totalBytes += (long)(size * 1024 * 1024); break;
                        case "GB": totalBytes += (long)(size * 1024 * 1024 * 1024); break;
                    }
                }
            }

            statusLabel.Text = "File list: " + lv.Items.Count + " files, " + ByteCnt.FromBytes(totalBytes) + " total [ENC]";
        }
    }
}