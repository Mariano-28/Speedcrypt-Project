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
using System.Linq;

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// PGPFoldersManager: Manages persistent storage of PGP key folder paths
    /// and tracks the last folder selected for encryption operations.
    /// </summary>
    /// 
    /// <remarks>
    /// This class provides folder management functionality including:
    /// - Persistent storage of folder paths in a configuration file
    /// - Addition and removal of folders
    /// - Tracking of the last selected folder
    /// - Binding of folder paths to UI controls such as ComboBox
    ///
    /// Folder data is stored inside a dedicated "PGPFolders" directory
    /// within the application base path.
    ///
    /// The class encapsulates all file I/O operations required to load
    /// and save configuration data while protecting internal collections
    /// from external modification.
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>    
    public class PGPFoldersManager
    {
        // Base directory for storing PGP folder metadata.
        private string BaseFolder;

        // File storing the list of folders and the last selected folder.
        private string ConfigFile;

        // List containing all user-added folders.
        private System.Collections.Generic.List<string> FoldersList;

        // Stores the last folder used for real encryption operations.
        private string LastSelectedFolder;

        // Constructor: Initializes paths and empty folder list.
        public PGPFoldersManager()
        {
            BaseFolder = System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "PGPFolders");
            ConfigFile = System.IO.Path.Combine(BaseFolder, "folders.txt");
            FoldersList = new System.Collections.Generic.List<string>();
            LastSelectedFolder = string.Empty;
        }

        // Initializes the folder manager: creates directories and config file if missing, then loads folders.
        public void Initialize()
        {
            if (!System.IO.Directory.Exists(BaseFolder))
                System.IO.Directory.CreateDirectory(BaseFolder);

            if (!System.IO.File.Exists(ConfigFile))
                System.IO.File.WriteAllText(ConfigFile, string.Empty);

            LoadFoldersFromFile();
        }

        // Adds a new folder to the list if it does not already exist (case-insensitive) and is not a root path.
        public void AddFolder(string folderPath)
        {
            if (!IsValidFolderPath(folderPath)) // <-- Strict validation added
                return;

            if (IsRootPath(folderPath))
                return;

            if (!System.IO.Directory.Exists(folderPath)) // only add if folder exists
                return;

            if (!FoldersList.Contains(folderPath, System.StringComparer.OrdinalIgnoreCase))
            {
                FoldersList.Add(folderPath);
                SaveFoldersToFile();
            }
        }

        // Removes a folder from the list (does not delete the actual folder from disk).
        public void RemoveFolder(string folderPath)
        {
            if (FoldersList.Contains(folderPath, System.StringComparer.OrdinalIgnoreCase))
            {
                FoldersList.Remove(folderPath);

                // Reset last selected if it matches the removed folder.
                if (LastSelectedFolder.Equals(folderPath, System.StringComparison.OrdinalIgnoreCase))
                    LastSelectedFolder = string.Empty;

                SaveFoldersToFile();
            }
        }

        // Returns a copy of the folders list to prevent external modification.
        public System.Collections.Generic.List<string> GetFolders()
        {
            return new System.Collections.Generic.List<string>(FoldersList);
        }

        // Sets the last selected folder for encryption, only if it exists in the list.
        public void SetLastSelected(string folderPath)
        {
            if (FoldersList.Contains(folderPath, System.StringComparer.OrdinalIgnoreCase))
            {
                LastSelectedFolder = folderPath;
                SaveFoldersToFile();
            }
        }

        // Retrieves the last selected folder.
        public string GetLastSelected()
        {
            return LastSelectedFolder;
        }

        // Binds the folder list to a ComboBox and sets the selected item to the last used folder.
        public void BindToComboBox(System.Windows.Forms.ComboBox combo)
        {
            combo.Items.Clear();

            foreach (string folder in FoldersList)
            {
                combo.Items.Add(folder);
            }

            // Set the last selected folder deterministically.
            if (!string.IsNullOrEmpty(LastSelectedFolder) && combo.Items.Contains(LastSelectedFolder))
                combo.SelectedItem = LastSelectedFolder;
            else if (combo.Items.Count > 0)
                combo.SelectedIndex = 0;
            else
                combo.Text = string.Empty;
        }

        // Refreshes the ComboBox contents after adding/removing folders.
        public void RefreshComboBox(System.Windows.Forms.ComboBox combo)
        {
            BindToComboBox(combo);
        }

        // Saves the current folder list and last selected folder to the configuration file.
        private void SaveFoldersToFile()
        {
            var lines = new System.Collections.Generic.List<string>();

            // Only keep folders that exist, automatically removing non-existing ones
            FoldersList.RemoveAll(f => !System.IO.Directory.Exists(f));

            foreach (string folder in FoldersList)
            {
                lines.Add(folder);
            }

            lines.Add("[LAST_SELECTED]=" + LastSelectedFolder);
            System.IO.File.WriteAllLines(ConfigFile, lines);
        }

        // Loads folders and last selected folder from the configuration file.
        private void LoadFoldersFromFile()
        {
            FoldersList.Clear();
            LastSelectedFolder = string.Empty;

            if (!System.IO.File.Exists(ConfigFile))
                return;

            string[] lines = System.IO.File.ReadAllLines(ConfigFile);
            foreach (string line in lines)
            {
                if (line.StartsWith("[LAST_SELECTED]="))
                {
                    LastSelectedFolder = line.Substring("[LAST_SELECTED]=".Length);
                }
                else if (!string.IsNullOrWhiteSpace(line))
                {
                    string path = line.Trim();
                    if (IsValidFolderPath(path) && !IsRootPath(path) && System.IO.Directory.Exists(path)) // strict validation added
                        FoldersList.Add(path);
                }
            }

            // Save immediately to clean up non-existing folders from file
            SaveFoldersToFile();
        }

        // Checks if the provided path is a root path like C:\ or D: (case-insensitive).
        private bool IsRootPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            string root = System.IO.Path.GetPathRoot(path);
            return string.Equals(path.TrimEnd('\\'), root.TrimEnd('\\'), System.StringComparison.OrdinalIgnoreCase);
        }

        // ========================================
        // Strict validation helper for all folder paths
        // ========================================
        public bool IsValidFolderPath(string folderPath)
        {
            if (string.IsNullOrWhiteSpace(folderPath) || folderPath.Length < 3)
                return false;

            // Only allow letter + colon + backslash at the beginning
            return char.IsLetter(folderPath[0]) && folderPath[1] == ':' && folderPath[2] == '\\';
        }        
    }

    /* ============================== Usage: Technical Summary ==================================

    1. Adding a folder:
       - Adds a new folder to the internal list and updates the configuration file.
       foldersManager.AddFolder(txtNewFolder.Text.Trim());

    2. Refreshing a ComboBox after changes:
       - Ensures the ComboBox reflects the current folders list and selects the last used folder.
       foldersManager.RefreshComboBox(cmbFolderPhat);

    3. Setting the last selected folder:
       - Marks a folder as the last used for encryption operations.
       foldersManager.SetLastSelected(cmbFolderPhat.SelectedItem.ToString());

    4. Removing a folder:
       - Deletes a folder from the internal list and updates the configuration file.
       foldersManager.RemoveFolder(folderToDelete);

    5. Binding to ComboBox for initialization:
       - Populates a ComboBox and selects the last used folder deterministically.
       foldersManager.BindToComboBox(cmbFolderPhat);
    */
}
