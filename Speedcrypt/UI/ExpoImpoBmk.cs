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

using Speedcrypt.Exceptionlog;
using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ExpoImpoBmk: Handles export and import of ListView benchmark data
    /// in Speedcrypt, with file header validation, anti-duplicate logic,
    /// and optional overwriting of existing data.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized management of a unique file header for .txt benchmark files
    /// - Exporting ListView data to a text file with Save As functionality
    /// - Appending new records while avoiding duplicates based on a generated key
    /// - Importing benchmark data from existing files with optional overwrite
    /// - Automatic association of the file path for future saves
    /// - Icon assignment to subitems based on content (ENCRYPT, DECRYPT, DELETION)
    /// - Safe handling of invalid or missing files
    /// - Integration with Windows Forms UI elements (ListView, SaveFileDialog, OpenFileDialog)
    /// - Graceful exception handling with user feedback and logging
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class ExpoImpoBmk
    {
        // ====================================================================================================
        // ENTERPRISE IMPLEMENTATION NOTE: IMPORTATION NOTIFICATION OPTIMIZATION
        // ====================================================================================================
        // All verbose dialogs and notifications indicating successful data importation operations 
        // have been intentionally commented out to streamline the user experience (UX) and prevent 
        // interface pollution or disruptive operational flows. 
        //
        // Identical refactoring and optimization patterns have been systematically applied across 
        // multiple sibling classes within the project architecture.
        //
        // These instructional blocks remain preserved within the codebase under inactive comments 
        // to facilitate diagnostic tracing, QA verification, and specialized debugging sessions. 
        // Developers may uncomment these routines if granular runtime tracing is required.
        // ====================================================================================================

        // Unique file header identifier
        private const string UniqueHeader = "SPEEDCRYPT_BMK_EXPORT_v1.0";

        // Current associated file
        private static string CurrentFilePath = null;

        public static bool HasFile => !string.IsNullOrEmpty(CurrentFilePath);

        public static string FilePath
        {
            get => CurrentFilePath;
            private set => CurrentFilePath = value;
        }

        // ==============================
        // EXPORT (Save As)
        // ==============================
        public static void ExportListViewData(ListView listBmk)
        {
            // ENTERPRISE ARCHITECTURE: ENCAPSULATE FILE DIALOG PARAMETERS WITH DEDICATED CONTEXTUAL TITLE FOR METRIC EXPORT
            var saveFileDialog = new SaveFileDialog
            {
                Title = "Speedcrypt: export Benckmark List",
                FileName = "Benchmark Test",
                Filter = "Text Files (*.txt)|*.txt"
            };

            // EXECUTE MODAL VISUALIZATION AND PREVENT INTERACTION PROPAGATION ON CANCELLATION
            if (saveFileDialog.ShowDialog() != DialogResult.OK)
                return;

            string filePath = saveFileDialog.FileName;

            // ENFORCE DATA STRUCTURE INTEGRITY BY VERIFYING FILE STREAM HEADER INJECTION
            if (!BenchmarkEvents.WriteHeader(filePath, UniqueHeader))
            {
                MessageBox.Show("Invalid or corrupt Speedcrypt Benchmark file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // STREAM ENCAPSULATION Pipeline FOR SEQUENTIAL LISTVIEW SERIALIZATION
            using (var sw = new System.IO.StreamWriter(filePath, true))
            {
                foreach (ListViewItem item in listBmk.Items)
                {
                    var values = new System.Collections.Generic.List<string>();
                    for (int i = 1; i <= 5; i++)
                        values.Add(item.SubItems[i].Text);

                    string line = string.Join("\t", values);
                    sw.WriteLine(line);
                }
            }

            // PERSIST RESOLVED LOCAL PATH BACK TO THE RUNTIME STATE VARIABLE
            FilePath = filePath;
            //MessageBox.Show("Benchmark export completed successfully.", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
       
        // ==============================
        // SAVE (Silent State Overwrite Reflection)
        // ==============================
        public static void Save(ListView listBmk)
        {
            if (!HasFile)
            {
                ExportListViewData(listBmk);
                return;
            }

            // ENTERPRISE PROTOCOL: PURGE AND INITIALIZE FILE STREAM WITH VALIDATED HEADER IDENTIFIER SILENTLY
            if (!BenchmarkEvents.WriteHeader(FilePath, UniqueHeader))
            {
                MessageBox.Show("Invalid or corrupt Speedcrypt Benchmark file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // INITIALIZE TRACKER TO PREVENT DUPLICATION WITHIN THE CURRENT VISUAL DATA SET
            var processedKeys = new System.Collections.Generic.HashSet<string>(System.StringComparer.Ordinal);

            // STREAM ENCAPSULATION FOR OVERWRITING SYSTEM FILE WITH PRESENT DATA NODES ONLY
            using (var sw = new System.IO.StreamWriter(FilePath, true))
            {
                foreach (ListViewItem item in listBmk.Items)
                {
                    if (item.SubItems.Count < 6)
                        continue;

                    string v1 = item.SubItems[1].Text;
                    string v2 = item.SubItems[2].Text;
                    string v3 = item.SubItems[3].Text;
                    string v4 = item.SubItems[4].Text;
                    string v5 = item.SubItems[5].Text;

                    string key = MakeKey(v1, v2, v3, v4, v5);

                    // SKIP DUPLICATED ROWS WITHIN THE ACTIVE LISTVIEW STATE
                    if (processedKeys.Contains(key))
                        continue;

                    string line = string.Join("\t", v1, v2, v3, v4, v5);
                    sw.WriteLine(line);
                    processedKeys.Add(key);
                }
            }

            //MessageBox.Show("Benchmark saved successfully.", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ==============================
        // IMPORT
        // ==============================
        public static void ImportListViewData(ListView listBmk, OpenFileDialog openFileDialog, string boxErrorTitle, bool overwrite)
        {
            openFileDialog.Filter = "Text Files (*.txt)|*.txt";
            openFileDialog.RestoreDirectory = true;
            openFileDialog.Title = "Speedcrypt: Select Benchmark TXT File to load";

            if (openFileDialog.ShowDialog() != DialogResult.OK)
                return;

            string filePath = openFileDialog.FileName;

            if (!string.Equals(System.IO.Path.GetExtension(filePath), ".txt", System.StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show("Invalid or corrupt Speedcrypt Benchmark file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                if (!System.IO.File.Exists(filePath) || new System.IO.FileInfo(filePath).Length == 0)
                {
                    if (!BenchmarkEvents.WriteHeader(filePath, UniqueHeader))
                    {
                        MessageBox.Show("Invalid or corrupt Speedcrypt Benchmark file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                if (!BenchmarkEvents.ValidateHeader(filePath, UniqueHeader))
                {
                    MessageBox.Show("Invalid or corrupt Speedcrypt Benchmark file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (overwrite)
                    listBmk.Items.Clear();

                var existingKeys = new System.Collections.Generic.HashSet<string>(System.StringComparer.Ordinal);

                foreach (ListViewItem it in listBmk.Items)
                {
                    if (it.SubItems.Count >= 6)
                        existingKeys.Add(MakeKey(it.SubItems[1].Text, it.SubItems[2].Text, it.SubItems[3].Text, it.SubItems[4].Text, it.SubItems[5].Text));
                }

                var lines = new System.Collections.Generic.List<string>(System.IO.File.ReadAllLines(filePath));
                if (lines.Count > 0) lines.RemoveAt(0); // remove header

                 foreach (string line in lines)
                 {
                     if (string.IsNullOrWhiteSpace(line))
                         continue;

                     var values = line.Split('\t');
                     if (values.Length < 5)
                         continue;

                     string key = MakeKey(values[0], values[1], values[2], values[3], values[4]);
                     if (existingKeys.Contains(key))
                         continue;

                     var item = new ListViewItem();
                     for (int i = 0; i < 5; i++)
                         item.SubItems.Add(values[i].Trim());

                     listBmk.Items.Add(item);
                     existingKeys.Add(key);
                 }

                ImportIcon(listBmk);
                FilePath = filePath;

                //MessageBox.Show("Benchmark loaded successfully.", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (System.Exception ex)
            {
                MessageBox.Show("Invalid or corrupt Speedcrypt Benchmark file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "SETTINGS", "Error during import!");
            }
        }

        // ==============================
        // PRIVATE: Assign icons to ListView subitems
        // ==============================
        private static void ImportIcon(ListView listBmk)
        {
            listBmk.ShowSubItemIcons(true);

            foreach (ListViewItem item in listBmk.Items)
            {
                if (item.SubItems[2].Text.Contains("ENCRYPT"))
                    item.ImageIndex = 0;
                else if (item.SubItems[2].Text.Contains("DECRYPT"))
                    item.ImageIndex = 1;
                else if (item.SubItems[2].Text.Contains("DELETION"))
                    item.ImageIndex = 3;

                listBmk.AddIconToSubitem(item.Index, 4, 2);
            }
        }

        // ==============================
        // PRIVATE: Generate unique key for anti-duplicate logic
        // ==============================
        private static string MakeKey(string a, string b, string c, string d, string e)
        {
            return (a ?? string.Empty).Trim() + "|" +
                   (b ?? string.Empty).Trim() + "|" +
                   (c ?? string.Empty).Trim() + "|" +
                   (d ?? string.Empty).Trim() + "|" +
                   (e ?? string.Empty).Trim();
        }
    }
}