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
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.UI;

namespace Speedcrypt.Exceptionlog
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// LogManager: Utility class providing controlled access to the Speedcrypt error log file.
    /// </summary>
    ///
    /// <remarks>
    /// This class manages the ErrorLog.txt file used by the Speedcrypt framework,
    /// ensuring safe reading, writing, importing, exporting, and clearing of log data.
    ///
    /// Features:
    /// - Clear, overwrite, or append log entries
    /// - Header enforcement to validate log files
    /// - Safe export and import using file dialogs
    /// - No sensitive data is stored beyond the log entries
    ///
    /// 📒 Security Notes:
    /// - All operations are informational and must not be interpreted as automated recovery.
    /// - File header ensures only valid Speedcrypt log files are used.
    /// - All methods swallow exceptions to prevent propagation and UI disruption.
    ///
    /// Designed for Speedcrypt logging framework with focus on clarity,
    /// robustness, and operator assistance.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class LogManager
    {
        private static readonly string LogFilePath =
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ErrorLog.txt");

        private const string LogHeader = "## SPEEDCRYPT ERROR LOG ##";

        // =======================
        // Clear entire log
        // =======================
        public static void ClearLog()
        {
            try
            {
                if (File.Exists(LogFilePath))
                    File.Delete(LogFilePath);
            }
            catch
            {
                // Never throw from logger
            }
        }

        // =======================
        // Export log (with SaveFileDialog)
        // Default file name: ErrorLog.txt
        // =======================
        public static bool ExportLog()
        {
            try
            {
                if (!File.Exists(LogFilePath))
                    return false;

                using (SaveFileDialog sfd = new SaveFileDialog())
                {
                    sfd.FileName = "ErrorLog.txt";
                    sfd.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
                    sfd.Title = "Speedcrypt: Export log TXT file";

                    if (sfd.ShowDialog() == DialogResult.OK)
                    {
                        string path = sfd.FileName;

                        // Read original log
                        var lines = File.ReadAllLines(LogFilePath).ToList();

                        /// <summary>
                        /// ENTERPRISE PURGE: Enforce distinct log entry filtering to prevent redundancy before header attachment.
                        /// </summary>
                        var uniqueLines = lines.Distinct().ToList();

                        // Insert header at the top
                        uniqueLines.Insert(0, LogHeader);

                        File.WriteAllLines(path, uniqueLines);
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        // =======================
        // Import log (with OpenFileDialog)
        // overwrite = true -> replaces current log
        // overwrite = false -> appends to current log
        // =======================
        public static bool ImportLog(bool overwrite)
        {
            try
            {
                using (OpenFileDialog ofd = new OpenFileDialog())
                {
                    ofd.Filter = "Text files (*.txt)|*.txt";
                    ofd.RestoreDirectory = true;
                    ofd.Title = "Speedcrypt: Select Log TXT File to load";

                    // Silent exit on user cancellation to maintain predictable UI flow
                    if (ofd.ShowDialog() != DialogResult.OK)
                        return false;

                    string sourcePath = ofd.FileName;

                    // CRITICAL DEFENSIVE CHECK: Enforce explicit extension tracking to prevent execution payload hijacks
                    if (!string.Equals(Path.GetExtension(sourcePath), ".txt", StringComparison.OrdinalIgnoreCase))
                    {
                        MessageBox.Show("Invalid or corrupt Speedcrypt log file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return false;
                    }

                    var lines = File.ReadAllLines(sourcePath).ToList();

                    // METADATA VALIDATION: Reject external operational logs missing the corporate baseline cryptographic header
                    if (!lines.Any() || lines[0] != LogHeader)
                    {
                        MessageBox.Show("Invalid or corrupt Speedcrypt log file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return false;
                    }

                    var filteredLines = lines
                        .Skip(1) // remove header
                        .Where(l => !string.IsNullOrWhiteSpace(l))
                        .ToList();

                    if (overwrite || !File.Exists(LogFilePath))
                    {
                        /// <summary>
                        /// ENTERPRISE DE-DUPLICATION: Isolate unique entry payloads during structural state replacement.
                        /// </summary>
                        var distinctLines = filteredLines.Distinct().ToList();
                        File.WriteAllLines(LogFilePath, distinctLines);
                    }
                    else
                    {
                        /// <summary>
                        /// ENTERPRISE AGGREGATION FILTER: Read active telemetry state and merge with external payloads, suppressing all duplicate metadata.
                        /// </summary>
                        var existingLines = File.ReadAllLines(LogFilePath)
                            .Where(l => !string.IsNullOrWhiteSpace(l))
                            .ToList();

                        var mergedLines = existingLines.Concat(filteredLines).Distinct().ToList();
                        File.WriteAllLines(LogFilePath, mergedLines);
                    }

                    return true;
                }
            }
            catch
            {
                // ANTI-CRASH PROTOCOL: Intercept subsystem exceptions, present unified message block, and route diagnostic trace to corporate log
                MessageBox.Show("Invalid or corrupt Speedcrypt log file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }
    }
}