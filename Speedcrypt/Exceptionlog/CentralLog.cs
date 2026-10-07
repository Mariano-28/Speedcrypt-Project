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
using System.Drawing;
using System.Windows.Forms;
using System.Security.Cryptography;

namespace Speedcrypt.Exceptionlog
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CentralLog: Static helper class for centralized logging of exceptions in Speedcrypt.
    /// Provides methods to log exceptions to a ListView and persist logs in a text file.
    /// </summary>
    /// <remarks>
    /// Centralizes exception management with:
    /// - Loading logs from a persistent text file into a ListView
    /// - Logging exceptions with optional module name, resolution status, and context
    /// - Determining severity levels based on exception type
    /// - Writing structured log entries to "ErrorLog.txt"
    ///
    /// 📒 Security Notes:
    /// - Logging is non-blocking; exceptions during logging are silently ignored
    /// - Do not store sensitive information unencrypted in log files
    /// - ListView formatting must match UI expectations
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks> 
    public static class CentralLog
    {
        // The ListView used to display log entries in the UI
        private static ListView _logListView;

        public static ListView LogListView
        {
            get => _logListView;
            set
            {
                _logListView = value;
                EnableDoubleBuffer(_logListView);
            }
        }
        private static void EnableDoubleBuffer(ListView lv)
        {
            if (lv == null) return;

            typeof(ListView)
                .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                .SetValue(lv, true, null);
        }

        // Event triggered when the log count changes
        public static event Action<int> LogCountChanged;

        private static void NotifyLogCountChanged()
        {
            LogCountChanged?.Invoke(LogListView?.Items.Count ?? 0);
        }

        // Path to the log file
        private static readonly string LogFilePath =
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ErrorLog.txt");

        // =======================
        // Load log entries from file into the ListView
        // =======================
        public static void LoadLogFromFile(ListView listLog)
        {
            if (listLog == null) return;

            listLog.BeginUpdate();
            listLog.Items.Clear();

            if (!File.Exists(LogFilePath))
            {
                listLog.EndUpdate();
                NotifyLogCountChanged();
                return;
            }

            string[] lines = File.ReadAllLines(LogFilePath);

            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Skips malformed lines that do not contain basic log structure to prevent startup crashes
                if (!line.Contains("Module:") || !line.Contains("Status:")) continue;

                // Correct timestamp extraction from [yyyy-MM-dd HH:mm:ss]
                string timestamp = ExtractTimestamp(line) ?? "";

                string module = ExtractField(line, "Module:") ?? "Unknown";
                string status = ExtractField(line, "Status:") ?? "Normal";
                string message = ExtractField(line, "Message:")?.Replace("[|]", "|") ?? "";
                string method = ExtractField(line, "Method:") ?? "Unknown";
                string notes = ExtractField(line, "Notes:")?.Replace("[|]", "|") ?? "";
                string handled = ExtractField(line, "Handled:") ?? "Yes";

                // Safe retrieval of the StackTrace
                string stackTrace = "See full log file";
                int stackTraceIndex = line.IndexOf("StackTrace:");
                if (stackTraceIndex >= 0)
                {
                    stackTrace = line.Substring(stackTraceIndex + "StackTrace:".Length)
                        .Trim()
                        .Replace("[|]", "|");

                    if (string.IsNullOrWhiteSpace(stackTrace))
                        stackTrace = "See full log file";
                }

                var item = new ListViewItem("");
                item.UseItemStyleForSubItems = false;

                while (item.SubItems.Count < listLog.Columns.Count)
                    item.SubItems.Add(string.Empty);

                // Verified original numerical indexing for subitem fields
                item.SubItems[1].Text = message;
                item.SubItems[2].Text = status;
                item.SubItems[3].Text = module;
                item.SubItems[4].Text = !string.IsNullOrWhiteSpace(timestamp)
                    ? timestamp
                    : DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                item.SubItems[5].Text = method;
                item.SubItems[6].Text = stackTrace;
                item.SubItems[7].Text = notes;
                item.SubItems[8].Text = handled;
                item.ImageIndex = 15;

                ApplySeverityColors(item, status);
                listLog.Items.Add(item);
            }

            listLog.EndUpdate();
            NotifyLogCountChanged();
        }
        // =======================
        // Extract timestamp from [yyyy-MM-dd HH:mm:ss]
        // =======================
        private static string ExtractTimestamp(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return null;

            int start = line.IndexOf('[');
            int end = line.IndexOf(']');

            if (start >= 0 && end > start)
            {
                string value = line.Substring(start + 1, end - start - 1).Trim();
                return string.IsNullOrWhiteSpace(value) ? null : value;
            }

            return null;
        }

        // =======================
        // Extract generic field
        // =======================
        private static string ExtractField(string line, string label)
        {
            int start = line.IndexOf(label);
            if (start < 0) return null;

            start += label.Length;
            int end = line.IndexOf('|', start);
            if (end < 0) end = line.Length;

            return line.Substring(start, end - start).Trim();
        }

        // =======================
        // Extracts the real Class.Method from StackTrace for system/IO exceptions
        // =======================
        private static string ExtractTrueMethod(Exception ex)
        {
            if (ex == null) return "Unknown";

            if (!string.IsNullOrWhiteSpace(ex.StackTrace))
            {
                string[] separator = new string[] { Environment.NewLine };
                string[] lines = ex.StackTrace.Split(separator, StringSplitOptions.RemoveEmptyEntries);

                foreach (string stackLine in lines)
                {
                    string cleanLine = stackLine.Trim();

                    if (cleanLine.Contains("System.IO") ||
                        cleanLine.Contains("WinIOError") ||
                        cleanLine.Contains("WriteCore"))
                        continue;

                    int atIdx = cleanLine.IndexOf("at ");
                    if (atIdx < 0) atIdx = cleanLine.IndexOf("in ");
                    int parenIdx = cleanLine.IndexOf('(');

                    if (parenIdx > 0)
                    {
                        int startIdx = atIdx >= 0 ? atIdx + 3 : 0;
                        string fullMethodPath = cleanLine.Substring(startIdx, parenIdx - startIdx).Trim();

                        int lastDot = fullMethodPath.LastIndexOf('.');
                        if (lastDot >= 0)
                        {
                            string methodName = fullMethodPath.Substring(lastDot + 1);
                            string remainingPath = fullMethodPath.Substring(0, lastDot);

                            int secondLastDot = remainingPath.LastIndexOf('.');
                            if (secondLastDot >= 0)
                            {
                                string className = remainingPath.Substring(secondLastDot + 1);
                                return className + "." + methodName;
                            }

                            return remainingPath + "." + methodName;
                        }

                        return fullMethodPath;
                    }
                }
            }

            if (ex.TargetSite != null && ex.TargetSite.DeclaringType != null)
            {
                return ex.TargetSite.DeclaringType.Name + "." + ex.TargetSite.Name;
            }

            return ex.TargetSite != null ? ex.TargetSite.Name : "Unknown";
        }

        // =======================
        // Log an exception
        // =======================
        public static void LogException(Exception ex, string moduleName = null, string contextMessage = "", bool handled = true)
        {
            if (ex == null) return;

            // Retrieve and sanitize advice notes thoroughly
            string notes = ExceptionAdvice.GetAdvice(ex);
            if (notes != null)
            {
                notes = notes.Replace("\r", "").Replace("\n", "").Trim();
            }
            else
            {
                notes = "";
            }

            string stackTraceShort;
            if (!string.IsNullOrWhiteSpace(ex.StackTrace))
            {
                string[] separator = new string[] { Environment.NewLine };
                string[] lines = ex.StackTrace.Split(separator, StringSplitOptions.RemoveEmptyEntries);
                stackTraceShort = lines.Length > 0 ? lines[0].Trim() : "See full log file";
            }
            else
            {
                stackTraceShort = "See full log file";
            }

            WriteToFile(ex, moduleName, handled, contextMessage, notes);

            if (LogListView == null) return;

            LogListView.BeginUpdate();

            string status = DetermineStatus(ex);
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string method = ExtractTrueMethod(ex);

            string message = string.IsNullOrWhiteSpace(contextMessage)
                ? ex.Message
                : contextMessage + " " + ex.Message;

            message = message.Replace("\r", "").Replace("\n", "").Trim();

            var item = new ListViewItem("");
            item.UseItemStyleForSubItems = false;

            while (item.SubItems.Count < LogListView.Columns.Count)
                item.SubItems.Add(string.Empty);

            item.SubItems[1].Text = message;
            item.SubItems[2].Text = status;
            item.SubItems[3].Text = moduleName ?? "Unknown";
            item.SubItems[4].Text = timestamp;
            item.SubItems[5].Text = method;
            item.SubItems[6].Text = stackTraceShort;
            item.SubItems[7].Text = notes;
            item.SubItems[8].Text = handled ? "Yes" : "No";

            ApplySeverityColors(item, status);
            item.ImageIndex = 15;

            LogListView.Items.Add(item);
            LogListView.EndUpdate();
            NotifyLogCountChanged();
        }
        // =======================
        // Log a generic event
        // =======================
        public static void LogEvent(string moduleName, string message, string methodName, bool handled = true)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                string status = "Normal";
                string notes = ExceptionAdvice.GetAdvice(new InvalidOperationException(message)) ?? "";

                if (message != null) message = message.Replace("\r", "").Replace("\n", "").Trim();
                if (notes != null) notes = notes.Replace("\r", "").Replace("\n", "").Trim();

                string stackTraceShort = "See full log file";
                if (!string.IsNullOrWhiteSpace(Environment.StackTrace))
                {
                    string[] separator = new string[] { Environment.NewLine };
                    string[] lines = Environment.StackTrace.Split(separator, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string stackLine in lines)
                    {
                        if (!stackLine.Contains(nameof(LogEvent)))
                        {
                            stackTraceShort = stackLine.Trim();
                            break;
                        }
                    }
                }

                string safeMessage = message.Replace("|", "[|]");
                string safeNotes = notes.Replace("|", "[|]");
                string safeStackTrace = stackTraceShort.Replace("|", "[|]");

                string line =
                    $"[{timestamp}] | " +
                    $"Module: {moduleName ?? "Unknown"} | " +
                    $"Status: {status} | " +
                    $"Message: {safeMessage} | " +
                    $"Method: {methodName ?? "Unknown"} | " +
                    $"Notes: {safeNotes} | " +
                    $"Handled: {(handled ? "Yes" : "No")} | " +
                    $"StackTrace: {safeStackTrace}";

                File.AppendAllText(LogFilePath, line + Environment.NewLine);

                if (LogListView == null) return;

                LogListView.BeginUpdate();

                var item = new ListViewItem("");
                item.UseItemStyleForSubItems = false;

                while (item.SubItems.Count < LogListView.Columns.Count)
                    item.SubItems.Add(string.Empty);

                item.SubItems[1].Text = message;
                item.SubItems[2].Text = status;
                item.SubItems[3].Text = moduleName ?? "Unknown";
                item.SubItems[4].Text = timestamp;
                item.SubItems[5].Text = methodName ?? "Unknown";
                item.SubItems[6].Text = stackTraceShort;
                item.SubItems[7].Text = notes;
                item.SubItems[8].Text = handled ? "Yes" : "No";

                ApplySeverityColors(item, status);
                item.ImageIndex = 15;

                LogListView.Items.Add(item);

                LogListView.EndUpdate();
                NotifyLogCountChanged();
            }
            catch
            {
                // Never throw from logger
            }
        }
        private static string DetermineStatus(Exception ex)
        {
            if (ex is NullReferenceException ||
                ex is AccessViolationException ||
                ex is OutOfMemoryException ||
                ex is StackOverflowException)
                return "High";

            if (ex is IOException ||
                ex is UnauthorizedAccessException ||
                ex is CryptographicException)
                return "Medium";

            return "Normal";
        }
        private static void WriteToFile(Exception ex, string moduleName, bool handled, string contextMessage = null, string notes = "")
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

                string message = contextMessage;
                if (!string.IsNullOrWhiteSpace(message)) message += " - ";
                message += ex.Message;

                Exception inner = ex.InnerException;
                while (inner != null)
                {
                    message += " | Inner: " + inner.Message;
                    inner = inner.InnerException;
                }

                message = message.Replace("\r", "").Replace("\n", "").Replace("|", "[|]").Trim();

                string method = ExtractTrueMethod(ex);
                string status = DetermineStatus(ex);

                if (notes != null) notes = notes.Replace("\r", "").Replace("\n", "").Replace("|", "[|]").Trim();
                string safeNotes = notes ?? "";

                string stackTrace = (ex.StackTrace ?? "See full log file")
                    .Replace(Environment.NewLine, " | ")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Replace("|", "[|]");

                string line =
                    $"[{timestamp}] | " +
                    $"Module: {moduleName ?? "Unknown"} | " +
                    $"Status: {status} | " +
                    $"Message: {message} | " +
                    $"Method: {method} | " +
                    $"Notes: {safeNotes} | " +
                    $"Handled: {(handled ? "Yes" : "No")} | " +
                    $"StackTrace: {stackTrace}";

                File.AppendAllText(LogFilePath, line + Environment.NewLine);
            }
            catch
            {
                // Never throw from the logger
            }
        }
        private static void ApplySeverityColors(ListViewItem item, string status)
        {
            switch (status)
            {
                case "High":
                    item.SubItems[2].ForeColor = Color.Red;
                    item.SubItems[2].Font = new Font(LogListView.Font, FontStyle.Bold);
                    break;

                case "Medium":
                    item.SubItems[2].ForeColor = Color.Orange;
                    item.SubItems[2].Font = new Font(LogListView.Font, FontStyle.Regular);
                    break;

                case "Normal":
                    item.SubItems[2].ForeColor = Color.Green;
                    item.SubItems[2].Font = new Font(LogListView.Font, FontStyle.Regular);
                    break;
            }

            item.SubItems[8].ForeColor = Color.Blue;
        }
    }
}