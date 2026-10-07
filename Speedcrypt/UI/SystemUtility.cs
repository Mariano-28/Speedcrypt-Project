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
using Microsoft.Win32;
using System.Diagnostics;
using System.Windows.Forms;
using System.ComponentModel;

namespace Speedcrypt.UI
{
    /// Created by Mariano Ortu
    /// 
    /// SystemUtility: Provides system and process utilities including
    /// retrieval of MSINFO32 path, process launching, and URL opening.
    /// All methods handle exceptions gracefully, avoiding unhandled crashes.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - TryGetMsinfo32Path: Retrieves the MSINFO32 executable path from the registry.
    ///   Returns true if found, false otherwise.
    /// - StartProcess: Attempts to start a process given its file path.
    ///   Returns true if successful, false on any exception.
    /// - OpenUrl: Opens a URL in the default system browser.
    ///   Returns true if successful, false on failure.
    /// - ShowError: Centralized error handler that shows messages safely.
    /// - All operations are deterministic and suitable for system utilities.
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class SystemUtility
    {
        // Retrieves MSINFO32 path from Windows registry
        public static bool TryGetMsinfo32Path(out string path)
        {
            path = string.Empty;
            object tmp = null;

            RegistryKey regKey = Registry.LocalMachine;

            if (regKey != null)
            {
                regKey = regKey.OpenSubKey("Software\\Microsoft\\Shared Tools\\MSInfo");

                if (regKey != null)
                    tmp = regKey.GetValue("Path");

                if (tmp == null)
                {
                    regKey = regKey.OpenSubKey("Software\\Microsoft\\Shared Tools Location");

                    if (regKey != null)
                    {
                        tmp = regKey.GetValue("MSInfo");

                        if (tmp != null)
                            path = Path.Combine(tmp.ToString(), "MSInfo32.exe");
                    }
                }
                else
                {
                    path = tmp.ToString();
                }

                try
                {
                    return new FileInfo(path).Exists;
                }
                catch
                {
                    path = string.Empty;
                }
            }

            return false;
        }

        // Starts a process
        public static bool StartProcess(string filePath, IWin32Window owner = null)
        {
            try
            {
                Process.Start(filePath);
                return true;
            }
            catch (Win32Exception ex)
            {
                ShowError(ex.Message, owner);
            }
            catch (Exception ex)
            {
                ShowError(ex.Message, owner);
            }

            return false;
        }

        // Opens a URL using the system default browser
        public static bool OpenUrl(string url, IWin32Window owner = null)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                };

                Process.Start(psi);
                return true;
            }
            catch (Exception ex)
            {
                ShowError(ex.Message, owner);
            }

            return false;
        }

        // Centralized error handler
        private static void ShowError(string message, IWin32Window owner)
        {
            if (owner != null)
            {
                MessageBox.Show(owner, message, Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
            else
            {
                MessageBox.Show(message,  Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
        }
    }
}