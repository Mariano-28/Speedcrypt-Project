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
// https://www.gnu.org/licenses/gpl-3.0.html

using System;
using System.IO;
using Microsoft.Win32;
using System.Windows.Forms;
using System.Runtime.InteropServices;

// SpcUtility
using SpcUtility.UI;

namespace SpcUtility.RegKeys
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// AddKey: Utility class for Speedcrypt file extension registration.
    /// Registers the .SPCR extension in the Windows registry, associates
    /// it with the Speedcrypt executable, sets the default icon, and
    /// ensures Explorer updates the file associations.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Correct registration of the .SPCR file type under HKLM\Software\Classes
    /// - Association with Speedcrypt executable for seamless user experience
    /// - Proper icon assignment for Speedcrypt encrypted files
    /// - Automatic notification to Windows Explorer of the change
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>    
    public static class AddKey
    {
        private const int SHCNE_ASSOCCHANGED = 0x08000000;
        private const int SHCNF_IDLIST = 0x0000;
        private const int SHCNF_FLUSH = 0x1000;

        [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern void SHChangeNotify(
            int wEventId,
            int uFlags,
            IntPtr dwItem1,
            IntPtr dwItem2
        );
        public static void RegisterSpcExtension()
        {
            try
            {
                // Full path of the executable dynamically resolved from the current running environment
                string exePath = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "Speedcrypt.exe");

                string ext = ".SPCR";
                string progId = "SpeedcryptFile";

                // Target HKEY_LOCAL_MACHINE\Software\Classes to bypass UAC profile redirection issues
                string baseClassesPath = @"Software\Classes\";

                // Create or open the extension key under machine-wide classes registry
                using (RegistryKey extKey = Registry.LocalMachine.CreateSubKey(baseClassesPath + ext))
                {
                    if (extKey != null)
                    {
                        extKey.SetValue("", progId);
                    }
                }

                // Create global ProgID definition and assign a descriptive file type name
                using (RegistryKey progKey = Registry.LocalMachine.CreateSubKey(baseClassesPath + progId))
                {
                    if (progKey != null)
                    {
                        progKey.SetValue("", "Speedcrypt Encrypted File");

                        // Set default icon referencing the executable's first embedded icon resource (index 0)
                        using (RegistryKey defaultIcon = progKey.CreateSubKey("DefaultIcon"))
                        {
                            if (defaultIcon != null)
                            {
                                defaultIcon.SetValue("", exePath + ",0");
                            }
                        }

                        // Set open verb shell execution command for handling the file payload
                        using (RegistryKey shellKey = progKey.CreateSubKey(@"Shell\Open\Command"))
                        {
                            if (shellKey != null)
                            {
                                shellKey.SetValue("", "\"" + exePath + "\" \"%1\"");
                            }
                        }
                    }
                }

                // Instruct Windows Explorer to flush caches and instantly refresh shell file associations
                SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSH, IntPtr.Zero, IntPtr.Zero);

                MessageBox.Show("SPCR extension registered successfully!", ForAllUnits.Info, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error registering SPCR extension: " + ex.Message, ForAllUnits.Error, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}