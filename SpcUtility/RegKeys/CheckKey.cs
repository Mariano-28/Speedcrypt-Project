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

using Microsoft.Win32;

namespace SpcUtility.RegKeys
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CheckKey: Utility class to verify Speedcrypt file extension registration.
    /// Validates whether the .SPCR extension and its ProgID are correctly
    /// registered in the Windows registry globally for all users.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Accurate detection of .SPCR file type registration under HKLM\Software\Classes
    /// - Verification of correct association with the SpeedcryptFile ProgID
    /// - Safe access to registry keys utilizing 'using' statements to guarantee deterministic resource disposal
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class CheckKey
    {
        public static bool IsSpcExtensionRegistered()
        {
            string ext = ".SPCR";
            string progId = "SpeedcryptFile";
            string baseClassesPath = @"Software\Classes\";

            try
            {
                // Open the extension key under HKEY_LOCAL_MACHINE\Software\Classes
                using (RegistryKey extKey = Registry.LocalMachine.OpenSubKey(baseClassesPath + ext, false))
                {
                    if (extKey == null)
                    {
                        return false;
                    }

                    // Read and validate the default value of the extension key
                    object extValue = extKey.GetValue("");
                    if (extValue == null || extValue.ToString() != progId)
                    {
                        return false;
                    }
                }

                // Open and validate the ProgID key under HKEY_LOCAL_MACHINE\Software\Classes
                using (RegistryKey progKey = Registry.LocalMachine.OpenSubKey(baseClassesPath + progId, false))
                {
                    if (progKey == null)
                    {
                        return false;
                    }
                }

                // Both the extension structure and the ProgID schema are valid and linked in HKLM
                return true;
            }
            catch
            {
                // Fail-safe default fallback in case of unexpected environment or access restrictions
                return false;
            }
        }
    }
}