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
using Speedcrypt.Exceptionlog;

using System.Runtime.InteropServices;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// Capturescreen: Provides global utility methods to trigger the native 
    /// Windows screen capture system.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Consistent global screen capture triggering via native OS integration.
    /// - Low-level virtual key simulation bypasses complex UI layer dependencies.
    /// - Use of keybd_event to execute system-wide native shortcuts seamlessly.
    /// - Clean separation between OS-level interactions and core application logic.
    /// - Reusable, centralized logic to avoid code duplication across the project.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class Capturescreen
    {
        #region Win32 API Imports

        [DllImport("user32.dll")]
        private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, int dwExtraInfo);

        #endregion

        #region Virtual Key Constants

        private const byte VK_LWIN = 0x5B;   // Left Windows key
        private const byte VK_SHIFT = 0x10;  // Shift key
        private const byte VK_S = 0x53;      // 'S' key
        private const uint KEYEVENTF_KEYUP = 0x0002; // Key release flag

        #endregion

        /// <summary>
        /// Simulates the Windows + Shift + S hotkey to open the native screen snipping tool.
        /// </summary>
        public static void TriggerCapture()
        {
            try
            {
                // 1. Press keys (Windows + Shift + S)
                keybd_event(VK_LWIN, 0, 0, 0);
                keybd_event(VK_SHIFT, 0, 0, 0);
                keybd_event(VK_S, 0, 0, 0);

                // 2. Release keys in reverse order
                keybd_event(VK_S, 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_LWIN, 0, KEYEVENTF_KEYUP, 0);
            }
            catch (Exception ex)
            {
                // Log the exception to the centralized logging system
                CentralLog.LogException(ex, "SECURITY", "Error during the Screen Capture Process!");
            }
        }
    }
}