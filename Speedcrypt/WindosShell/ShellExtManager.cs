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
using System.Drawing;
using Microsoft.Win32;
using System.Windows.Forms;

namespace Speedcrypt.WindowsShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ShellExtManager provides strict and reusable management logic
    /// for auditing and displaying the active status of the Windows Shell 
    /// Extension context menu within a visual user interface.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Safe querying of the LocalMachine registry path for approved shell extensions.
    /// - Dynamic auditing of specialized COM GUID parameters within the Windows subsystem.
    /// - Isolation of execution failure points during restricted registry token access.
    /// - Thread-safe integration through automatic cross-thread UI execution marshaling.
    /// - Defensive memory management by cloning native icons into standalone visual assets.
    /// - Grid layout synchronization using optimized visual batch update buffers.
    /// - Explicit control over child sub-item structural formatting for independent rendering.
    /// - Contextual color assignment to dynamically reflect active or inactive system states.
    /// - Complete encapsulation of validation checks, preventing interface logic duplication.
    /// - Structural separation between direct operating system verification and display modules.
    ///
    /// - The class is UI-aware only to the extent of updating structural ListView and ImageList collections,
    /// -  but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    public sealed class ShellExtManager
    {
        private const string ContextMenuGuid = "{D6E693C4-0A4F-4E54-9E87-8F53E3E7D2A1}";
        private const string ApprovedKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";

        /// <summary>
        /// Audits the Windows Registry to determine if the Shell Extension is active, then populates the target ListView.
        /// </summary>
        /// <param name="listView">The target listShellExt control representing the UI grid.</param>
        /// <param name="imageList">The ImageList asset used to store the application icon.</param>
        /// <param name="appIcon">The main Speedcrypt icon instance to display in the ID column.</param>
        public static void PopulateShellExtensionMenu(ListView listView, ImageList imageList, Icon appIcon)
        {
            if (listView == null) return;

            // Ensures thread safety across execution contexts
            if (listView.InvokeRequired)
            {
                listView.Invoke(new Action(() => PopulateShellExtensionMenu(listView, imageList, appIcon)));
                return;
            }

            listView.BeginUpdate();
            listView.Items.Clear();

            if (imageList != null)
            {
                imageList.Images.Clear();

                // Add the main application icon to the image pool using a strict standalone Bitmap clone
                if (appIcon != null)
                {
                    using (Bitmap tempBitmap = appIcon.ToBitmap())
                    {
                        Bitmap standaloneBitmap = tempBitmap.Clone(
                            new Rectangle(0, 0, tempBitmap.Width, tempBitmap.Height),
                            tempBitmap.PixelFormat);

                        imageList.Images.Add("speedcrypt_main", standaloneBitmap);
                    }
                }
            }

            bool isActive = IsExtensionRegistered();
            string statusText = isActive ? "Active" : "Inactive";

            // Map elements to UI geometry: Column 1 (ID) displays the icon, Column 2 holds the component name
            ListViewItem item = new ListViewItem(string.Empty, "speedcrypt_main");
            item.SubItems.Add("Speedcrypt Context Menu Handler");
            item.SubItems.Add(statusText);

            // Dynamically apply colors based on the registry audit state to enhance user awareness
            if (isActive)
            {
                item.SubItems[2].ForeColor = Color.Green;
            }
            else
            {
                item.SubItems[2].ForeColor = Color.Red;
            }

            // Ensure UseItemStyleForSubItems is false so the Status column can render its custom text color properly
            item.UseItemStyleForSubItems = false;

            listView.Items.Add(item);
            listView.EndUpdate();
        }

        /// <summary>
        /// Queries the Windows Registry to check if the Shell Extension GUID is properly registered and approved.
        /// </summary>
        /// <returns>True if the extension is found in the Approved keys list; otherwise, false.</returns>
        private static bool IsExtensionRegistered()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(ApprovedKeyPath, false))
                {
                    if (key == null) return false;

                    // Verify if our specific dynamic COM GUID exists inside the Windows configuration table
                    object value = key.GetValue(ContextMenuGuid);
                    return value != null;
                }
            }
            catch
            {
                // Fallback default in case of restricted user account access tokens
                return false;
            }
        }
    }
}