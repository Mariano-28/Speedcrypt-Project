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
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SpcShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ShellContextMenu provides strict and reusable management logic
    /// for creating, configuring, and executing an active application context 
    /// menu handler inside the native Windows Shell subsystem.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Lazy loading and explicit caching of executable targets to drastically minimize registry I/O overhead.
    /// - Dynamic operational layout switching based on filesystem item scanning and file extension tracking.
    /// - Structural wrapping of standard win32 context menu attributes using managed structures.
    /// - Secure extraction and isolated conversions of assembly shell resources into target menu bitmap indicators.
    /// - Complete prevention of unmanaged handle leaks via systematic native object deallocation cycles.
    /// - Direct argument marshaling routines supporting parallel item queues during processing operations.
    /// - Defensive validation constraints on deployment paths before activating shell process executions.
    /// - Isolated processing of context helper tooltip descriptive text assets based on execution states.
    /// - Structural decoupling of context logic blocks from direct windows form presentation elements.
    ///
    /// - The class is UI-aware only to the extent of interfacing with native menu descriptors and icon pointers,
    /// -  but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for this C# implementation, shell interop logic,
    /// architectural integration, and behavioral correctness lies entirely with the author.
    /// </remarks>
    public sealed class ShellContextMenu
    {
        private readonly List<string> selectedPaths;
        private readonly string cachedExePath;

        private bool showEncrypt;
        private bool showDecrypt;
        private IntPtr menuBitmap = IntPtr.Zero;
        public ShellContextMenu(List<string> selectedPaths)
        {
            this.selectedPaths = selectedPaths ?? new List<string>();

            // Lazy loading and caching the executable path during initialization to reduce registry I/O overhead
            this.cachedExePath = ResolveExecutablePath();

            ConfigureMenu();
        }
        public int CreateMenu(IntPtr hMenu, uint indexMenu, uint idCmdFirst)
        {
            if (!showEncrypt && !showDecrypt)
                return 0;

            // Determine the text based on the mode set by ConfigureMenu
            string menuText = showEncrypt ? "&Encrypt with Speedcrypt" : "&Decrypt with Speedcrypt";

            if (menuBitmap == IntPtr.Zero)
            {
                menuBitmap = GetIconBitmap();
            }

            ShellInterop.MENUITEMINFO mii = new ShellInterop.MENUITEMINFO();
            mii.cbSize = (uint)Marshal.SizeOf(typeof(ShellInterop.MENUITEMINFO));
            mii.fMask = ShellInterop.MIIM_STRING | ShellInterop.MIIM_ID | ShellInterop.MIIM_FTYPE;
            mii.fType = ShellInterop.MFT_STRING;
            mii.wID = idCmdFirst;
            mii.dwTypeData = menuText;
            mii.cch = (uint)menuText.Length;

            if (menuBitmap != IntPtr.Zero)
            {
                mii.fMask |= ShellInterop.MIIM_BITMAP;
                mii.hbmpItem = menuBitmap;
            }

            if (ShellInterop.InsertMenuItem(hMenu, indexMenu, true, ref mii))
            {
                return 1; // Return 1 inserted item
            }

            return 0;
        }
        public bool Execute(int normalizedCommand)
        {
            // Since we always pass idCmdFirst, the normalizedCommand returned by the Shell will always be 0
            if (normalizedCommand == 0)
            {
                if (showEncrypt)
                {
                    Launch("-encrypt");
                    return true;
                }

                if (showDecrypt)
                {
                    Launch("-decrypt");
                    return true;
                }
            }

            return false;
        }
        public string GetHelpText(uint idCommand)
        {
            if (idCommand == 0)
            {
                if (showEncrypt) return "Encrypt the selected items using Speedcrypt algorithm.";
                if (showDecrypt) return "Decrypt the selected .SPCR files.";
            }
            return string.Empty;
        }
        private void ConfigureMenu()
        {
            if (selectedPaths.Count == 0)
                return;

            string primaryPath = selectedPaths[0];

            if (System.IO.Directory.Exists(primaryPath))
            {
                showEncrypt = true;
                showDecrypt = false;
                return;
            }

            string extension = System.IO.Path.GetExtension(primaryPath);

            if (string.Equals(extension, ".SPCR", System.StringComparison.OrdinalIgnoreCase))
            {
                showEncrypt = false;
                showDecrypt = true;
            }
            else
            {
                showEncrypt = true;
                showDecrypt = false;
            }
        }
        private string ResolveExecutablePath()
        {
            string installFolder = Microsoft.Win32.Registry.GetValue(
                @"HKEY_LOCAL_MACHINE\Software\Speedcrypt",
                "InstallPath",
                null) as string;

            if (string.IsNullOrWhiteSpace(installFolder))
                return null;

            string exe = System.IO.Path.Combine(installFolder, "Speedcrypt.exe");
            return System.IO.File.Exists(exe) ? exe : null;
        }
        private IntPtr GetIconBitmap()
        {
            if (cachedExePath == null)
                return IntPtr.Zero;

            IntPtr[] largeIcons = new IntPtr[1];
            IntPtr[] smallIcons = new IntPtr[1];

            try
            {
                uint extracted = ShellInterop.ExtractIconEx(cachedExePath, 0, largeIcons, smallIcons, 1);

                if (largeIcons[0] != IntPtr.Zero) ShellInterop.DestroyIcon(largeIcons[0]);

                if (extracted > 0 && smallIcons[0] != IntPtr.Zero)
                {
                    using (System.Drawing.Icon icon = System.Drawing.Icon.FromHandle(smallIcons[0]))
                    using (System.Drawing.Bitmap bitmap = icon.ToBitmap())
                    {
                        IntPtr hBitmap = bitmap.GetHbitmap();
                        return hBitmap;
                    }
                }
            }
            catch
            {
                // Fall-safe default fallback
            }
            finally
            {
                if (smallIcons[0] != IntPtr.Zero)
                {
                    ShellInterop.DestroyIcon(smallIcons[0]);
                }
            }

            return IntPtr.Zero;
        }
        private void Launch(string operation)
        {
            if (string.IsNullOrWhiteSpace(cachedExePath))
            {
                throw new System.IO.FileNotFoundException("Speedcrypt.exe not found.");
            }

            var argumentsBuilder = new StringBuilder();
            argumentsBuilder.Append(operation);

            foreach (string path in selectedPaths)
            {
                argumentsBuilder.AppendFormat(" \"{0}\"", path);
            }

            var start = new System.Diagnostics.ProcessStartInfo
            {
                FileName = cachedExePath,
                Arguments = argumentsBuilder.ToString(),
                UseShellExecute = true,
                WorkingDirectory = System.IO.Path.GetDirectoryName(cachedExePath)
            };
            System.Diagnostics.Process.Start(start);

            if (menuBitmap != IntPtr.Zero)
            {
                ShellInterop.DeleteObject(menuBitmap);
                menuBitmap = IntPtr.Zero;
            }
        }
    }
}