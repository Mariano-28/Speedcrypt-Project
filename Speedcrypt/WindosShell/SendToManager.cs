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
using System.Runtime.InteropServices;

namespace Speedcrypt.WindowsShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// SendToManager provides strict and reusable management logic
    /// for processing and displaying system shortcut links inside
    /// a Windows Form interface.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Safe scanning of the standard Windows SendTo user directory.
    /// - Dynamic population of ListView visual targets using optimized batch updates.
    /// - Secure extraction of shell-level small icons via native Win32 API calls.
    /// - Isolated memory isolation by cloning native bitmaps to avoid runtime exceptions.
    /// - Immediate unmanaged pointer destruction to secure the Windows host memory.
    /// - Thread-safe integration through automatic cross-thread UI execution marshaling.
    /// - Filtering logic that explicitly ignores hidden and system shortcut entities.
    /// - Complete encapsulation of shell interaction routines, preventing Form duplication.
    /// - Robust error isolation with integrated application exception fallback messaging.
    /// - Non-blocking operational flow during layout modifications using visual state buffers.
    ///
    /// - The class is UI-aware only to the extent of updating structural ListView and ImageList collections,
    /// - but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public sealed class SendToManager
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct SHFILEINFO
        {
            public IntPtr hIcon;
            public int iIcon;
            public uint dwAttributes;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szDisplayName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
            public string szTypeName;
        }

        private const uint SHGFI_ICON = 0x000000100;
        private const uint SHGFI_SMALLICON = 0x000000001;

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyIcon(IntPtr hIcon);

        /// <summary>
        /// Scans the Windows SendTo directory and populates the ListView.
        /// Extracts shell icons into a fully independent, isolated Bitmap memory layout to strictly prevent get_Width() exceptions.
        /// </summary>
        public static void PopulateSendToMenu(ListView listView, ImageList imageList)
        {
            if (listView == null) return;

            if (listView.InvokeRequired)
            {
                listView.Invoke(new Action(() => PopulateSendToMenu(listView, imageList)));
                return;
            }

            listView.BeginUpdate();
            listView.Items.Clear();

            if (imageList != null)
            {
                imageList.Images.Clear();
            }

            try
            {
                string sendToPath = Environment.GetFolderPath(Environment.SpecialFolder.SendTo);

                if (!Directory.Exists(sendToPath))
                {
                    listView.EndUpdate();
                    return;
                }

                string[] files = Directory.GetFiles(sendToPath);
                foreach (string file in files)
                {
                    FileInfo fileInfo = new FileInfo(file);

                    if ((fileInfo.Attributes & FileAttributes.Hidden) != 0 ||
                        (fileInfo.Attributes & FileAttributes.System) != 0)
                    {
                        continue;
                    }

                    string displayName = Path.GetFileNameWithoutExtension(fileInfo.Name);

                    if (imageList != null)
                    {
                        SHFILEINFO shfi = new SHFILEINFO();
                        uint flags = SHGFI_ICON | SHGFI_SMALLICON;

                        IntPtr res = SHGetFileInfo(file, 0, ref shfi, (uint)Marshal.SizeOf(shfi), flags);

                        if (res != IntPtr.Zero && shfi.hIcon != IntPtr.Zero)
                        {
                            using (Icon fileIcon = Icon.FromHandle(shfi.hIcon))
                            {
                                using (Bitmap tempBitmap = fileIcon.ToBitmap())
                                {
                                    // Deep-clone pixel matrix data to structurally unbind it from Win32 memory cycles
                                    Bitmap standaloneBitmap = tempBitmap.Clone(
                                        new Rectangle(0, 0, tempBitmap.Width, tempBitmap.Height),
                                        tempBitmap.PixelFormat);

                                    // Commit the isolated bitmap strictly into managed image inventory
                                    imageList.Images.Add(file, standaloneBitmap);
                                }
                            }
                            // Clean up unmanaged pointers immediately to protect the Windows desktop instance
                            DestroyIcon(shfi.hIcon);
                        }
                    }

                    ListViewItem item = new ListViewItem(string.Empty, file);
                    item.SubItems.Add(displayName);

                    listView.Items.Add(item);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load SendTo shortcuts: {ex.Message}", "Speedcrypt Core Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                listView.EndUpdate();
            }
        }
    }
}