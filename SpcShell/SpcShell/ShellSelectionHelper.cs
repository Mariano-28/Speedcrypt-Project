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

using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace SpcShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ShellSelectionHelper provides strict and reusable management logic
    /// for extracting selected filesystem paths from a native Windows Explorer 
    /// data object during shell extension interactions.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Secure mapping of unmanaged COM data objects into managed IDataObject interface targets.
    /// - Hardcoded formatting constraints utilizing explicit clipboard structures and storage medium parameters.
    /// - Dynamic interrogation of file counts via native Win32 DragQueryFile extraction cycles.
    /// - High-performance string construction loops parsing native buffer pointers safely.
    /// - Elimination of memory anomalies through explicit structural unmanaged storage releases (ReleaseStgMedium).
    /// - Precise COM reference count degradation via strict Marshal.ReleaseComObject destruction cycles.
    /// - Failure-tolerant boundary traps returning empty collections instead of cascading runtime errors.
    /// - Absolute encapsulation of complex data marshaling, preventing layout duplication across consumers.
    /// - Clean architectural isolation keeping underlying data operations detached from presentation modules.
    ///
    /// - The class is UI-aware only to the extent of parsing file selections from shell desktop instances,
    /// -  but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for this C# implementation, shell interop logic,
    /// architectural integration, and behavioral correctness lies entirely with the author.
    /// </remarks>
    public static class ShellSelectionHelper
    {
        private const short CF_HDROP = 15;

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern uint DragQueryFile(
            System.IntPtr hDrop,
            uint iFile,
            System.Text.StringBuilder buffer,
            uint bufferSize);

        [DllImport("ole32.dll")]
        private static extern void ReleaseStgMedium(ref STGMEDIUM medium);
        public static List<string> GetSelectedPaths(System.IntPtr dataObject)
        {
            var paths = new List<string>();

            if (dataObject == System.IntPtr.Zero)
                return paths;

            IDataObject shellData =
                Marshal.GetTypedObjectForIUnknown(
                    dataObject,
                    typeof(IDataObject)) as IDataObject;

            if (shellData == null)
                return paths;

            FORMATETC format = new FORMATETC
            {
                cfFormat = CF_HDROP,
                ptd = System.IntPtr.Zero,
                dwAspect = DVASPECT.DVASPECT_CONTENT,
                lindex = -1,
                tymed = TYMED.TYMED_HGLOBAL
            };

            STGMEDIUM medium = new STGMEDIUM();

            try
            {
                shellData.GetData(ref format, out medium);

                if (medium.unionmember == System.IntPtr.Zero)
                    return paths;

                uint count = DragQueryFile(
                    medium.unionmember,
                    0xFFFFFFFF,
                    null,
                    0);

                for (uint i = 0; i < count; i++)
                {
                    var path = new System.Text.StringBuilder(1024);
                    DragQueryFile(
                        medium.unionmember,
                        i,
                        path,
                        (uint)path.Capacity);

                    string formattedPath = path.ToString();
                    if (!string.IsNullOrWhiteSpace(formattedPath))
                    {
                        paths.Add(formattedPath);
                    }
                }

                return paths;
            }
            catch
            {
                return paths;
            }
            finally
            {
                if (medium.unionmember != System.IntPtr.Zero)
                {
                    ReleaseStgMedium(ref medium);
                }

                if (shellData != null)
                {
                    Marshal.ReleaseComObject(shellData);
                }
            }
        }
    }
}