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
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SpcShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ShellExtension provides strict and reusable management logic
    /// for implementing a COM-visible Windows Shell Extension, interfacing 
    /// directly with native OS shell context menus via IShellExtInit and IShellContextMenu.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Explicit COM infrastructure exposure utilizing explicit visibility, GUID mapping, and interface structures.
    /// - Automation of localized registry binding routines via designated assembly registration attributes.
    /// - Secure collection tracking of selected explorer targets using helper data object extractors.
    /// - Defensive object validation loops that safely isolate empty contextual process targets.
    /// - Formatting constraint compliance with structural bitwise operations filtering non-standard menu executions.
    /// - Precise translation of operational insertion increments into formatted system HRESULT responses.
    /// - Low-level structural unmarshalling of native execution information tables into managed runtime memory.
    /// - Explicit memory manipulation routines copying multi-encoding sequence buffers directly to unmanaged pointers.
    /// - Robust boundary isolation tracking that traps anomalies to return standard verification failure constants.
    /// - Architecture integration preserving structural boundaries between COM marshaling code and business logic.
    ///
    /// - The class is UI-aware only to the extent of interfacing with native COM pointers and shell control messages,
    /// -  but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for this C# implementation, shell interop logic,
    /// architectural integration, and behavioral correctness lies entirely with the author.
    /// </remarks>

    [ComVisible(true)]
    [Guid("D6E693C4-0A4F-4E54-9E87-8F53E3E7D2A1")]
    [ClassInterface(ClassInterfaceType.None)]
    public sealed class ShellExtension :
        IShellExtInit,
        IShellContextMenu
    {
        private ShellContextMenu contextMenu;

        [ComRegisterFunction]
        public static void Register(Type type)
        {
            ShellRegistration.Register();
        }

        [ComUnregisterFunction]
        public static void Unregister(Type type)
        {
            ShellRegistration.Unregister();
        }
        public void Initialize(
            IntPtr pidlFolder,
            IntPtr dataObject,
            IntPtr hKeyProgId)
        {
            List<string> selectedPaths =
                ShellSelectionHelper.GetSelectedPaths(dataObject);

            if (selectedPaths == null || selectedPaths.Count == 0)
            {
                contextMenu = null;
                return;
            }

            contextMenu = new ShellContextMenu(selectedPaths);
        }
        public int QueryContextMenu(
            IntPtr hMenu,
            uint indexMenu,
            uint idCmdFirst,
            uint idCmdLast,
            uint uFlags)
        {
            if (contextMenu == null)
                return ShellInterop.S_OK;

            if ((uFlags & ShellInterop.CMF_DEFAULTONLY) != 0)
                return ShellInterop.S_OK;

            int inserted = contextMenu.CreateMenu(
                hMenu,
                indexMenu,
                idCmdFirst);

            // Correctly returns the number of inserted items (which will be 1) mapped as an HRESULT
            return ShellInterop.MAKE_HRESULT(ShellInterop.SEVERITY_SUCCESS, ShellInterop.FACILITY_NULL, inserted);
        }
        public int InvokeCommand(IntPtr pici)
        {
            if (contextMenu == null)
                return ShellInterop.S_OK;

            try
            {
                ShellInterop.CMINVOKECOMMANDINFOEX info =
                    (ShellInterop.CMINVOKECOMMANDINFOEX)Marshal.PtrToStructure(pici, typeof(ShellInterop.CMINVOKECOMMANDINFOEX));

                // Windows extracts the relative offset from the lower 16 bits.
                // Having set wID = idCmdFirst, the extracted value will always be 0.
                if (((long)info.lpVerb & 0xFFFF0000) == 0)
                {
                    int command = (int)(info.lpVerb.ToInt64() & 0xFFFF);

                    if (contextMenu.Execute(command))
                    {
                        return ShellInterop.S_OK;
                    }
                }
            }
            catch
            {
                return ShellInterop.E_INVALIDARG;
            }

            return ShellInterop.E_INVALIDARG;
        }
        public int GetCommandString(
            UIntPtr idCommand,
            uint type,
            IntPtr reserved,
            IntPtr command,
            int length)
        {
            if (contextMenu == null)
                return ShellInterop.S_OK;

            string helpText = contextMenu.GetHelpText((uint)idCommand.ToUInt64());

            if (string.IsNullOrEmpty(helpText))
                return ShellInterop.S_OK;

            try
            {
                if (type == ShellInterop.GCS_HELPTEXTW || (type == (ShellInterop.GCS_HELPTEXTW | ShellInterop.GCS_UNICODE)))
                {
                    byte[] bytes = System.Text.Encoding.Unicode.GetBytes(helpText + "\0");
                    int maxBytes = Math.Min(bytes.Length, length * 2);
                    Marshal.Copy(bytes, 0, command, maxBytes);
                    return ShellInterop.S_OK;
                }
                else if (type == ShellInterop.GCS_HELPTEXTA)
                {
                    byte[] bytes = System.Text.Encoding.ASCII.GetBytes(helpText + "\0");
                    int maxBytes = Math.Min(bytes.Length, length);
                    Marshal.Copy(bytes, 0, command, maxBytes);
                    return ShellInterop.S_OK;
                }
            }
            catch
            {
                return ShellInterop.E_INVALIDARG;
            }

            return ShellInterop.E_INVALIDARG;
        }
    }
}