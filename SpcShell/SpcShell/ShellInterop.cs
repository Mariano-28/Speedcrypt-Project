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
using System.Runtime.InteropServices;

namespace SpcShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ShellInterop provides strict and reusable management logic
    /// for bridging managed code with native Windows Shell components by exposing 
    /// constant flags, marshaled structures, and essential Win32 API functions.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Explicit mapping of standard HRESULT status values and unmanaged error boundary codes.
    /// - Hardcoded alignment of menu rendering identifiers and multi-encoding string control constants.
    /// - Sequential layout definitions for native structures ensuring explicit runtime binary compatibility.
    /// - Explicit character-set marshaling for multi-byte and Unicode win32 execution parameters.
    /// - High-performance signatures for structural manipulation, icon extractions, and object deletion routines.
    /// - Dynamic generation of bit-shifted HRESULT values matching native Windows kernel specifications.
    /// - Isolated definitions of critical COM interfaces to enable reliable OS-level inheritance loops.
    /// - Complete removal of layout dependencies by centralizing lower-level system hooks.
    /// - Structural integrity preserving explicit integration boundaries without introducing external side effects.
    ///
    /// - The class is UI-aware only to the extent of mapping pointers to menus, coordinate blocks, and icon handles,
    /// -  but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for this C# implementation, shell interop logic,
    /// architectural integration, and behavioral correctness lies entirely with the author.
    /// </remarks>
    public static class ShellInterop
    {
        public const int S_OK = 0;
        public const int E_INVALIDARG = unchecked((int)0x80070057);
        public const int SEVERITY_SUCCESS = 0;
        public const int FACILITY_NULL = 0;

        public const int CMF_NORMAL = 0x00000000;
        public const int CMF_DEFAULTONLY = 0x00000001;

        public const uint MIIM_STRING = 0x00000040;
        public const uint MIIM_ID = 0x00000002;
        public const uint MIIM_BITMAP = 0x00000080;
        public const uint MIIM_FTYPE = 0x00000100;

        public const uint MFT_STRING = 0x00000000;

        // GCS flags for GetCommandString
        public const uint GCS_HELPTEXTA = 0x00000000;
        public const uint GCS_HELPTEXTW = 0x00000004;
        public const uint GCS_UNICODE = 0x00000010;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CMINVOKECOMMANDINFOEX
        {
            public int cbSize;
            public int fMask;
            public IntPtr hwnd;
            public IntPtr lpVerb;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpParameters;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpDirectory;
            public int nShow;
            public int dwHotKey;
            public IntPtr hIcon;
            [MarshalAs(UnmanagedType.LPStr)]
            public string lpTitle;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpParametersW;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpDirectoryW;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpTitleW;
            public POINT ptInvoke;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            public int x;
            public int y;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct MENUITEMINFO
        {
            public uint cbSize;
            public uint fMask;
            public uint fType;
            public uint fState;
            public uint wID;
            public IntPtr hSubMenu;
            public IntPtr hbmpChecked;
            public IntPtr hbmpUnchecked;
            public IntPtr dwItemData;
            public string dwTypeData;
            public uint cch;
            public IntPtr hbmpItem;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool InsertMenuItem(
            IntPtr hMenu,
            uint uItem,
            bool fByPosition,
            ref MENUITEMINFO lpmii);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        public static extern uint ExtractIconEx(
            string lpszFile,
            int nIconIndex,
            IntPtr[] phiconLarge,
            IntPtr[] phiconSmall,
            uint nIcons);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool DestroyIcon(IntPtr hIcon);

        [DllImport("gdi32.dll", SetLastError = true)]
        public static extern bool DeleteObject(IntPtr hObject);

        public static int MAKE_HRESULT(int sev, int fac, int code)
        {
            return (sev << 31) | (fac << 16) | code;
        }
    }

    // Extracted interfaces outside the static class context to allow proper COM inheritance
    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("000214E4-0000-0000-C000-000000000046")]
    public interface IShellContextMenu
    {
        [PreserveSig]
        int QueryContextMenu(
            IntPtr hMenu,
            uint indexMenu,
            uint idCmdFirst,
            uint idCmdLast,
            uint uFlags);

        [PreserveSig]
        int InvokeCommand(
            IntPtr pici);

        [PreserveSig]
        int GetCommandString(
            UIntPtr idCommand,
            uint type,
            IntPtr reserved,
            IntPtr command,
            int length);
    }

    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("000214E8-0000-0000-C000-000000000046")]
    public interface IShellExtInit
    {
        void Initialize(
            IntPtr pidlFolder,
            IntPtr dataObject,
            IntPtr hKeyProgId);
    }
}