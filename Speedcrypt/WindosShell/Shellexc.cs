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
using System.Runtime.InteropServices;

namespace Speedcrypt.WindowsShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// Shellexc: Provides a lightweight wrapper for invoking Windows Shell actions,
    /// such as displaying the standard file Properties dialog for a specified file path.
    ///
    /// This helper encapsulates the native ShellExecuteEx Win32 API call,
    /// allowing Speedcrypt to interact with the Windows Shell in a controlled
    /// and deterministic manner.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Encapsulation of the native ShellExecuteEx Win32 API.
    /// - Support for invoking the standard Windows Properties dialog for files.
    /// - Use of the SHELLEXECUTEINFO structure to configure execution parameters.
    /// - Defined constants (SW_SHOW, SEE_MASK_INVOKEIDLIST) for correct Shell behavior.
    /// - A deterministic and stable implementation suitable for production use
    ///   within Speedcrypt file operations.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class Shellexc
    {
        private const int SW_SHOW = 5;
        private const uint SEE_MASK_INVOKEIDLIST = 0x0000000C;

        public const byte MAX_FILEVerSION = 2;

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO lpExecInfo);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SHELLEXECUTEINFO
        {
            public int cbSize;
            public uint fMask;
            public IntPtr hwnd;

            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpVerb;

            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpFile;

            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpParameters;

            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpDirectory;

            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;

            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpClass;

            public IntPtr hkeyClass;
            public uint dwHotKey;
            public IntPtr hIcon;
            public IntPtr hProcess;
        }

        /// <summary>
        /// Shows the standard Windows Properties dialog for a specified file.
        /// </summary>
        /// <param name="filename">Full path of the file.</param>
        /// <returns>True if the shell invocation succeeds; otherwise false.</returns>
        public static bool ShowFileProperties(string filename)
        {
            SHELLEXECUTEINFO info = new SHELLEXECUTEINFO();

            info.cbSize = Marshal.SizeOf(typeof(SHELLEXECUTEINFO));
            info.lpVerb = "properties";
            info.lpFile = filename;
            info.nShow = SW_SHOW;
            info.fMask = SEE_MASK_INVOKEIDLIST;

            return ShellExecuteEx(ref info);
        }
    }
}