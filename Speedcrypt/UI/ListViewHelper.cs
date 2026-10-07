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
using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ListViewHelper: Provides a utility method for updating a ListView without causing
    /// vertical scrollbar jumps or flickering during bulk updates. Blocks redraw,
    /// temporarily hides the scrollbar, executes the update action, and then restores
    /// both redraw and scrollbar to ensure smooth UI behavior.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Safe and flicker-free updates to ListView controls in Windows Forms applications.
    /// - Temporary suspension of redraw and vertical scrollbar visibility to prevent UI artifacts.
    /// - Encapsulation of platform-specific Win32 API calls (SendMessage, GetWindowLongPtr, SetWindowLongPtr)
    ///   to modify window styles and control redraw behavior.
    /// - Designed as a final, stable, and deterministic helper for Speedcrypt's ListView handling.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    internal static class ListViewHelper
    {
        private const int WM_SETREDRAW = 0x000B;
        private const int GWL_STYLE = -16;
        private const int WS_VSCROLL = 0x00200000;

        [System.Runtime.InteropServices.DllImport("user32.dll", EntryPoint = "SendMessage")]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        [System.Runtime.InteropServices.DllImport("user32.dll", EntryPoint = "GetWindowLongPtr")]
        private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

        [System.Runtime.InteropServices.DllImport("user32.dll", EntryPoint = "SetWindowLongPtr")]
        private static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        /// <summary>
        /// Update the ListView safely without scrollbar jumps or flicker.
        /// </summary>
        /// <param name="lv">ListView control to update.</param>
        /// <param name="updateAction">Action performing the update.</param>
        public static void UpdateWithoutScrollbarJump(ListView lv, System.Action updateAction)
        {
            if (lv == null || updateAction == null) return;

            IntPtr originalStyle = GetWindowLongPtr(lv.Handle, GWL_STYLE);
            lv.BeginUpdate(); // Additional safety for long lists

            try
            {
                // Block redraw
                SendMessage(lv.Handle, WM_SETREDRAW, IntPtr.Zero, IntPtr.Zero);

                // Hide vertical scrollbar
                SetWindowLongPtr(lv.Handle, GWL_STYLE, new IntPtr(originalStyle.ToInt64() & ~WS_VSCROLL));

                // Execute update
                updateAction();
            }
            finally
            {
                // Restore original style
                SetWindowLongPtr(lv.Handle, GWL_STYLE, originalStyle);

                // Allow redraw and refresh
                SendMessage(lv.Handle, WM_SETREDRAW, new IntPtr(1), IntPtr.Zero);
                lv.EndUpdate();  // Ends BeginUpdate block
                lv.Invalidate();
                lv.Update();
            }
        }
    }
}