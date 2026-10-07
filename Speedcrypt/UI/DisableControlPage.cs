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
using System.Windows.Forms;

namespace Speedcrypt.UI{

    /// <summary>
    /// Created by Mariano Ortu    
    ///
    /// DisableControlPage: Utility class for WinForms TabControl and ListView customization.
    /// Provides methods to configure layout execution navigation constraints, disable horizontal and vertical 
    /// scrollbar interactions, and custom low-level message filtering for consistent UI design.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Proper intercept and cancellation of tab index navigation sequences
    /// - Absolute suppression of user-driven item selection changes within ListView containers
    /// - Low-level mouse message filtering to bypass selection highlighting and context menus
    /// - Complete suppression of vertical and horizontal scrolling, including mouse wheel and keyboard navigation (WM_VSCROLL, WM_HSCROLL)
    /// - Interception of non-client area mouse interactions to fully lock both the right and bottom scrollbars (HTVSCROLL, HTHSCROLL)
    /// - Active integration with the Application message loop via IMessageFilter implementation
    /// - Sub-system isolation utilizing deterministic detachment routines to prevent handler leaks
    /// - Reusable utility for any WinForms project requiring enhanced control layout presentation
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class DisableControlPage : IMessageFilter
    {
        private TabControl _tabControl;
        private ListView _listView;
        private IntPtr _headerHandle = IntPtr.Zero;

        // Standard Win32 Message Constants for Mouse Input Window Notifications
        private const int WM_LBUTTONDOWN = 0x0201;
        private const int WM_LBUTTONUP = 0x0202;
        private const int WM_LBUTTONDBLCLK = 0x0203;
        private const int WM_RBUTTONDOWN = 0x0204;
        private const int WM_RBUTTONUP = 0x0205;
        private const int WM_RBUTTONDBLCLK = 0x0206;

        // Win32 Constants for Scrolling and Non-Client Mouse Clicks
        private const int WM_VSCROLL = 0x0115;
        private const int WM_HSCROLL = 0x0114;
        private const int WM_MOUSEWHEEL = 0x020A;
        private const int WM_NCLBUTTONDOWN = 0x00A1;
        private const int WM_NCLBUTTONUP = 0x00A2;
        private const int WM_NCLBUTTONDBLCLK = 0x00A3;

        // Non-Client Hit Test Constants for Scrollbars
        private const int HTHSCROLL = 6; // Horizontal Scrollbar
        private const int HTVSCROLL = 7; // Vertical Scrollbar

        // Win32 Messages and Notifications for SysHeader32 Control Interception
        private const int LVM_FIRST = 0x1000;
        private const int LVM_GETHEADER = LVM_FIRST + 31;
        private const int WM_SETCURSOR = 0x0020;
        private const int WM_MOUSEMOVE = 0x0200;
        private const int WM_NCMOUSEMOVE = 0x00A0;

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        /// <summary>
        /// Binds layout execution navigation constraints to the target component instance to restrict active index mutation.
        /// </summary>
        public void Disable(TabControl tabControl)
        {
            if (tabControl == null) return;
            _tabControl = tabControl;

            _tabControl.Selecting -= TabControl_Selecting;
            _tabControl.Selecting += TabControl_Selecting;
        }

        /// <summary>
        /// Binds item state constraints, resolves the native SysHeader32 handle, and registers the low-level message filter to isolate the target ListView instance.
        /// </summary>
        public void Disable(ListView listView)
        {
            if (listView == null) return;
            _listView = listView;

            _listView.ItemSelectionChanged -= ListView_ItemSelectionChanged;
            _listView.ItemSelectionChanged += ListView_ItemSelectionChanged;

            // Resolve the native SysHeader32 handle belonging to the target ListView control
            if (_listView.IsHandleCreated)
            {
                _headerHandle = SendMessage(_listView.Handle, LVM_GETHEADER, IntPtr.Zero, IntPtr.Zero);
            }

            // Register the global message filter routine into the application thread context
            Application.RemoveMessageFilter(this);
            Application.AddMessageFilter(this);
        }

        /// <summary>
        /// Destroys structural navigation and message execution constraints to restore standard control container interactivity.
        /// </summary>
        public void Enable()
        {
            if (_tabControl != null)
            {
                _tabControl.Selecting -= TabControl_Selecting;
            }

            if (_listView != null)
            {
                _listView.ItemSelectionChanged -= ListView_ItemSelectionChanged;
            }

            _headerHandle = IntPtr.Zero;

            // Unregister the message filter
            Application.RemoveMessageFilter(this);
        }
        private void TabControl_Selecting(object sender, TabControlCancelEventArgs e)
        {
            // Blocks tab switching
            e.Cancel = true;
        }
        private void ListView_ItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
            // Reverts any selection attempt back to its previous state
            if (e.IsSelected)
            {
                e.Item.Selected = false;
            }
        }
        public bool PreFilterMessage(ref Message m)
        {
            if (_listView == null)
            {
                return false;
            }

            // Intercept and suppress tracking, cursor manipulation, and interaction messages dispatched to the SysHeader32 child window
            if (_headerHandle != IntPtr.Zero && m.HWnd == _headerHandle)
            {
                if (m.Msg == WM_LBUTTONDOWN || m.Msg == WM_LBUTTONDBLCLK ||
                    m.Msg == WM_NCLBUTTONDOWN || m.Msg == WM_NCLBUTTONDBLCLK ||
                    m.Msg == WM_SETCURSOR || m.Msg == WM_MOUSEMOVE || m.Msg == WM_NCMOUSEMOVE)
                {
                    return true;
                }
            }

            if (m.HWnd != _listView.Handle)
            {
                return false;
            }

            // 1. Block standard mouse clicks inside the ListView client area
            if (m.Msg == WM_LBUTTONDOWN || m.Msg == WM_LBUTTONUP || m.Msg == WM_LBUTTONDBLCLK ||
                m.Msg == WM_RBUTTONDOWN || m.Msg == WM_RBUTTONUP || m.Msg == WM_RBUTTONDBLCLK)
            {
                return true;
            }

            // 2. Block scrolling messages (Keyboard arrows, PageUp/PageDown, Mouse Wheel, Trackpad)
            if (m.Msg == WM_VSCROLL || m.Msg == WM_HSCROLL || m.Msg == WM_MOUSEWHEEL)
            {
                return true;
            }

            // 3. Block mouse clicks specifically on the Right (Vertical) and Bottom (Horizontal) Scrollbars
            if (m.Msg == WM_NCLBUTTONDOWN || m.Msg == WM_NCLBUTTONUP || m.Msg == WM_NCLBUTTONDBLCLK)
            {
                int hitTest = m.WParam.ToInt32();
                if (hitTest == HTVSCROLL || hitTest == HTHSCROLL)
                {
                    return true;
                }
            }

            return false;
        }
    }
}