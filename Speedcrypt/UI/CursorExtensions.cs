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

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.UI{

    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// CursorExtensions provides strict and reusable behavior
    /// for dynamic cursor management over interactive controls
    /// such as ListView, TreeView, and ListBox within a Windows Forms interface.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Automatic hand cursor activation when hovering valid items or nodes.
    /// - Safe handling of Enabled and Visible control states.
    /// - Deterministic cursor reset on MouseLeave.
    /// - Elimination of duplicated MouseMove logic across Forms.
    /// - Centralized and reusable UI behavior configuration.
    /// - Encapsulation of interaction logic without polluting Form code.
    /// - Immediate and predictable visual feedback to the user.
    /// - Extension-based design allowing clean one-line activation.
    /// - Preservation of layout and business logic separation.
    /// - Minimal overhead and zero impact on unrelated UI behavior.
    ///
    /// The class is UI-aware only to the extent of managing cursor state,
    /// and does not introduce additional form responsibilities,
    /// ensuring modularity and architectural cleanliness.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class CursorExtensions
    {
        private static bool _isSuspended;

        /// <summary>
        /// Gets or sets a value indicating whether programmatic cursor overrides are suspended.
        /// When true, forces target controls to fallback to Default rendering to optimize UI cycles during cryptographic execution.
        /// </summary>
        public static bool IsSuspended
        {
            get => _isSuspended;
            set => _isSuspended = value;
        }

        /// <summary>
        /// Enables automatic hand cursor behavior for ListView.
        /// Safe: respects Enabled, Visible, and global Suspension state.
        /// Logs exception silently if invoked on null.
        /// </summary>
        public static void EnableHandCursor(this ListView listView)
        {
            try
            {
                if (listView == null)
                    throw new ArgumentNullException(nameof(listView));

                listView.MouseMove += (s, e) =>
                {
                    if (!listView.Enabled || !listView.Visible || _isSuspended)
                    {
                        if (listView.Cursor != Cursors.Default)
                            listView.Cursor = Cursors.Default;
                        return;
                    }

                    Cursor desiredCursor = listView.HitTest(e.X, e.Y).Item != null
                        ? Cursors.Hand
                        : Cursors.Default;

                    if (listView.Cursor != desiredCursor)
                        listView.Cursor = desiredCursor;
                };

                listView.MouseLeave += (s, e) =>
                {
                    if (listView.Cursor != Cursors.Default)
                        listView.Cursor = Cursors.Default;
                };
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "CursorExtensions", "EnableHandCursor failed for ListView");
            }
        }

        /// <summary>
        /// Enables automatic hand cursor behavior for TreeView.
        /// Safe: respects Enabled, Visible, and global Suspension state.
        /// Logs exception silently if invoked on null.
        /// </summary>
        public static void EnableHandCursor(this TreeView treeView)
        {
            try
            {
                if (treeView == null)
                    throw new ArgumentNullException(nameof(treeView));

                treeView.MouseMove += (s, e) =>
                {
                    if (!treeView.Enabled || !treeView.Visible || _isSuspended)
                    {
                        if (treeView.Cursor != Cursors.Default)
                            treeView.Cursor = Cursors.Default;
                        return;
                    }

                    TreeNode node = treeView.GetNodeAt(e.X, e.Y);

                    Cursor desiredCursor = node != null
                        ? Cursors.Hand
                        : Cursors.Default;

                    if (treeView.Cursor != desiredCursor)
                        treeView.Cursor = desiredCursor;
                };

                treeView.MouseLeave += (s, e) =>
                {
                    if (treeView.Cursor != Cursors.Default)
                        treeView.Cursor = Cursors.Default;
                };
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "CursorExtensions", "EnableHandCursor failed for TreeView");
            }
        }

        /// <summary>
        /// Enables automatic hand cursor behavior for ListBox.
        /// Safe: respects Enabled, Visible, and global Suspension state.
        /// Logs exception silently if invoked on null.
        /// </summary>
        public static void EnableHandCursor(this ListBox listBox)
        {
            try
            {
                if (listBox == null)
                    throw new ArgumentNullException(nameof(listBox));

                listBox.MouseMove += (s, e) =>
                {
                    if (!listBox.Enabled || !listBox.Visible || _isSuspended)
                    {
                        if (listBox.Cursor != Cursors.Default)
                            listBox.Cursor = Cursors.Default;
                        return;
                    }

                    int index = listBox.IndexFromPoint(e.Location);

                    Cursor desiredCursor = index != ListBox.NoMatches
                        ? Cursors.Hand
                        : Cursors.Default;

                    if (listBox.Cursor != desiredCursor)
                        listBox.Cursor = desiredCursor;
                };

                listBox.MouseLeave += (s, e) =>
                {
                    if (listBox.Cursor != Cursors.Default)
                        listBox.Cursor = Cursors.Default;
                };
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "CursorExtensions", "EnableHandCursor failed for ListBox");
            }
        }
    }

    // ========================== Usage ===================================
    // yourListView.EnableHandCursor();
    // yourTreeView.EnableHandCursor();
    // yourListBox.EnableHandCursor();
    // You can insert as many ListViews, TreeViews, and ListBoxes as needed.
}