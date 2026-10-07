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

using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ToolStripCursor: Internal static helper class to manage mouse cursor behavior
    /// on ToolStrip buttons that do not expose the Cursor property directly. This class
    /// applies the Hand cursor to a ToolStrip when the user hovers over a specific
    /// reference button, restoring the default cursor when the mouse leaves.
    ///
    /// This approach allows:
    /// - Consistent visual feedback for interactive buttons on ToolStrips.
    /// - Avoids manual cursor handling for each ToolStrip item.
    /// - Lightweight and deterministic cursor management without side effects.
    /// </summary>
    ///
    /// <remarks>
    /// Usage:
    /// - Call EnableHandCursor(referenceButton, toolStrip) to activate.
    /// - Only affects the provided reference button; does not globally change other buttons.
    /// - Designed for Speedcrypt UI consistency and usability enhancement.
    /// - No state is stored; purely event-driven behavior.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    internal static class ToolStripCursor
    {
        /// <summary>
        /// Apply Hand cursor to a ToolStrip when hovering over a reference ToolStripButton.
        /// Restores default cursor on MouseLeave.
        /// </summary>
        /// <param name="referenceButton">The ToolStripButton to monitor for hover.</param>
        /// <param name="toolStrip">The parent ToolStrip whose cursor will be changed.</param>
        public static void EnableHandCursor(ToolStripButton referenceButton, ToolStrip toolStrip)
        {
            if (referenceButton == null || toolStrip == null) return;

            referenceButton.MouseEnter += (s, e) => toolStrip.Cursor = Cursors.Hand;
            referenceButton.MouseLeave += (s, e) => toolStrip.Cursor = Cursors.Default;
        }
    }

    // Usage Examples:

    // Basic usage: apply hand cursor when hovering over btnEncrypt on toolStripMain
    // ToolStripCursor.EnableHandCursor(btnEncrypt, toolStripMain);

    // Can be repeated for other buttons individually without affecting others
    // ToolStripCursor.EnableHandCursor(btnDecrypt, toolStripMain);
    // ToolStripCursor.EnableHandCursor(btnSettings, toolStripMain);
}