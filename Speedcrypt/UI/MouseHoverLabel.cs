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
using System.Drawing;
using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// MouseHoverLabel: Provides a simple and deterministic mechanism to show
    /// a Label when the mouse pointer enters a specific TextBox and hide it
    /// when the mouse leaves the control.
    ///
    /// This helper allows multiple independent TextBox/Label associations
    /// within the same form, enabling contextual UI hints without requiring
    /// additional event-handling code in the form itself.
    ///
    /// Designed for WinForms applications and intended to keep the UI logic
    /// minimal, clear, and reusable across different parts of the application.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </summary>
    public class MouseHoverLabel
    {
        /// <summary>
        /// Associates a TextBox with a Label to show/hide on mouse hover.
        /// </summary>
        /// <param name="textBox">The TextBox to monitor for mouse enter/leave.</param>
        /// <param name="label">The Label to show/hide.</param>
        public MouseHoverLabel(TextBox textBox, Label label)
        {
            if (textBox == null) throw new ArgumentNullException(nameof(textBox));
            if (label == null) throw new ArgumentNullException(nameof(label));

            // Initially hide the label
            label.Visible = false;

            // Mouse enters TextBox: show label
            textBox.MouseEnter += (s, e) =>
            {
                label.Visible = true;
            };

            // Mouse leaves TextBox: hide label only if the cursor
            // is truly outside the TextBox client area
            textBox.MouseLeave += (s, e) =>
            {
                Point cursorPosition = textBox.PointToClient(Cursor.Position);

                if (!textBox.ClientRectangle.Contains(cursorPosition))
                {
                    label.Visible = false;
                }
            };
        }
    }

    // ========================== Usage ==============================
    // In your form constructor or initialization:
    //
    // new MouseHoverLabel(txtUsername, lblUsernameHint);
    // new MouseHoverLabel(txtPassword, lblPasswordHint);
    //
    // The associated label becomes visible when the mouse pointer
    // enters the TextBox and hides when the pointer leaves it.
}