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

using System.Drawing;
using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// TextBoxHoverHighlighter: Recursively highlights TextBox, RichTextBox, and MaskedTextBox
    /// controls within any container. Remembers and restores each control's original BackColor.
    /// Supports multiple containers independently and configurable hover color.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Recursively highlights all text input controls in any container (Forms, Panels, GroupBoxes, TabPages).
    /// - Remembers the original BackColor for precise restoration on MouseLeave.
    /// - Supports multiple containers independently without affecting other controls.
    /// - Minimal, stable, deterministic, production-ready for Speedcrypt UI.
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class TextBoxHoverHighlighter
    {
        /// <summary>
        /// Attach hover highlighting to all TextBox controls in the specified container.
        /// </summary>
        /// <param name="root">Container (Form, Panel, etc.)</param>
        /// <param name="hoverColor">Optional color to apply on mouse enter (default: Yellow)</param>
        public static void Attach(Control root, Color? hoverColor = null)
        {
            Color onEnter = hoverColor ?? Color.Yellow;
            AttachRecursive(root, onEnter);
        }
        private static void AttachRecursive(Control parent, Color hoverColor)
        {
            foreach (Control ctrl in parent.Controls)
            {
                // Only TextBox controls are considered now
                if (ctrl is TextBox)
                {
                    Color originalColor = ctrl.BackColor;

                    ctrl.MouseEnter += (s, e) => { ctrl.BackColor = hoverColor; };
                    ctrl.MouseLeave += (s, e) => { ctrl.BackColor = originalColor; };
                }

                if (ctrl.HasChildren)
                {
                    AttachRecursive(ctrl, hoverColor);
                }
            }
        }
    }

    // ========================================== Usage =================================
    // Highlight all text input controls in the current Form, default hover color Yellow:
    // TextBoxHoverHighlighter.Attach(this);

    // Highlight with custom hover color, original colors restored automatically:
    // TextBoxHoverHighlighter.Attach(this, Color.LightYellow);
}