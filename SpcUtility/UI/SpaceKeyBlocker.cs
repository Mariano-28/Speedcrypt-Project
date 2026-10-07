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

using System.Windows.Forms;

namespace SpcUtility.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// SpaceKeyBlocker: Utility class to block the Space key from triggering form-wide
    /// actions, while still allowing normal input in text controls.
    /// </summary>
    ///
    /// <remarks>
    /// This static class ensures:
    /// - Intercepts the KeyDown event of a Form to selectively block the Space key.
    /// - Space key is blocked for all controls except those derived from TextBoxBase
    ///   (TextBox, RichTextBox, etc.).
    /// - Provides Enable() and Disable() methods to attach or detach the blocking behavior.
    /// - No other keys are affected, preserving normal input functionality.
    /// - Designed as a stable, deterministic helper for UI behavior consistency.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    namespace SpcUtility.UI
    {
        public static class SpaceKeyBlocker
        {
            public static void Enable(Form form)
            {
                form.KeyPreview = true; // Form can intercept keys
                form.KeyDown += Form_KeyDown;
            }
            public static void Disable(Form form)
            {
                form.KeyPreview = false; // Disable intercept keys
                form.KeyDown += Form_KeyDown;
            }
            private static void Form_KeyDown(object sender, KeyEventArgs e)
            {
                Form form = sender as Form;
                if (form == null) return;

                // If Space pressed
                if (e.KeyCode == Keys.Space)
                {
                    // Block space unless focus is on a TextBoxBase (TextBox, RichTextBox)
                    if (!(form.ActiveControl is TextBoxBase))
                    {
                        e.Handled = true;
                        e.SuppressKeyPress = true;
                    }
                }
            }
        }
    }
}
