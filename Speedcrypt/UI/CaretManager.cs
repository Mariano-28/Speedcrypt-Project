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
    /// CaretManager: Provides centralized management of the caret position
    /// for editable TextBoxBase and ComboBox controls. Ensures that after any text change,
    /// the caret is always positioned at the end of the text with no active selection.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Consistent caret behavior across all attached TextBoxBase and ComboBox controls.
    /// - Automatic repositioning of the caret to the end of the text.
    /// - Removal of any text selection after user input or item selection.
    /// - Use of BeginInvoke to execute after the internal control update cycle,
    ///   preventing the default WinForms behavior from overriding the caret position.
    /// - Clean separation between UI behavior and application logic.
    /// - Reusable, centralized logic to avoid code duplication across the project.
    /// - The behavior can be attached or detached dynamically to any supported control.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class CaretManager
    {
        #region TextBoxBase

        /// <summary>
        /// Attaches automatic caret management to a TextBoxBase control.
        /// </summary>
        public static void Attach(TextBoxBase textBox)
        {
            if (textBox == null)
                return;

            textBox.TextChanged -= TextBox_TextChanged;
            textBox.TextChanged += TextBox_TextChanged;
        }

        /// <summary>
        /// Detaches automatic caret management from a TextBoxBase control.
        /// </summary>
        public static void Detach(TextBoxBase textBox)
        {
            if (textBox == null)
                return;

            textBox.TextChanged -= TextBox_TextChanged;
        }

        /// <summary>
        /// Moves the caret to the end of the text safely after text changes.
        /// </summary>
        private static void TextBox_TextChanged(object sender, EventArgs e)
        {
            TextBoxBase textBox = sender as TextBoxBase;
            if (textBox == null)
                return;

            textBox.BeginInvoke(new Action(() =>
            {
                textBox.SelectionStart = textBox.Text.Length;
                textBox.SelectionLength = 0;
            }));
        }

        /// <summary>
        /// Sets text, optionally focuses the control and safely moves the caret to the end.
        /// </summary>
        public static void SetText(TextBoxBase textBox, string text, bool focus)
        {
            if (textBox == null)
                return;

            textBox.Text = text ?? string.Empty;

            textBox.BeginInvoke(new Action(() =>
            {
                if (focus)
                    textBox.Focus();

                textBox.SelectionStart = textBox.Text.Length;
                textBox.SelectionLength = 0;
            }));
        }

        #endregion

        #region ComboBox

        /// <summary>
        /// Attaches automatic caret management to a ComboBox control.
        /// </summary>
        public static void Attach(ComboBox combo)
        {
            if (combo == null)
                return;

            combo.TextChanged -= Combo_TextChanged;
            combo.TextChanged += Combo_TextChanged;
        }

        /// <summary>
        /// Detaches automatic caret management from a ComboBox control.
        /// </summary>
        public static void Detach(ComboBox combo)
        {
            if (combo == null)
                return;

            combo.TextChanged -= Combo_TextChanged;
        }

        /// <summary>
        /// Moves the caret to the end of the text safely after text changes.
        /// </summary>
        private static void Combo_TextChanged(object sender, EventArgs e)
        {
            ComboBox combo = sender as ComboBox;
            if (combo == null)
                return;

            combo.BeginInvoke(new Action(() =>
            {
                combo.SelectionStart = combo.Text.Length;
                combo.SelectionLength = 0;
            }));
        }

        /// <summary>
        /// Sets text, optionally focuses the ComboBox and safely moves the caret to the end.
        /// </summary>
        public static void SetText(ComboBox combo, string text, bool focus)
        {
            if (combo == null)
                return;

            combo.Text = text ?? string.Empty;

            combo.BeginInvoke(new Action(() =>
            {
                if (focus)
                    combo.Focus();

                combo.SelectionStart = combo.Text.Length;
                combo.SelectionLength = 0;
            }));
        }
        //=============================== usage ======================================

        // TextBox
        //CaretManager.Attach(txtPassword);
        //CaretManager.Detach(txtPassword);
        //CaretManager.SetText(txtPassword, "Hello", true);

        // ComboBox
        //CaretManager.Attach(cmbAlgorithms);
        //CaretManager.Detach(cmbAlgorithms);
        //CaretManager.SetText(cmbAlgorithms, "AES-256", true);

        // RichTextBox
        //CaretManager.Attach(rtxtLog);
        //CaretManager.Detach(rtxtLog);
        //CaretManager.SetText(rtxtLog, "Operation completed successfully.", false);

        #endregion
    }
}