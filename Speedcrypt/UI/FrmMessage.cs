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
    /// FrmMessage provides a custom modal dialog implementation
    /// designed to replace the standard MessageBox with full
    /// control over positioning and behavior within Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Deterministic centering relative to the owner form.
    /// - Manual positioning to guarantee visual consistency.
    /// - Modal interaction using ShowDialog with DialogResult handling.
    /// - Explicit Yes / No user decision flow.
    /// - Keyboard support via AcceptButton (Enter) and CancelButton (ESC).
    /// - Integration with a custom warning icon for visual clarity.
    /// - Isolation from standard MessageBox limitations.
    /// - Consistent behavior across different screen configurations.
    /// - UI independence from system-managed dialog placement.
    /// - Reliable and predictable user interaction flow.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class FrmMessage : Form
    {
        // UI Controls
        private Label lblMessage;          // Label to display the message text
        private PictureBox picIcon;        // Icon to show warning or info
        private Button btnYes;             // Yes button
        private Button btnNo;              // No button

        // Internal state
        private Form _ownerForm;           // Reference to owner form for centering
        private string _message;           // Message text to display

        /// <summary>
        /// Constructor accepting the owner form and message text.
        /// </summary>
        /// <param name="owner">Form that owns this dialog</param>
        /// <param name="message">Message text to display</param>
        public FrmMessage(Form owner, string message)
        {
            _ownerForm = owner;
            _message = message;

            InitializeComponent();
        }

        /// <summary>
        /// InitializeComponent sets up all controls, layout, and event handlers.
        /// </summary>
        private void InitializeComponent()
        {
            // Instantiate controls
            lblMessage = new Label();
            picIcon = new PictureBox();
            btnYes = new Button();
            btnNo = new Button();

            // Form properties
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application; // Application icon fallback
            Text = "Speedcrypt Self Test";
            FormBorderStyle = FormBorderStyle.FixedDialog;   // Non-resizable dialog
            StartPosition = FormStartPosition.Manual;       // Manual positioning for centering
            ClientSize = new Size(380, 120);               // Fixed size
            MaximizeBox = false;                            // Disable maximize
            MinimizeBox = false;                            // Disable minimize
            ShowInTaskbar = false;                          // Do not show in taskbar

            // Icon setup
            picIcon.Location = new Point(20, 25);
            picIcon.Size = new Size(32, 32);
            picIcon.Image = ForAllUnits.Energy32;          // Custom icon from resources
            picIcon.SizeMode = PictureBoxSizeMode.StretchImage;

            // Message label setup
            lblMessage.Location = new Point(70, 20);
            lblMessage.Size = new Size(320, 60);
            lblMessage.Text = _message;

            // Yes button setup
            btnYes.Text = "Yes";
            btnYes.Size = new Size(90, 30);
            btnYes.Location = new Point(120, 80);
            btnYes.Cursor = Cursors.Hand;
            btnYes.Click += BtnYes_Click;

            // No button setup
            btnNo.Text = "No";
            btnNo.Size = new Size(90, 30);
            btnNo.Location = new Point(220, 80);
            btnNo.Cursor = Cursors.Hand;
            btnNo.Click += BtnNo_Click;

            // Add controls to form
            Controls.Add(picIcon);
            Controls.Add(lblMessage);
            Controls.Add(btnYes);
            Controls.Add(btnNo);

            // Set default buttons for keyboard
            AcceptButton = btnYes;   // Enter triggers Yes
            CancelButton = btnNo;    // ESC triggers No

            // Load event to center form relative to owner
            Load += FrmMessage_Load;
        }

        /// <summary>
        /// Centers the dialog relative to the owner form when loaded.
        /// </summary>
        private void FrmMessage_Load(object sender, EventArgs e)
        {
            if (_ownerForm != null)
            {
                int x = _ownerForm.Location.X + (_ownerForm.Width - Width) / 2;
                int y = _ownerForm.Location.Y + (_ownerForm.Height - Height) / 2;

                Location = new Point(x, y);  // Set manual location
            }
        }

        /// <summary>
        /// Yes button click handler.
        /// Sets DialogResult to Yes and closes the dialog.
        /// </summary>
        private void BtnYes_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Yes;
            Close();
        }

        /// <summary>
        /// No button click handler.
        /// Sets DialogResult to No and closes the dialog.
        /// </summary>
        private void BtnNo_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.No;
            Close();
        }
    }
}