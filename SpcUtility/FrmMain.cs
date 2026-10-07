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

using System;
using System.IO;
using System.Linq;
using System.Drawing;
using System.Reflection;
using System.Diagnostics;
using System.Windows.Forms;

// SpcUtility
using SpcUtility.UI;
using SpcUtility.Mix;
using SpcUtility.Nuvola;
using SpcUtility.Backup;
using SpcUtility.RegKeys;
using SpcUtility.UI.SpcUtility.UI;

namespace SpcUtility
{
    public partial class FrmMain : Form
    {
        #region Fields

        private ToolTipManager _tt;

        #endregion Fields

        #region Constructor
        public FrmMain()
        {
            InitializeComponent();
            // LoadAll performs all initialization tasks, including positioning
            // this form relative to coordinates passed via command-line arguments.
            // If valid center coordinates are provided, the form's StartPosition is set to Manual
            // and the Location is calculated so that the form appears centered at the specified point.
            LoadAll();
        }

        #endregion Constructor

        #region Settings
        void LoadAll()
        {
            #region Instances

            _tt = new ToolTipManager(); // Tooltip

            #endregion Instances

            #region Form Interface

            // Main
            Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
            StartPosition = FormStartPosition.CenterScreen;
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;
            MaximizeBox = false;
            MinimizeBox = false;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            Text = "Speedcrypt Utility...";
            TopMost = true;
            
            // Form Images
            picGrad.Image = Image.FromStream(new MemoryStream(Allicon.Gradient));
            picGrad.BackgroundImageLayout = ImageLayout.Stretch;
            picSimb.Image = Image.FromStream(new MemoryStream(Nuvola_32._32_configure));
            picSimb.Parent = picGrad;
            picSimb.BackColor = Color.Transparent;

            // Form Labels
            labYel.BackColor = Color.Yellow;
            labFir.Text = Text;
            labFir.Parent = picGrad;
            labFir.BackColor = Color.Transparent;
            labFir.ForeColor = Color.White;
            labFir.Font = new Font(labFir.Font.FontFamily, 10, FontStyle.Bold);
            labSec.Text = "Icon Association for Encrypted Files, Backup and Restore";
            labSec.Parent = picGrad;
            labSec.BackColor = Color.Transparent;
            labSec.ForeColor = Color.White;
            labSec.Font = new Font(labSec.Font.FontFamily, 10);

            #endregion Form Interface

            #region Form Components

            // GroupBox
            grbKeys.Text = "Windows Registry:";
            grbKeys.ForeColor = Color.Brown;
            grbBck.Text = "Backup and Restore:";
            grbBck.ForeColor = grbKeys.ForeColor;

            // Buttons
            var allbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                (btnAdd, "&Add key", "Create the icon association for encrypted files", Image.FromStream(new MemoryStream(Nuvola_32._32_Speedcrypt)), true),
                (btnRemove, "&Remove Key", "Remove the icon association from encrypted files", Image.FromStream(new MemoryStream(Nuvola_32._32_dvi)), true),
                (btnBck, "&Backup", "Perform Backup of Sensitive Files", Image.FromStream(new MemoryStream(Nuvola_32._32_ark)), true),
                (btnRest, "R&estore", "Perform Restore of Sensitive Files", Image.FromStream(new MemoryStream(Nuvola_32._32_folder_tar)), true),               
            };
            int verticalSpacing = 5;
            foreach (var optionbut in allbutton)
            {
                optionbut.Button.Text = optionbut.Text;
                _tt.Set(optionbut.Button, optionbut.Tip);
                optionbut.Button.Cursor = Cursors.Hand;
                optionbut.Button.Image = optionbut.Icon;
                optionbut.Button.ImageAlign = ContentAlignment.MiddleCenter;
                optionbut.Button.TextAlign = ContentAlignment.BottomCenter;
                optionbut.Button.Enabled = optionbut.Enabled;
                optionbut.Button.Padding = new Padding(0, 0, 0, verticalSpacing);
            }

            // other Buttons
            var otherbutton = new (Button Button, string Text, string Tip, Image Icon)[]
            {
                (btnOk, "&Ok", "Close Speedcrypt Utility", Image.FromStream(new MemoryStream(Nuvola_16._16_apply))),
                (btnHelp, "&Help", "Help Speedcrypt Utility", Image.FromStream(new MemoryStream(Nuvola_16._16_help))),
            };
            foreach (var othernbut in otherbutton)
            {
                othernbut.Button.Text = othernbut.Text;
                _tt.Set(othernbut.Button, othernbut.Tip);
                othernbut.Button.Cursor = Cursors.Hand;
                othernbut.Button.Image = othernbut.Icon;
            }

            // CechkcBoxs
            var allChkBox = new (CheckBox Chk, string Text, string Tip, bool Checked, bool Enabled)[]
            {
                (chkOpenFolder, "Open the folder after restore", "Open the folder where the sensitive files are stored", false, true),
            };
            foreach (var boxOption in allChkBox)
            {
                boxOption.Chk.Enabled = boxOption.Enabled;
                boxOption.Chk.Checked = boxOption.Checked;
                boxOption.Chk.Text = boxOption.Text;
                _tt.Set(boxOption.Chk, boxOption.Tip);
                boxOption.Chk.Cursor = Cursors.Hand;
            }           

            // Images
            picShort.Image = Image.FromStream(new MemoryStream(Nuvola_22._22_khotkeys));
            picNoteKey.Image = Image.FromStream(new MemoryStream(Nuvola_22._22_knotes));
            pictOpen.Image = Image.FromStream(new MemoryStream(Nuvola_22._22_folder_green_open));
            picNoteBck.Image = picNoteKey.Image;

            // Labels
            labIcon.Text = "●  Speedcrypt does not make any changes to your system.\r\n\r\n " +
                           "●  Speedcrypt can associate its icon with encrypted files. \r\n\r\n" +
                           "●  Speedcrypt requires your authorization for this association. \r\n\r\n" +
                           "●  Speedcrypt does not interfere with your system in any way\r\n\r\n" +
                           "●  Speedcrypt does nothing without your explicit authorization";

            labBck.Text = "●  Speedcrypt allows you to back up its sensitive files,\r\n including the DLL libraries dedicated to encryption. \r\n\r\n" +
                          "●  It is absolutely necessary to make a copy of these \r\ndata so they can be restored in case the project is \r\nattacked and its files are tampered with. \r\n\r\n" +
                          "●  This utility is a survival tool that will be extremely \r\nuseful for bringing the project back to its original\r\n state and full operational capacity.\r\n";
            
            labNoteKey.Text = "Notes:";
            labNoteKey.Font = new Font(labFir.Font.FontFamily, 10, FontStyle.Regular);
            labNoteKey.ForeColor = Color.Red;
            labNoteBck.Text = labNoteKey.Text;
            labNoteBck.Font = labNoteKey.Font;
            labNoteBck.ForeColor = labNoteKey.ForeColor;
            labShort.Text = "Shortcut keys:";
            labShort.ForeColor = Color.Red;
            labCut.Text = "ALT + A   ALT + R   ALT + B   ALT + E   ALT + O   ALT + H";
            labCut.ForeColor = Color.RoyalBlue;

            #endregion Form Components

            #region Event handlers

            btnAdd.Click += BtnAdd_Click;
            btnRemove.Click += BtnRemove_Click;
            btnBck.Click += BtnBck_Click;
            btnRest.Click += BtnRest_Click;
            btnOk.Click += BtnOk_Click;
            btnHelp.Click += BtnHelp_Click;

            #endregion Event handlers

            #region Initialization

            keyExists();

            ValidateUiTexts();

            // High-density Enterprise documentation applied directly above the target block.
            // 
            // TECHNICAL SPECIFICATION: Manual Windows Form Positioning via CLI Arguments
            // 1. INPUT VALIDATION: Extracts CLI arguments and verifies a minimum count of 3 to guarantee coordinate availability.
            // 2. DATA PARSING: Executes safe integer parsing (int.TryParse) on indices [1] and [2] to prevent runtime exceptions.
            // 3. STATE INITIALIZATION: Forces FormStartPosition to Manual, overriding default OS layout management.
            // 4. COORDINATE CALCULATION: Computes top-left boundaries by offsetting dynamic Form dimensions (Width/Height) 
            //    from the provided absolute center coordinates, achieving precise reference alignment.

            string[] args = Environment.GetCommandLineArgs();

            if (args.Length >= 3)
            {
                int centerX;
                int centerY;

                if (int.TryParse(args[1], out centerX) &&
                    int.TryParse(args[2], out centerY))
                {
                    this.StartPosition = FormStartPosition.Manual;

                    this.Location = new Point(
                        centerX - (this.Width / 2),
                        centerY - (this.Height / 2)
                    );
                }
            }

            // Block space key interference
            // Attaches an input interception listener to suppress keyboard spacing actions inside specific controls
            SpaceKeyBlocker.Enable (this);
            
            #endregion Initialization
        }

        #endregion Settings

        #region Event handlers
        
        // Windows Registry
        private void BtnAdd_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("You asked Speedcrypt to associate its icon with encrypted files.May I proceed with this operation?", ForAllUnits.Warning,
                                  MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (result == DialogResult.No) return;

            AddKey.RegisterSpcExtension();

            keyExists();
        }
        private void BtnRemove_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("You asked Speedcrypt to remove the icon association from encrypted files.May I proceed with this operation?", ForAllUnits.Warning,
                                  MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (result == DialogResult.No) return;

            RemoveKey.UnregisterSpcExtension();

            keyExists();
        }

        // Backup and Restore
        private void BtnBck_Click(object sender, EventArgs e)
        {
            string basePath = AppDomain.CurrentDomain.BaseDirectory;

            SpcBackup.BackupAutomatic(basePath);
            MessageBox.Show("Backup completed successfully!", ForAllUnits.Info, MessageBoxButtons.OK, MessageBoxIcon.Information);

            keyExists();
        }       
        private void BtnRest_Click(object sender, EventArgs e)
        {
            string basePath = AppDomain.CurrentDomain.BaseDirectory;

            // Check if Speedcrypt is running to alert the user before the ecosystem shutdown
            bool speedcryptRunning = Process.GetProcessesByName("Speedcrypt").Any(p => p.Id != Process.GetCurrentProcess().Id);

            if (speedcryptRunning)
            {
                // Ask user for confirmation before closing Speedcrypt
                DialogResult result = MessageBox.Show("You requested to restore the data. Speedcrypt will be closed to complete the operation and will be reopened afterwards. Do you want to continue?",
                                                       ForAllUnits.Warning, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

                if (result != DialogResult.Yes)
                    return; // User cancelled, exit the handler
            }

            try
            {
                // Execute the redesigned robust restore pipeline
                SpcRestore.RestoreAutomatic(basePath);

                // The synchronous message box holds the execution until the user interacts with it
                MessageBox.Show("Restore completed successfully.", ForAllUnits.Info, MessageBoxButtons.OK, MessageBoxIcon.Information);

                if (chkOpenFolder.Checked)
                {
                    Process.Start(basePath);
                }

                // Safely terminates the auxiliary application after the user acknowledges the success message
                Application.Exit();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error during restore: " + ex.Message, ForAllUnits.Error, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // Close
        private void BtnOk_Click(object sender, EventArgs e)
        {
            Close();
        }

        // Help
        private void BtnHelp_Click(object sender, EventArgs e)
        {
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.Utility);
        }

        #endregion Event handlers

        #region Procedures
        void keyExists()
        {
            bool isRegistered = CheckKey.IsSpcExtensionRegistered();
            TestResult(isRegistered);
        }
        void TestResult(bool result)
        {
            labReport.Text = result
                ? "SPCR association is Present"
                : "SPCR association is NOT Present";

            // Enable Add button ONLY if key does NOT exist
            btnAdd.Enabled = !result;
            btnRemove.Enabled = result;

            // Check Backup folder existence
            string basePath = AppDomain.CurrentDomain.BaseDirectory;
            string backupPath = Path.Combine(basePath, "Backup");

            btnRest.Enabled = Directory.Exists(backupPath);
            
            if (picRep.Image != null)
            {
                picRep.Image.Dispose();
                picRep.Image = null;
            }

            picRep.Image = result
                ? Image.FromStream(new MemoryStream(Nuvola_16._16_ledgreen))
                : Image.FromStream(new MemoryStream(Nuvola_16._16_ledred));
        }
        void ValidateUiTexts()
        {
            // Backup / Restore buttons
            btnBck.Text = "&Backup";
            btnRest.Text = "R&estore";

            // Checkbox
            chkOpenFolder.Text = "Open the folder after restore";

            // Status label (Base text, then dynamically changes)
            if (btnAdd.Enabled)
                labReport.Text = "SPCR association is NOT Present";
            else
                labReport.Text = "SPCR association is Present";
        }

        #endregion Procedures
    }
}