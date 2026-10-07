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
using System.IO;
using System.Drawing;
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.Distribution;

namespace Speedcrypt
{
    public partial class FrmAbout : Form
    {
        #region Fields

        // Reference to the main user interface window container
        private FrmMain mainForm;

        #endregion Fields

        #region Constructor
        public FrmAbout(Form callingForm)
        {
            InitializeComponent(); // Initialize designer components
            mainForm = callingForm as FrmMain; // Cast and store reference to the main application form
            Loadall(); // Configure runtime interface
        }

        #endregion Constructor

        #region Form Routines

        // Initializes the user interface and runtime elements
        void Loadall()
        {
            #region Instances

            SpeedcryptGhost.Disable(this); // Obfuscate print Screen

            #endregion Instances

            #region Form Interface

            // Assign application icon extracted from the executable
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;

            // Configure dialog behavior
            MaximizeBox = false;
            MinimizeBox = false;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            Text = "About Speedcrypt...";

            // Main Speedcrypt logo
            picSpcr.Image = ForAllUnits.Speedcrypt48;

            // OSI Certified logo
            picOsi.Image = ForAllUnits.Osicertified;
            picOsi.SizeMode = PictureBoxSizeMode.Zoom;
            picOsi.BorderStyle = BorderStyle.None;

            // System information group
            grbSys.ForeColor = Color.Brown;

            // System information button icon
            btnSys.Image = ForAllUnits.System64;
            btnSys.Cursor = Cursors.Hand;

            // Retrieve executable version automatically
            string version = Application.ProductVersion;

            // Version information
            labVer.Text = "Speedcrypt\r\n" +
                          "Version " + version + "\r\n" +
                          "© 2024–" + DateTime.Now.Year.ToString() + " Mariano Ortu\r\n";

            labVer.Font = new Font(labVer.Font.FontFamily.Name, 10, FontStyle.Regular);
            labVer.ForeColor = Color.RoyalBlue;

            // About text
            labCop.Text = "Speedcrypt is a free and open-source cryptographic suite\r\n" +
                          "designed to provide secure encryption tools with transparency\r\n" +
                          "and reliability.\r\n\r\n" +
                          "The project focuses on security, code clarity and verifiable algorithms.\r\n\r\n" +
                          "Licensed under the GNU General Public License v3.0\r\n\r\n" +
                          "The full license text is available in the LICENSE file\r\n" +
                          "distributed with this software.\r\n\r\n" +
                          "Speedcrypt Official website:\r\n\r\n";

            // Web icon
            picWeb.Image = ForAllUnits.Wbftp22;

            // Speedcrypt website
            labkSpc.Text = "https://www.speedcrypt.info/";

            // Author website
            labMar.Text = "Mariano Ortu Official website:";
            labkSic.Text = "https://www.sicurpas.it/";

            // Trademark disclaimer
            labBrand.Text = "Brand, product and algorithm names may be trademarks\r\n" +
                            "or registered trademarks of their respective owners.\r\n";
            labBrand.ForeColor = Color.Red;

            // OK button icon
            btnOk.Image = ForAllUnits.Apply22;
            btnOk.Cursor = Cursors.Hand;

            picPortable.Image = ForAllUnits.Pendrive64;
            labPortable.Text = "Portable Edition";
            labPortable.ForeColor = Color.Red;

            // Speedcrypt Distribution
            labPortable.Visible = SpeedcryptDistribution.ShowAboutLabel;
            picPortable.Visible = SpeedcryptDistribution.ShowAboutIcon;

            #endregion

            #region Events Handler

            btnSys.Click += BtnSys_Click;

            labkSpc.LinkClicked += LabkSpc_LinkClicked;
            labkSic.LinkClicked += LabkSic_LinkClicked;

            labkLic.Text = "License";
            labkLic.LinkClicked += LabkLic_LinkClicked;

            labkAck.Text = "Acknowledgements";
            labkAck.LinkClicked += LabkAck_LinkClicked;

            // Block space key interference
            // Attaches an input interception listener to suppress keyboard spacing actions inside specific controls
            SpaceKeyBlocker.Enable(this);

            if (mainForm.Obfs == true) // Enable / Disable Obfuscate print Screen
                SpeedcryptGhost.Enable(this); // Enforces secure environment policy to obstruct external screen capture and display sniffing tools
            
            #endregion
        }
        #endregion Form Routines

        #region Events Handler

        // Opens acknowledgements topic from help file
        private void LabkAck_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            string helpFile = Path.Combine(ForAllUnits.DirPath, ForAllUnits.HelpFile);

            if (File.Exists(helpFile))
                Help.ShowHelp(this, helpFile, HelpNavigator.Topic, ForAllUnits.AckTopic);
        }

        // Opens license topic from help file
        private void LabkLic_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            string helpFile = Path.Combine(ForAllUnits.DirPath, ForAllUnits.HelpFile);

            if (File.Exists(helpFile))
                Help.ShowHelp(this, helpFile, HelpNavigator.Topic, ForAllUnits.LicenzeTopic);
        }
        
        // Opens Sicurpas website
        private void LabkSic_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
           SystemUtility.OpenUrl(labkSic.Text);
        }
        
        // Opens Speedcrypt website
        private void LabkSpc_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
          SystemUtility.OpenUrl(labkSpc.Text);
        }

        // Launch Microsoft System Information
        private void BtnSys_Click(object sender, EventArgs e)
        {
            if (SystemUtility.TryGetMsinfo32Path(out string strSysInfo))
                SystemUtility.StartProcess(strSysInfo);
        }
        #endregion Events Handler
    }
}