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
using System.Linq;
using System.Text;
using System.Data;
using System.Drawing;
using System.Windows.Forms;
using System.Collections.Generic;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.SALT;
using Speedcrypt.EstimMST;
using Speedcrypt.XMLConfig;
using Speedcrypt.SecureText;
using Speedcrypt.Passwordgen;
using Speedcrypt.Exceptionlog;
using Speedcrypt.HASHLibraries;
using Speedcrypt.Digests.Bcrypt;

using Newtonsoft.Json;

namespace Speedcrypt
{
    public partial class FrmPasswgen : Form
    {
        #region Cryptographic Fields

        // Reference to the main form of the application, used to interact with UI elements and pass data
        private FrmMain mainForm;

        // Constructor commented out; could be used to initialize FrmPasswgen with default parameters
        //public FrmPasswgen() : this(null) { }

        private PasswordProfile _originalProfile;        

        // Remember selected pattern index for each category
        private int _standardPatternIndex = -1;
        private int _advancedPatternIndex = -1;
        private int _corporatePatternIndex = -1;

        // Manages tooltips in the UI, likely for displaying hints or help messages
        private ToolTipManager _tt;

        // Flag indicating if the placeholder text is currently active in input fields
        private bool isPlaceholderActive = true;

        // Default placeholder text displayed in input fields when empty
        private string placeholderText = "Profile Name";

        // Internal counters or state variables
        private int _SCR = 0,           // Likely "Security Counter" or internal scoring metric
                    _PTR_TEST = 0;     // Counter for Pattern Tests

        // Flag to track if a file error message has already been shown to the user
        private bool fileErrorShown = false;

        // Handles reading/writing to a private XML configuration file for storing persistent settings
        private PrivateXmlConfig _xmlConfig;

        // Stores the original pattern record, possibly to allow rollback or comparison with edits
        private string _originalPatternRecord = string.Empty;

        #endregion Cryptographic Fields

        #region Constructor
        public FrmPasswgen(Form callingForm)
        {
            InitializeComponent(); // Initialize UI components
            mainForm = callingForm as FrmMain;
            Loadall();             // Load application data and initialize runtime state
        }

        #endregion Constructor

        #region Form Routines
        void Loadall()
        {
            #region Form Components

            // Initializes the custom ToolTip manager used to provide contextual UI hints
            _tt = new ToolTipManager();// Tooltip

            // Initializes a shared OpenFileDialog instance accessible through ForAllUnits
            ForAllUnits.openFileDialog1 = new OpenFileDialog();

            // Sets the form icon using the executable associated icon; falls back to default system icon if null
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;

            // Disables the maximize button to enforce fixed window dimensions
            MaximizeBox = false;

            // Disables the minimize button to prevent form minimization
            MinimizeBox = false;

            // Sets the form border style to a fixed dialog (non-resizable)
            FormBorderStyle = FormBorderStyle.FixedDialog;

            // Centers the form on screen when launched
            StartPosition = FormStartPosition.CenterScreen;

            // Sets the window title text
            Text = "Speedcrypt Password Generator...";

            // Images

            // Loads the gradient background image from embedded resources using a memory stream
            picGrad.Image = ForAllUnits.Gradientform;

            // Ensures the background image stretches to fit the PictureBox dimensions
            picGrad.BackgroundImageLayout = ImageLayout.Stretch;

            // Assigns the 32x32 password generator image to picSimb
            picSimb.Image = ForAllUnits.Generatepassw32;

            // Sets picSimb as a child control of picGrad to enable overlay rendering
            picSimb.Parent = picGrad;

            // Enables transparent background so picSimb blends with the gradient
            picSimb.BackColor = Color.Transparent;

            // Labels

            // Sets a yellow background color for labYel (likely used as a visual indicator or separator)
            labYel.BackColor = Color.Yellow;

            // Sets primary title text for the generator section
            labFir.Text = "Password Generator...";

            // Makes labFir a child of picGrad to render above the gradient background
            labFir.Parent = picGrad;

            // Enables transparent background for labFir to preserve gradient visibility
            labFir.BackColor = Color.Transparent;

            // Sets foreground text color to white for contrast against the gradient
            labFir.ForeColor = Color.White;

            // Applies bold font style with fixed size for visual emphasis
            labFir.Font = new Font(labFir.Font.FontFamily, 10, FontStyle.Bold);

            // Sets secondary descriptive text explaining generator purpose
            labSec.Text = "Create strong Passwords with the Speedcrypt Generator";

            // Makes labSec a child of picGrad for layered rendering
            labSec.Parent = picGrad;

            // Enables transparent background for consistent visual integration
            labSec.BackColor = Color.Transparent;

            // Sets foreground text color to white
            labSec.ForeColor = Color.White;

            // Applies regular font style with defined size
            labSec.Font = new Font(labSec.Font.FontFamily, 10);

            // ImageList

            // Adds a 22x22 compiled file icon image to imageList1 collection
            imageList1.Images.Add(ForAllUnits.Compfile22);

            #endregion Form Components

            #region Candidate Master Key

            // Sets the maximum password length allowed for the secure password input field
            secPasw.MaxLength = 32; // Maximum password length

            // Sets the label text for the candidate master key section
            labCand.Text = "Candidate Master Key:";
            labCand.ForeColor = Color.Brown;

            // Displays password statistics: number of characters, entropy in bits, and calculated strength score
            labScor.Text = "Chars 0 / 0 Bits / Score 0";
            labScor.ForeColor = Color.RoyalBlue;

            // Sets the title for the pseudo-random number generator selection group
            grbEngine.Text = "Select the Pseudo-Random Number Generator:";
            grbEngine.ForeColor = Color.Brown;

            // Random number generators available for password generation
            cmbNmb.Items.AddRange(new object[]
            {
                "BCRYPT", "FORTUNA", "AES-CTR DRBG",
                "CRYPTO-RANDOM", "BLUM-BLUM-SHUB (BBS)"
            });

            // Prevents manual text input; user must select from predefined PRNG options
            cmbNmb.DropDownStyle = ComboBoxStyle.DropDownList;

            // Sets the default selected pseudo-random number generator
            cmbNmb.SelectedIndex = 0;

            // Sets the label describing the generated password length selector
            labPswlh.Text = "Length of Generated Password:";
            labPswlh.ForeColor = Color.Brown;

            // Sets the label for profile selection
            labProfile.Text = "Profile:";
            labProfile.ForeColor = Color.Brown;
            labProfnum.Text = "0";
            labProfnum.ForeColor = Color.Red;
                 
            #endregion Candidate Master Key

            #region Miscellaneous

            // Configuration of secondary action buttons (text buttons with icons and tooltips)
            var otherbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                (btnGen, "&Generate", "Generate master key", ForAllUnits.Generatepassw32, true),
                (btnTest, "Start &Test", "Check whether the pattern is valid", ForAllUnits.Connect32, false),
                (btnClear, "Clea&r", "Clear all values", ForAllUnits.Empty32, false),
                (btnSave, "Sa&ve", "Save pattern", ForAllUnits.Filesaveas32, false),
                (btnDelete, "&Delete", "Delete selected pattern", ForAllUnits.Cancelitem32, false),
                (btnModif, "&Modify", "Save changes to the pattern", ForAllUnits.Filesave32, false),
                (btnRestore, "Rest&ore...", "Restore selected pattern files", ForAllUnits.Restore32, true),
            };

            // Vertical spacing used for icon/text alignment padding
            int verticalSpacing = 5;

            foreach (var othernbut in otherbutton)
            {
                othernbut.Button.Text = othernbut.Text;
                _tt.Set(othernbut.Button, othernbut.Tip); // Assign tooltip
                othernbut.Button.Cursor = Cursors.Hand; // Hand cursor for better UX
                othernbut.Button.Image = othernbut.Icon;
                othernbut.Button.ImageAlign = ContentAlignment.MiddleCenter;
                othernbut.Button.TextAlign = ContentAlignment.BottomCenter;
                othernbut.Button.Enabled = othernbut.Enabled;
                othernbut.Button.Padding = new Padding(0, 0, 0, verticalSpacing);
            }

            // Configuration of icon-based buttons (minimal text, tooltip-driven UX)
            var allbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                (btnPsw, "", "View / hide master key", ForAllUnits.Passwordview22, false),
                (btnSaveProfile, "", "Save settings profile", ForAllUnits.Filesave22, false),
                (btnDeleteProfile, "", "Delete selected profile", ForAllUnits.Cancelitem22, false),
                (btnClearCombo, "", "Clear combo box text", ForAllUnits.Empty22, false),
                (btnAcpt, "&Accept Candidate", "Accept the generated candidate password", ForAllUnits.Apply16, false),
                (btnCanc, "&Cancel", "Close Speedcrypt generator", ForAllUnits.No16, true),
                (btnHelp, "&Help", "View help guide", ForAllUnits.Help16, true),
            };

            foreach (var optionbut in allbutton)
            {
                optionbut.Button.Text = optionbut.Text;
                _tt.Set(optionbut.Button, optionbut.Tip);
                optionbut.Button.Cursor = Cursors.Hand;
                optionbut.Button.Image = optionbut.Icon;
                optionbut.Button.Enabled = optionbut.Enabled;
            }

            // Configuration of all ComboBox controls
            var allcombo = new (ComboBox Box, string Tip, bool Enabled)[]
            {
                (cmbNmb, "Select your preferred random number generator", true),
                (cmbProfile, "Enter the profile name for password generation", true),
                (cmbPatterns, "Select the pattern to generate a password", true),
            };

            foreach (var option in allcombo)
            {
                _tt.Set(option.Box, option.Tip);
                option.Box.Enabled = option.Enabled;
                option.Box.Cursor = Cursors.Hand;
            }

            // Configuration of all CheckBox controls (character set and behavior options)
            var allChkBox = new (CheckBox Chk, string Text, string Tip, bool Checked, bool Enabled)[]
            {
                (chkUppercase, "Include uppercase letters (A–Z)", "", true, true),
                (chkLowercase, "Include lowercase letters (a–z)", "", false, true),
                (chkDigits, "Include digits (0–9)", "", false, true),
                (chkSymbols, "Include symbols (!@#$…)", "", false, true),
                (chkCustomChars, "Include custom characters", "", false, true),
                (chkForceEachCategory, "Force at least one character from each selected category", "", false, true),
                (chkMinus, "Include minus (-)", "", false, true),
                (chkUnderline, "Include underscore (_)", "", false, true),
                (chkSpace, "Include space ( )", "", false, true),
                (chkBrackets, "Include brackets ( ( ) [ ] { } < > )", "", false, true),
                (chkLatin, "Include Latin-1 Supplement (U+00A0–U+00FF)", "", false, true),
                (chkPermute, "Randomly permute password characters", "", false, true),
                (chkAdvancedPattern, "Enable advanced pattern syntax ([ABC], [a-z], {min,max})", "", false, true),
                (chkNoConsecutive, "Prevent consecutive duplicate characters", "", false, true),
                (chkUserEntropyDialog, "Enable dialog to collect additional user entropy", "", false, true),
                (chkBackup, "Backup files after every save", "", false, true),
                (chkBckStandard, "Standard patterns", "Restore standard patterns", true, true),
                (chkBckAdvanced, "Advanced patterns", "Restore advanced patterns", false, true),
                (chkBckCorporate, "Corporate patterns", "Restore corporate patterns", false, true),
            };

            foreach (var boxOption in allChkBox)
            {
                boxOption.Chk.Enabled = boxOption.Enabled;
                boxOption.Chk.Checked = boxOption.Checked;
                boxOption.Chk.Text = boxOption.Text;
                _tt.Set(boxOption.Chk, boxOption.Tip);
                boxOption.Chk.Cursor = Cursors.Hand;
            }

            // Configuration of all RadioButton controls (generation modes and file sources)
            var allradiobut = new (RadioButton Button, string Text, string Tip, bool Checked)[]
            {
                (rdbCharSet, "Generate using character set", "Generate passwords using basic settings", true),
                (rdbPattern, "Generate using patterns", "Generate passwords using pattern strings", false),
                (rbStandardPatterns, "Standard patterns", "Generate a password using standard patterns", true),
                (rbAdvancedPatterns, "Advanced patterns", "Generate a password using advanced patterns", false),
                (rbCorporatePatterns, "Corporate patterns", "Generate a password using corporate patterns", false),
                (rbFileStandardPatterns, "Standard patterns", "Load standard pattern file", true),
                (rbFileAdvancedPatterns, "Advanced patterns", "Load advanced pattern file", false),
                (rbFileCorporatePatterns, "Corporate patterns", "Load corporate pattern file", false),
                (rbUserFile, "User files", "Restore user-created files", false),
                (rbOriginalFile, "Original files", "Restore original files", true),
            };

            foreach (var radoption in allradiobut)
            {
                radoption.Button.Checked = radoption.Checked;
                radoption.Button.Text = radoption.Text;
                _tt.Set(radoption.Button, radoption.Tip);
                radoption.Button.Cursor = Cursors.Hand;
            }

            #endregion Miscellaneous

            #region Settings

            // Sets the title of the main password settings tab page
            tabPage1.Text = "Password Settings...";

            // Character Set

            // Sets the title of the character set group box
            grbCharacter.Text = "Character Set";
            grbCharacter.ForeColor = Color.Brown;

            // Assigns the keyboard icon to visually represent character input configuration
            picChrset.Image = ForAllUnits.keyboard48;

            // Character or Pattern section

            // Indicates that character set mode is active (green LED icon)
            picChr.Image = ForAllUnits.Ledgreen16;

            // Indicates that pattern mode is inactive (red LED icon)
            picPat.Image = ForAllUnits.Ledred16;

            // Sets the title of the advanced options group
            grbAdvance.Text = "Advanced Options:";
            grbAdvance.ForeColor = Color.Brown;

            // Patterns

            // Label prompting the user to select a pattern type
            labSelect.Text = "Select the pattern type:";
            labSelect.ForeColor = Color.Brown;

            // Sets the title of the pattern set group box
            grbPattern.Text = "Pattern Set:";
            grbPattern.ForeColor = Color.Brown;

            // Prevents manual text entry; selection must come from predefined pattern list
            cmbPatterns.DropDownStyle = ComboBoxStyle.DropDownList;

            // Makes the preview text box read-only to prevent user modification
            txtPreview.ReadOnly = true;
            txtPreview.TabStop = false;

            // Makes the test result text box read-only to preserve output integrity
            txtTestResult.ReadOnly = true;
            txtTestResult.TabStop = false;

            // Displays the total number of loaded patterns
            labPatCount.Text = "0";
            labPatCount.ForeColor = Color.Red;

            // Displays the number of characters in the selected pattern
            labPatternChr.Text = "0";
            labPatternChr.ForeColor = Color.Red;

            // Label describing the pattern value and its character count
            labPat.Text = "Pattern Value [Character Count]:";
            labPat.ForeColor = Color.Brown;

            // Assigns the advanced features icon
            pictAdvanced.Image = ForAllUnits.Atlantik48;

            // Describes advanced capabilities of the password generator
            labOpt.Text = "●  Support for multiple secure generation algorithms\r\n\r\n" +
                          "●  Ability to update and customize Pattern-related files\r\n\r\n" +
                          "●  Final permutation to reduce any bias in the password\r\n\r\n" +
                          "●  Automatic check to prevent consecutive identical characters\r\n\r\n" +
                          "●  Optional inclusion of user-provided entropy for enhanced security\r\n\r\n" +
                          "●  Advanced management of corporate rules and minimum requirements\r\n\r\n" +
                          "●  Option to customize and enhance entropy collection from the system in use\r\n";

            // Section describing available keyboard shortcuts
            picShort.Image = ForAllUnits.Keyboard22;
            labSho.Text = "Generator Keyboard Shortcuts:";
            labSho.ForeColor = Color.Brown;
            labShochr.Text = "[ A  -  C  -  D  -  G  -  H  -  M  -  O  -  R  -  T  -  V ]";
            labShochr.ForeColor = Color.Blue;

            // Pattern Files
            listPatterns.TabStop = false;

            // Sets the title of the pattern files management tab page
            tabPage2.Text = "Pattern Files...";

            // Label prompting selection of a pattern list
            labSel.Text = "Select a list of patterns:";
            labSel.ForeColor = Color.Brown;

            // Displays the number of patterns in the selected list
            labCount.Text = "0";
            labCount.ForeColor = Color.Red;

            // Sets the title for the new pattern creation group
            grbNewPattern.Text = "Enter a new pattern...";
            grbNewPattern.ForeColor = Color.Brown;

            // Labels describing required pattern definition fields
            labPatternName.Text = "[●] Pattern Name:";
            labPatternRule.Text = "[●] Pattern Rule:";
            labPatternFlag.Text = "[●] Flag:";
            labField.Text = "[●] Required Field";

            // Displays the character count of the pattern rule
            labPatternRuleChr.Text = "0";
            labPatternRuleChr.ForeColor = Color.Red;

            // Displays the number of test iterations performed
            labTestCount.Text = "0";
            labTestCount.ForeColor = Color.Red;

            // Label describing the test result output
            labResult.Text = "Test Result:";

            // Describes pattern management features
            labNewpat.Text = "●  Pattern Testing\r\n\r\n" +
                             "●  Create New Patterns\r\n\r\n" +
                             "●  Customize Your Patterns\r\n\r\n" +
                             "●  Pattern Backup and Restore\r\n";

            // Backup and Restore

            // Sets the title of the backup group for pattern files
            grbBackup.Text = "Backup Pattern File:";
            grbBackup.ForeColor = Color.Brown;

            // Label describing restore functionality for pattern files
            labRestore.Text = "Restore pattern files";

            // Tooltip explaining double-click behavior for inserting a pattern into the test field
            _tt.Set(listPatterns, "Double-click to insert a pattern into the test field.");

            #endregion Settings

            #region Events Handler

            // Candidate Master Key
            btnGen.Click += BtnGen_Click;
            btnPsw.Click += BtnPsw_Click;
            secPasw.MouseClick += SecPasw_MouseClick;
            secPasw.KeyUp += SecPasw_KeyUp;
            secPasw.KeyDown += SecPasw_KeyDown;
            cmbProfile.TextChanged += CmbProfile_TextChanged;
            cmbProfile.SelectedIndexChanged += CmbProfile_SelectedIndexChanged;
            cmbProfile.Enter += CmbProfile_Enter;
            cmbProfile.Leave += CmbProfile_Leave;
            cmbProfile.KeyPress += CmbProfile_KeyPress;
            cmbProfile.DropDown += CmbProfile_DropDown;
            cmbProfile.DrawItem += CmbProfile_DrawItem;
            cmbProfile.MouseClick += CmbProfile_MouseClick;
            cmbProfile.KeyDown += CmbProfile_KeyDown;
            cmbProfile.DropDownClosed += CmbProfile_DropDownClosed; 
            cmbProfile.DrawMode = DrawMode.OwnerDrawFixed;
            
            // Selection of pseudo-random number generators
            cmbNmb.SelectedIndexChanged += CmbNmb_SelectedIndexChanged;

            // Profile
            btnSaveProfile.Click += BtnSaveProfile_Click;
            btnClearCombo.Click += BtnClearCombo_Click;
            btnDeleteProfile.Click += BtnDeleteProfile_Click;

            // Characters Set / Patterns
            tabControl1.SelectedIndexChanged += TabControl1_SelectedIndexChanged;

            // Characters Set
            rdbCharSet.CheckedChanged += RbCharSet_CheckedChanged;
            chkUppercase.CheckedChanged += ChkUppercase_CheckedChanged;
            chkLowercase.CheckedChanged += ChkUppercase_CheckedChanged;
            chkDigits.CheckedChanged += ChkUppercase_CheckedChanged;
            chkSymbols.CheckedChanged += ChkUppercase_CheckedChanged;
            chkForceEachCategory.CheckedChanged += ChkUppercase_CheckedChanged;
            chkMinus.CheckedChanged += ChkUppercase_CheckedChanged;
            chkUnderline.CheckedChanged += ChkUppercase_CheckedChanged;
            chkSpace.CheckedChanged += ChkUppercase_CheckedChanged;
            chkBrackets.CheckedChanged += ChkUppercase_CheckedChanged;
            chkLatin.CheckedChanged += ChkUppercase_CheckedChanged;
            chkCustomChars.CheckedChanged += ChkUppercase_CheckedChanged;
            secPasw.TextChanged += (s, e) => TruncateSecurePassword();

            // Character profiles
            chkUppercase.MouseUp += ChkUppercase_MouseUp;
            chkLowercase.MouseUp += ChkUppercase_MouseUp;
            chkDigits.MouseMove += ChkUppercase_MouseUp;
            chkSymbols.MouseUp += ChkUppercase_MouseUp;
            chkForceEachCategory.MouseUp += ChkUppercase_MouseUp;
            chkMinus.MouseUp += ChkUppercase_MouseUp;
            chkUnderline.MouseUp += ChkUppercase_MouseUp;
            chkSpace.MouseUp += ChkUppercase_MouseUp;
            chkBrackets.MouseUp += ChkUppercase_MouseUp;
            chkLatin.MouseUp += ChkUppercase_MouseUp;
            chkCustomChars.MouseUp += ChkUppercase_MouseUp;
            chkPermute.MouseUp += ChkUppercase_MouseUp;
            chkNoConsecutive.MouseUp += ChkUppercase_MouseUp;
            chkUserEntropyDialog.MouseUp += ChkUppercase_MouseUp;
            nmUpDo.MouseUp += ChkUppercase_MouseUp;

            // Patterns profiles
            rbStandardPatterns.Click += RbStandardPatterns_Click;
            rbAdvancedPatterns.Click += RbStandardPatterns_Click;
            rbCorporatePatterns.Click += RbStandardPatterns_Click;
            cmbPatterns.DropDownClosed += CmbPatterns_DropDownClosed;

            // Character and Patterns
            cmbNmb.DropDownClosed += CmbNmb_DropDownClosed;

            // Patterns
            rdbPattern.CheckedChanged += RbPattern_CheckedChanged;
            rbStandardPatterns.CheckedChanged += RbStandardPatterns_CheckedChanged;
            rbAdvancedPatterns.CheckedChanged += RbAdvancedPatterns_CheckedChanged;
            rbCorporatePatterns.CheckedChanged += RbCorporatePatterns_CheckedChanged;
            rbFileStandardPatterns.CheckedChanged += RbFileStandardPatterns_CheckedChanged;
            rbFileAdvancedPatterns.CheckedChanged += RbFileStandardPatterns_CheckedChanged;
            rbFileCorporatePatterns.CheckedChanged += RbFileStandardPatterns_CheckedChanged;
            txtPatternFlag.KeyPress += TxtPatternFlag_KeyPress;
            btnTest.Click += BtnTest_Click;
            btnSave.Click += BtnSave_Click;
            btnModif.Click += BtnModif_Click;
            btnDelete.Click += BtnDelete_Click;
            btnClear.Click += BtnClear_Click;
            listPatterns.Click += ListPatterns_Click;
            listPatterns.DoubleClick += ListPatterns_DoubleClick;
            listPatterns.MouseUp += ListPatterns_MouseUp;
            txtTestResult.TextChanged += TxtTestResult_TextChanged;
            txtPatternName.TextChanged += (s, ev) => UpdateBtnTest();
            txtPatternRule.TextChanged += (s, ev) => UpdateBtnTest();
            txtPatternFlag.TextChanged += (s, ev) => UpdateBtnTest();
            chkBckStandard.CheckedChanged += ChkBckStandard_CheckedChanged;
            chkBckAdvanced.CheckedChanged += ChkBckStandard_CheckedChanged;
            chkBckCorporate.CheckedChanged += ChkBckStandard_CheckedChanged;
            txtPreview.TextChanged += TxtPreview_TextChanged;
            
            // Restore
            btnRestore.Click += BtnRestore_Click;

            // Acept, Help and Close
            btnAcpt.Click += BtnAcpt_Click;
            btnCanc.Click += BtnCanc_Click;
            btnHelp.Click += BtnHelp_Click;

            #endregion Events Handler

            #region Configuration File

            LoadPatterns(); //Necessary

            _xmlConfig = AppConfigHelper.XmlConfig;
            
            try
            {
                // Pseudo Number Generator
                cmbNmb.Text = string.IsNullOrEmpty(_xmlConfig.GetValue("Result.PSWPeseudoNumberGen")) ? "0" : _xmlConfig.GetValue("Result.PSWPeseudoNumberGen");

                // Password Length
                nmUpDo.Value = int.TryParse(_xmlConfig.GetValue("Result.PSWPasswLength"), out int val) ? val : 7;             

                // Charset 
                rdbCharSet.Checked = string.IsNullOrEmpty(_xmlConfig.GetValue("Result.PSWCharset")) ? true : _xmlConfig.GetValue("Result.PSWCharset") == "True";

                // Pattern 
                rdbPattern.Checked = _xmlConfig.GetValue("Result.PSWPatterns") == "True";

                // Pattern Mode
                rbStandardPatterns.Checked = string.IsNullOrEmpty(_xmlConfig.GetValue("Result.PSWStandardPatterns")) ? true : _xmlConfig.GetValue("Result.PSWStandardPatterns") == "True";

                rbAdvancedPatterns.Checked = _xmlConfig.GetValue("Result.PSWAdvancedPatterns") == "True";
                rbCorporatePatterns.Checked = _xmlConfig.GetValue("Result.PSWCorporatePatterns") == "True";
                rbFileStandardPatterns.Checked = string.IsNullOrEmpty(_xmlConfig.GetValue("Result.PSWFileStandardPatterns")) ? true : _xmlConfig.GetValue("Result.PSWFileStandardPatterns") == "True";
                rbFileAdvancedPatterns.Checked = _xmlConfig.GetValue("Result.PSWFileAdvancedPatterns") == "True";
                rbFileCorporatePatterns.Checked = _xmlConfig.GetValue("Result.PSWFileCorporatePatterns") == "True";
                cmbPatterns.Text = string.IsNullOrEmpty(_xmlConfig.GetValue("Result.PSWFileValuePatterns")) ? "" : _xmlConfig.GetValue("Result.PSWFileValuePatterns");

                // Character Set
                chkUppercase.Checked = string.IsNullOrEmpty(_xmlConfig.GetValue("Result.PSWUpperCase")) ? true : _xmlConfig.GetValue("Result.PSWUpperCase") == "True";
                chkLowercase.Checked = _xmlConfig.GetValue("Result.PSWLowerCase") == "True";
                chkDigits.Checked = _xmlConfig.GetValue("Result.PSWDigits") == "True";
                chkSymbols.Checked = _xmlConfig.GetValue("Result.PSWSymbols") == "True";
                chkMinus.Checked = _xmlConfig.GetValue("Result.PSWMinus") == "True";
                chkUnderline.Checked = _xmlConfig.GetValue("Result.PSWUnderline") == "True";
                chkSpace.Checked = _xmlConfig.GetValue("Result.PSWSpace") == "True";
                chkBrackets.Checked = _xmlConfig.GetValue("Result.PSWBrackets") == "True";
                chkLatin.Checked = _xmlConfig.GetValue("Result.PSWLatin") == "True";
                chkCustomChars.Checked = _xmlConfig.GetValue("Result.PSWCustomChars") == "True";
                chkForceEachCategory.Checked = _xmlConfig.GetValue("Result.PSWForceEachCategory") == "True";
                chkPermute.Checked = _xmlConfig.GetValue("Result.PSWPermute") == "True";
                chkNoConsecutive.Checked = _xmlConfig.GetValue("Result.PSWNoConsecutive") == "True";
                chkUserEntropyDialog.Checked = _xmlConfig.GetValue("Result.PSWUserEntropyDialog") == "True";

                // Backup Files
                chkBackup.Checked = _xmlConfig.GetValue("Result.PSWBackup") == "True";
                chkBckStandard.Checked = _xmlConfig.GetValue("Result.PSWBckStandard") == "True";
                chkBckAdvanced.Checked = _xmlConfig.GetValue("Result.PSWBckAdvanced") == "True";
                chkBckCorporate.Checked = _xmlConfig.GetValue("Result.PSWBckCorporate") == "True";
                rbUserFile.Checked = _xmlConfig.GetValue("Result.PSWUserFile") == "True";
                rbOriginalFile.Checked = string.IsNullOrEmpty(_xmlConfig.GetValue("Result.PSWOriginalFile")) ? true : _xmlConfig.GetValue("Result.PSWOriginalFile") == "True";
            }
            catch (Exception ex)
            {
                // Silent Exception
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Handled exceptions during module loading! " + ex.Message);
            }

            #endregion Configuration File

            #region Initialization

            chkCustomChars.CheckedChanged += (s, e) =>
            {
                txtCustomChars.Enabled = chkCustomChars.Checked;
            };
            
            Selection();  
            EnableFlag();
            PatternFolder();
            chkAdvancedPattern.Enabled = false;
            
            // TextBox hover highlighting
            // Injects dynamic graphic interactions for active input structures
            TextBoxHoverHighlighter.Attach(this);
            ProfileFolder();
            LoadProfileNames();
            SetPlaceholder();
            listPatterns.EnableHandCursor();

            this.KeyPreview = true; // allows the form to intercept key presses

            SpaceKeyBlocker.Enable(this);
            SpeedcryptGhost.Disable(this);
            CaretManager.Attach(secPasw);
            CaretManager.Attach(cmbProfile);
            
            if (mainForm.Obfs == true) SpeedcryptGhost.Enable(this);

            Patternlaunch(); // Initial pattern

            #endregion Initialization
        }

        #endregion Form Routines

        #region Candidate Master Key
        private void BtnGen_Click(object sender, EventArgs e)
        {
            GeneratePassword();
        }
        private void BtnPsw_Click(object sender, EventArgs e)
        {
            if (secPasw.UseSystemPasswordChar == true)
            {
                secPasw.UseSystemPasswordChar = false;
                secPasw.Text = SecureStringExtension.ConvertToString(secPasw.SecureText);
                btnPsw.Image = null;
                btnPsw.Text = "\u25CF" + "\u25CF" + "\u25CF";
            }
            else
            {
                secPasw.UseSystemPasswordChar = true;
                btnPsw.Image = ForAllUnits.Passwordview22;
                btnPsw.Text = string.Empty;
            }
            secPasw.Focus();

            if (ForAllUnits.MousCurs == 0)
                secPasw.SelectionStart = secPasw.Text.Length;
            else
                secPasw.SelectionStart = ForAllUnits.MousCurs;
            secPasw.SelectionLength = 0;
        }
        private void SecPasw_MouseClick(object sender, MouseEventArgs e)
        {
            ForAllUnits.MousCurs = secPasw.SelectionStart;
        }
        private void SecPasw_KeyUp(object sender, KeyEventArgs e)
        {
            ForAllUnits.MousCurs = secPasw.SelectionStart;
            if (secPasw.UseSystemPasswordChar == true)
            {
                btnPsw.Text = string.Empty;
                btnPsw.Image = ForAllUnits.Passwordview22;
            }

            MastKey();
        }
        private void SecPasw_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Delete)
            {
                e.SuppressKeyPress = true;//Prevents the Delete key
            }
        }
        private void CmbNmb_SelectedIndexChanged(object sender, EventArgs e)
        {
            Selection();
        }
        private void BtnSaveProfile_Click(object sender, EventArgs e)
        {
            SaveProfile();
            LoadProfile();
        }
        private void BtnClearCombo_Click(object sender, EventArgs e)
        {
            cmbProfile.Text = string.Empty;
            ResetPlaceHolder();
            btnClearCombo.Enabled = false;
        }
        private void BtnDeleteProfile_Click(object sender, EventArgs e)
        {
            CancelProfile();
        }
        private void CmbProfile_TextChanged(object sender, EventArgs e)
        {
            bool exists = cmbProfile.Items.Cast<object>().Any(item => string.Equals(item.ToString(), cmbProfile.Text, StringComparison.OrdinalIgnoreCase));

            btnSaveProfile.Enabled = cmbProfile.Text != placeholderText && cmbProfile.Text != string.Empty  &&  !exists;

            btnClearCombo.Enabled = cmbProfile.Text != placeholderText && cmbProfile.Text != string.Empty;

            if (!isPlaceholderActive && string.IsNullOrEmpty(cmbProfile.Text))
            {
                cmbProfile.Text = placeholderText;
                cmbProfile.ForeColor = Color.Gray;
                isPlaceholderActive = true;
                cmbProfile.SelectionStart = 0;
            }
            labProfnum.Text = cmbProfile.Items.Count.ToString();
            ProfileExists();
        }
        private void CmbProfile_DropDown(object sender, EventArgs e)
        {
            if (isPlaceholderActive)
            {
                cmbProfile.Text = placeholderText;
                cmbProfile.ForeColor = Color.Gray;
                cmbProfile.SelectionStart = 0;
            }
        }
        private void CmbProfile_DropDownClosed(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(cmbProfile.Text))
            {
                cmbProfile.Text = placeholderText;
                cmbProfile.ForeColor = Color.Gray;
                isPlaceholderActive = true;
            }
        }
        private void CmbProfile_SelectedIndexChanged(object sender, EventArgs e)
        {
            LoadProfile();
            if (cmbProfile.SelectedIndex >= 0)
            {
                cmbProfile.ForeColor = Color.Black;
                isPlaceholderActive = false;
            }
         }
        private void CmbProfile_Enter(object sender, EventArgs e)
        {
            if (isPlaceholderActive)
            {
                cmbProfile.Text = "";
                cmbProfile.ForeColor = Color.Black;
                isPlaceholderActive = false;
            }
        }
        private void CmbProfile_Leave(object sender, EventArgs e)
        {
             if (string.IsNullOrEmpty(cmbProfile.Text))
             {
                 cmbProfile.Text = placeholderText;
                 cmbProfile.ForeColor = Color.Gray;
                 isPlaceholderActive = true;
             }
        }
        private void CmbProfile_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (isPlaceholderActive)
             {                
                cmbProfile.Text = "";
                cmbProfile.ForeColor = Color.Black;
                isPlaceholderActive = false;
             }
        }
        private void CmbProfile_MouseClick(object sender, MouseEventArgs e)
        {
            if (isPlaceholderActive)
            {
                cmbProfile.Text = "";
                cmbProfile.ForeColor = Color.Black;
                isPlaceholderActive = false;
            }
        }
        private void CmbProfile_KeyDown(object sender, KeyEventArgs e)
        {
             if (isPlaceholderActive)
             {
                 cmbProfile.Text = "";
                 cmbProfile.ForeColor = Color.Black;
                 isPlaceholderActive = false;
                 cmbProfile.SelectionStart = 0;
             }
        }
        private void CmbProfile_DrawItem(object sender, DrawItemEventArgs e)
         {
             if (e.Index < 0) return;

             if ((e.State & DrawItemState.Selected) == DrawItemState.Selected)
             {
                 e.Graphics.FillRectangle(SystemBrushes.Highlight, e.Bounds);
                 using (SolidBrush brush = new SolidBrush(SystemColors.HighlightText))
                 {
                     e.Graphics.DrawString(cmbProfile.Items[e.Index].ToString(), e.Font, brush, e.Bounds);
                 }
             }
             else
             {
                 e.Graphics.FillRectangle(SystemBrushes.Window, e.Bounds);
                 using (SolidBrush brush = new SolidBrush(Color.Black)) 
                 {
                     e.Graphics.DrawString(cmbProfile.Items[e.Index].ToString(), e.Font, brush, e.Bounds);
                 }
             }

             e.DrawFocusRectangle();            
        }
        private void SetPlaceholder()
        {
            cmbProfile.Text = "Profile Name";
            cmbProfile.ForeColor = Color.Gray;
            isPlaceholderActive = true;
        }

        // TECHNICAL SPECIFICATION: High-Entropy Deterministic Password Generation Engine
        // 1. ENTROPY AGGREGATION: Dynamically chains system cryptographically secure random seeds (CSPRNG) 
        //    with volatile, custom hardware runtime user entropy inputs into an isolated buffer.
        // 2. CRYPTOGRAPHIC PRNG: Drives deterministic bit extraction via an internal Hash-DRBG state machine 
        //    powered by the robust HASHLib Skein256 algorithm with integrated rejection-sampling logic.
        // 3. CHARSET & PATTERN INGESTION: Parses conditional corporate compliance tokens, regular expressions, 
        //    and uniform bounds to generate compliant visual sequences with strict non-consecutive tracking.
        // 4. SECURITY FINALIZATION: Executes an unbiased modulo-bias-free Fisher-Yates memory permutation loop, 
        //    commits the final data tokens directly to Win32 SecureString contexts, and forcefully purges (wipes) 
        //    all temporary source array byte residues inside a guaranteed isolation block (finally).
        void GeneratePassword()
        {
            if (cmbNmb.SelectedIndex == 1)
                btnGen.Enabled = false;

            // CLEAR SECURE TEXT
            secPasw.SecureText.Clear();

            byte[] userEntropy = null;

            // COLLECT USER ENTROPY IF ENABLED
            if (chkUserEntropyDialog.Checked)
            {
                FrmEntropy fEntropy = new FrmEntropy(this)
                {
                    StartPosition = FormStartPosition.Manual,
                    Owner = this
                };

                int x = this.Location.X + (this.Width - fEntropy.Width) / 2;
                int y = this.Location.Y + (this.Height - fEntropy.Height) / 2;
                fEntropy.Location = new Point(x, y);

                fEntropy.ShowDialog();

                if (fEntropy.CollectedEntropy != null && fEntropy.CollectedEntropy.Length > 0)
                    userEntropy = fEntropy.CollectedEntropy;
            }

            // DEFINE CHARACTER SETS
            const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string LOWER = "abcdefghijklmnopqrstuvwxyz";
            const string DIGITS = "0123456789";
            const string SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?";

            int length = (int)nmUpDo.Value;

            var checkboxCharSet = new List<char>();
            if (chkUppercase.Checked) checkboxCharSet.AddRange(UPPER);
            if (chkLowercase.Checked) checkboxCharSet.AddRange(LOWER);
            if (chkDigits.Checked) checkboxCharSet.AddRange(DIGITS);
            if (chkSymbols.Checked) checkboxCharSet.AddRange(SYMBOLS);
            if (chkMinus.Checked) checkboxCharSet.Add('-');
            if (chkUnderline.Checked) checkboxCharSet.Add('_');
            if (chkSpace.Checked) checkboxCharSet.Add(' ');
            if (chkBrackets.Checked) checkboxCharSet.AddRange("()[]{}<>");
            if (chkLatin.Checked)
            {
                for (int cp = 0x00A0; cp <= 0x00FF; cp++)
                    checkboxCharSet.Add((char)cp);
            }

            if (chkCustomChars.Checked && !string.IsNullOrEmpty(txtCustomChars.Text))
                // Enforce Distinct to eliminate user-input duplicates and maintain uniform entropy
                checkboxCharSet.AddRange(txtCustomChars.Text.Distinct());

            if (rdbCharSet.Checked && checkboxCharSet.Count == 0)
            {
                MessageBox.Show("Please select at least one character set.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            var entropyProvider = new SystemEntropyProvider(); // BouncyCastle CSPRNG
                                                               // GENERATE RNG SEED
            byte[] seed = null;
            try
            {
                switch (cmbNmb.Text)
                {
                    case "BCRYPT":
                        byte[] saltBytes = BCryptBouncy.BcryptSalt();
                        seed = saltBytes; // use the byte[] directly
                        break;

                    case "FORTUNA":
                        seed = SaltManager.FortunaSalt();
                        break;

                    case "AES-CTR DRBG":
                        seed = SaltManager.AesctrdrbSeq(entropyProvider);
                        break;

                    case "CRYPTO-RANDOM":
                        seed = SaltManager.Criptorandom(entropyProvider);
                        break;

                    case "BLUM-BLUM-SHUB[BBS]":
                        seed = SaltManager.BlumBlumSeq(entropyProvider);
                        break;

                    default:
                        seed = SaltManager.Criptorandom(entropyProvider);
                        break;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("RNG selection failed! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "RNG selection failed! " + ex.Message);
                return;
            }

            if (seed == null || seed.Length == 0)
            {
                MessageBox.Show("RNG seed generation failed!", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // INTERNAL STATE FOR HASH-BASED PRNG
            byte[] lastBlock = Array.Empty<byte>();
            long blockCounter = 0;
            int blockPos = 0;

            // NEXT BYTE GENERATOR USING HASH DRBG WITH REJECTION SAMPLING
            byte[] combined = new byte[seed.Length + (userEntropy?.Length ?? 0) + sizeof(long)];

            byte NextByte()
            {
                if (blockPos >= lastBlock.Length)
                {
                    Buffer.BlockCopy(seed, 0, combined, 0, seed.Length);
                    if (userEntropy != null)
                        Buffer.BlockCopy(userEntropy, 0, combined, seed.Length, userEntropy.Length);
                    Buffer.BlockCopy(BitConverter.GetBytes(blockCounter), 0, combined, seed.Length + (userEntropy?.Length ?? 0), sizeof(long));

                    lastBlock = HASHLib.ComputeSkein256(combined);

                    if (lastBlock == null || lastBlock.Length == 0)
                        throw new InvalidOperationException("Hash PRNG returned empty block.");

                    blockCounter++;
                    blockPos = 0;

                    // CLEAR TEMPORARY COMBINED BUFFER
                    Array.Clear(combined, 0, combined.Length);
                }
                return lastBlock[blockPos++];
            }

            int CountInCategory(List<char> list, string category)
            {
                int cnt = 0;
                for (int ii = 0; ii < list.Count; ii++)
                    if (category.IndexOf(list[ii]) >= 0) cnt++;
                return cnt;
            }

            // ExpandRange: turns "a-z0-9" or "01-3" inside a bracket into an explicit char sequence.
            string ExpandRange(string token)
            {
                var charsList = new List<char>();
                for (int i = 0; i < token.Length; i++)
                {
                    if (i + 2 < token.Length && token[i + 1] == '-')
                    {
                        char start = token[i];
                        char end = token[i + 2];
                        if (start <= end)
                            for (char c = start; c <= end; c++) charsList.Add(c);
                        else
                            for (char c = start; c >= end; c--) charsList.Add(c);
                        i += 2;
                    }
                    else
                    {
                        charsList.Add(token[i]);
                    }
                }
                return new string(charsList.ToArray());
            }

            var passwordChars = new List<char>();

            try
            {
                // =========================
                // BLOCK 1: CHARSET GENERATION
                // =========================
                if (rdbCharSet.Checked)
                {
                    if (chkForceEachCategory.Checked)
                    {
                        if (chkUppercase.Checked) passwordChars.Add(UPPER[NextByte() % UPPER.Length]);
                        if (chkLowercase.Checked) passwordChars.Add(LOWER[NextByte() % LOWER.Length]);
                        if (chkDigits.Checked) passwordChars.Add(DIGITS[NextByte() % DIGITS.Length]);
                        if (chkSymbols.Checked) passwordChars.Add(SYMBOLS[NextByte() % SYMBOLS.Length]);
                        if (chkCustomChars.Checked && !string.IsNullOrEmpty(txtCustomChars.Text))
                            passwordChars.Add(txtCustomChars.Text[NextByte() % txtCustomChars.Text.Length]);
                        if (chkMinus.Checked) passwordChars.Add('-');
                        if (chkUnderline.Checked) passwordChars.Add('_');
                        if (chkSpace.Checked) passwordChars.Add(' ');
                    }

                    var activeCategories = new List<string>();
                    if (chkUppercase.Checked) activeCategories.Add(UPPER);
                    if (chkLowercase.Checked) activeCategories.Add(LOWER);
                    if (chkDigits.Checked) activeCategories.Add(DIGITS);
                    if (chkSymbols.Checked) activeCategories.Add(SYMBOLS);
                    if (chkCustomChars.Checked && !string.IsNullOrEmpty(txtCustomChars.Text)) activeCategories.Add(txtCustomChars.Text);
                    if (chkMinus.Checked) activeCategories.Add("-");
                    if (chkUnderline.Checked) activeCategories.Add("_");
                    if (chkSpace.Checked) activeCategories.Add(" ");

                    int minPercentage = 20;
                    foreach (string category in activeCategories)
                    {
                        int minCount = Math.Max(1, (int)Math.Ceiling(length * minPercentage / 100.0));
                        while (CountInCategory(passwordChars, category) < minCount && passwordChars.Count < length)
                        {
                            char sel;
                            int safety = 0;
                            do
                            {
                                byte r = NextByte();
                                sel = category[r % category.Length];
                                safety++;
                            } while (chkNoConsecutive.Checked && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safety < 64);
                            passwordChars.Add(sel);
                        }
                    }

                    while (passwordChars.Count < length)
                    {
                        char sel;
                        int safety = 0;
                        do
                        {
                            byte r = NextByte();
                            sel = checkboxCharSet[r % checkboxCharSet.Count];
                            safety++;
                        } while (chkNoConsecutive.Checked && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safety < 64);
                        passwordChars.Add(sel);
                    }
                }
                // =========================
                // BLOCK 2: PATTERN GENERATION
                // =========================
                else if (rdbPattern.Checked)
                {
                    // CORPORATE PATTERNS AND ADVANCED PATTERN LOGIC INCLUDED
                    if (rbCorporatePatterns.Checked)
                    {
                        if (cmbPatterns.SelectedItem == null)
                        {
                            MessageBox.Show("Please select a corporate pattern.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        string ruleString = labPattern.Text;
                        if (string.IsNullOrEmpty(ruleString))
                        {
                            MessageBox.Show("Pattern definition is empty.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        string[] ruleParts = ruleString.Split('|');
                        if (ruleParts.Length >= 2)
                            ruleString = ruleParts[1];
                        else
                            ruleString = ruleParts[0];

                        passwordChars.Clear();

                        if (ruleString.StartsWith("Type=passphrase", StringComparison.OrdinalIgnoreCase))
                        {
                            var parts = ruleString.Split(';');
                            int wordCount = 4;
                            string separator = "-";

                            foreach (var part in parts)
                            {
                                if (part.StartsWith("Words=")) int.TryParse(part.Substring(6), out wordCount);
                                else if (part.StartsWith("Separator=")) separator = part.Substring(10);
                            }

                            for (int i = 0; i < wordCount; i++)
                            {
                                int wordLen = 3 + (NextByte() % 4);
                                for (int j = 0; j < wordLen; j++)
                                {
                                    passwordChars.Add(LOWER[NextByte() % LOWER.Length]);
                                }

                                if (i < wordCount - 1 && !string.IsNullOrEmpty(separator))
                                {
                                    foreach (char sepChar in separator)
                                        passwordChars.Add(sepChar);
                                }
                            }
                        }
                        else if (ruleString.StartsWith("L="))
                        {
                            int targetLength = 0, minUpper = 0, minLower = 0, minDigits = 0, minSymbols = 0;
                            bool noConsecutive = false;

                            string[] parts = ruleString.Split(';');
                            foreach (var part in parts)
                            {
                                if (part.StartsWith("L=")) int.TryParse(part.Substring(2), out targetLength);
                                else if (part.StartsWith("U>=")) int.TryParse(part.Substring(3), out minUpper);
                                else if (part.StartsWith("Lw>=")) int.TryParse(part.Substring(4), out minLower);
                                else if (part.StartsWith("D>=")) int.TryParse(part.Substring(3), out minDigits);
                                else if (part.StartsWith("S>=")) int.TryParse(part.Substring(3), out minSymbols);
                                else if (part.Equals("NoConsecutive=1", StringComparison.OrdinalIgnoreCase)) noConsecutive = true;
                            }

                            while (CountInCategory(passwordChars, UPPER) < minUpper && passwordChars.Count < targetLength) passwordChars.Add(UPPER[NextByte() % UPPER.Length]);
                            while (CountInCategory(passwordChars, LOWER) < minLower && passwordChars.Count < targetLength) passwordChars.Add(LOWER[NextByte() % LOWER.Length]);
                            while (CountInCategory(passwordChars, DIGITS) < minDigits && passwordChars.Count < targetLength) passwordChars.Add(DIGITS[NextByte() % DIGITS.Length]);
                            while (CountInCategory(passwordChars, SYMBOLS) < minSymbols && passwordChars.Count < targetLength) passwordChars.Add(SYMBOLS[NextByte() % SYMBOLS.Length]);

                            string allChars = UPPER + LOWER + DIGITS + SYMBOLS;
                            while (passwordChars.Count < targetLength)
                            {
                                char sel = allChars[NextByte() % allChars.Length];
                                int safety = 0;
                                while (noConsecutive && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safety < 64)
                                {
                                    sel = allChars[NextByte() % allChars.Length];
                                    safety++;
                                }
                                passwordChars.Add(sel);
                            }
                        }
                        else if (ruleString.StartsWith("[") || Char.IsLetter(ruleString[0]))
                        {
                            var regex = new System.Text.RegularExpressions.Regex(@"(\[[^\]]+\]|[^\[\]]+)(\{(\d+),?(\d+)?\})?");
                            var matches = regex.Matches(ruleString);

                            foreach (System.Text.RegularExpressions.Match m in matches)
                            {
                                string token = m.Groups[1].Value;
                                int minRepeat = 1, maxRepeat = 1;

                                if (m.Groups[3].Success)
                                {
                                    // Enforce InvariantCulture to safely parse the minimum repeat constraint from the third regex group
                                    minRepeat = Math.Max(1, int.Parse(m.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture));
                                }

                                if (m.Groups[4].Success)
                                {
                                    // Enforce InvariantCulture to safely parse the maximum repeat constraint from the fourth regex group
                                    maxRepeat = Math.Max(minRepeat, int.Parse(m.Groups[4].Value, System.Globalization.CultureInfo.InvariantCulture));
                                }


                                if (token.StartsWith("[") && token.EndsWith("]"))
                                {
                                    string charSet = ExpandRange(token.Substring(1, token.Length - 2));
                                    if (string.IsNullOrEmpty(charSet)) continue;

                                    int repeat = minRepeat + (maxRepeat > minRepeat ? NextByte() % (maxRepeat - minRepeat + 1) : 0);
                                    for (int i = 0; i < repeat; i++)
                                        passwordChars.Add(charSet[NextByte() % charSet.Length]);
                                }
                                else if (token == "?")
                                {
                                    if (checkboxCharSet.Count == 0)
                                    {
                                        MessageBox.Show("Character set cannot be empty when '?' is used in the pattern.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                        return;
                                    }
                                    int repeat = minRepeat + (maxRepeat > minRepeat ? NextByte() % (maxRepeat - minRepeat + 1) : 0);
                                    for (int i = 0; i < repeat; i++)
                                        passwordChars.Add(checkboxCharSet[NextByte() % checkboxCharSet.Count]);
                                }
                                else
                                {
                                    int repeat = minRepeat + (maxRepeat > minRepeat ? NextByte() % (maxRepeat - minRepeat + 1) : 0);
                                    for (int r = 0; r < repeat; r++)
                                    {
                                        foreach (char ch in token)
                                            passwordChars.Add(ch);
                                    }
                                }
                            }
                        }
                    }

                    // STANDARD PATTERN GENERATION
                    else
                    {
                        string pattern = labPattern.Text ?? string.Empty;
                        if (pattern.Length == 0)
                        {
                            MessageBox.Show("Pattern cannot be empty.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        if (pattern.Contains('?') && checkboxCharSet.Count == 0)
                        {
                            MessageBox.Show("Character set cannot be empty when '?' is used in the pattern.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        passwordChars.Clear();

                        bool advancedAllowed = chkAdvancedPattern.Checked;

                        if (advancedAllowed)
                        {
                            var regex = new System.Text.RegularExpressions.Regex(@"(\[[^\]]+\]|[^\[\]]+)(\{(\d+),?(\d+)?\})?");
                            var matches = regex.Matches(pattern);

                            foreach (System.Text.RegularExpressions.Match m in matches)
                            {
                                string token = m.Groups[1].Value;
                                int minRepeat = 1, maxRepeat = 1;

                                if (m.Groups[3].Success)
                                {
                                    // Enforce InvariantCulture to safely parse the minimum repeat constraint from the third regex group
                                    minRepeat = Math.Max(1, int.Parse(m.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture));
                                }

                                if (m.Groups[4].Success)
                                {
                                    // Enforce InvariantCulture to safely parse the maximum repeat constraint from the fourth regex group
                                    maxRepeat = Math.Max(minRepeat, int.Parse(m.Groups[4].Value, System.Globalization.CultureInfo.InvariantCulture));
                                }

                                if (token.StartsWith("[") && token.EndsWith("]"))
                                {
                                    string charSet = ExpandRange(token.Substring(1, token.Length - 2));
                                    if (string.IsNullOrEmpty(charSet)) continue;

                                    int repeat = minRepeat + (maxRepeat > minRepeat ? NextByte() % (maxRepeat - minRepeat + 1) : 0);
                                    for (int i = 0; i < repeat; i++)
                                        passwordChars.Add(charSet[NextByte() % charSet.Length]);
                                }
                                else if (token == "?")
                                {
                                    int repeat = minRepeat + (maxRepeat > minRepeat ? NextByte() % (maxRepeat - minRepeat + 1) : 0);
                                    for (int i = 0; i < repeat; i++)
                                        passwordChars.Add(checkboxCharSet[NextByte() % checkboxCharSet.Count]);
                                }
                                else
                                {
                                    int repeat = minRepeat + (maxRepeat > minRepeat ? NextByte() % (maxRepeat - minRepeat + 1) : 0);
                                    for (int r = 0; r < repeat; r++)
                                    {
                                        foreach (char ch in token)
                                            passwordChars.Add(ch);
                                    }
                                }
                            }
                        }
                        else
                        {
                            foreach (char c in pattern)
                            {
                                char sel = '?';
                                int safetyLimit = 0;

                                if (char.IsUpper(c))
                                {
                                    int len = UPPER.Length;
                                    int rem = 256 % len;
                                    byte b;
                                    do { b = NextByte(); } while (b >= 256 - rem);
                                    sel = UPPER[b % len];

                                    // Handle non-consecutive constraint using the same character set context
                                    while (chkNoConsecutive.Checked && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safetyLimit < 64)
                                    {
                                        do { b = NextByte(); } while (b >= 256 - rem);
                                        sel = UPPER[b % len];
                                        safetyLimit++;
                                    }
                                }
                                else if (char.IsLower(c))
                                {
                                    int len = LOWER.Length;
                                    int rem = 256 % len;
                                    byte b;
                                    do { b = NextByte(); } while (b >= 256 - rem);
                                    sel = LOWER[b % len];

                                    // Handle non-consecutive constraint using the same character set context
                                    while (chkNoConsecutive.Checked && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safetyLimit < 64)
                                    {
                                        do { b = NextByte(); } while (b >= 256 - rem);
                                        sel = LOWER[b % len];
                                        safetyLimit++;
                                    }
                                }
                                else if (char.IsDigit(c))
                                {
                                    int len = DIGITS.Length;
                                    int rem = 256 % len;
                                    byte b;
                                    do { b = NextByte(); } while (b >= 256 - rem);
                                    sel = DIGITS[b % len];

                                    // Handle non-consecutive constraint using the same character set context
                                    while (chkNoConsecutive.Checked && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safetyLimit < 64)
                                    {
                                        do { b = NextByte(); } while (b >= 256 - rem);
                                        sel = DIGITS[b % len];
                                        safetyLimit++;
                                    }
                                }
                                else if (c == '!')
                                {
                                    int len = SYMBOLS.Length;
                                    int rem = 256 % len;
                                    byte b;
                                    do { b = NextByte(); } while (b >= 256 - rem);
                                    sel = SYMBOLS[b % len];

                                    // Handle non-consecutive constraint using the same character set context
                                    while (chkNoConsecutive.Checked && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safetyLimit < 64)
                                    {
                                        do { b = NextByte(); } while (b >= 256 - rem);
                                        sel = SYMBOLS[b % len];
                                        safetyLimit++;
                                    }
                                }
                                else if (c == '-') sel = '-';
                                else if (c == '_') sel = '_';
                                else if (c == ' ') sel = ' ';
                                else if (c == '?')
                                {
                                    if (checkboxCharSet.Count == 0) return;

                                    int len = checkboxCharSet.Count;
                                    int rem = 256 % len;
                                    byte b;
                                    do { b = NextByte(); } while (b >= 256 - rem);
                                    sel = checkboxCharSet[b % len];

                                    // Handle non-consecutive constraint using the same character set context
                                    while (chkNoConsecutive.Checked && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safetyLimit < 64)
                                    {
                                        do { b = NextByte(); } while (b >= 256 - rem);
                                        sel = checkboxCharSet[b % len];
                                        safetyLimit++;
                                    }
                                }
                                else
                                {
                                    MessageBox.Show($"Invalid character in pattern: '{c}'. Advanced pattern not allowed.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                                    return;
                                }

                                passwordChars.Add(sel);
                            }

                            string finalPassword = new string(passwordChars.ToArray());
                            secPasw.Text = finalPassword;
                            secPasw.SecureText.Clear();
                            ForAllUnits.CharArr = passwordChars.ToArray();
                            foreach (char ch in ForAllUnits.CharArr)
                                secPasw.SecureText.AppendChar(ch);
                        }
                    }
                }

                // PERMUTE PASSWORD IF ENABLED
                if (chkPermute.Checked)
                {
                    for (int i = passwordChars.Count - 1; i > 0; i--)
                    {
                        int j;
                        do
                        {
                            j = NextByte();
                        } while (j >= 256 - (256 % (i + 1))); // reduce modulo bias
                        j = j % (i + 1);

                        char tmp = passwordChars[i];
                        passwordChars[i] = passwordChars[j];
                        passwordChars[j] = tmp;
                    }
                }

                // FINALIZE PASSWORD
                string result = new string(passwordChars.ToArray());
                secPasw.Text = result; // indispensable

                secPasw.SecureText.Clear();
                ForAllUnits.CharArr = passwordChars.ToArray();
                foreach (char c in ForAllUnits.CharArr)
                    secPasw.SecureText.AppendChar(c);

                MastKey();
                btnGen.Enabled = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Generation failed! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Generation failed! " + ex.Message);
            }
            finally
            {
                // CLEAR TEMPORARY BUFFERS AND SEEDS
                if (seed != null) { Array.Clear(seed, 0, seed.Length); seed = null; }
                if (lastBlock != null) { Array.Clear(lastBlock, 0, lastBlock.Length); lastBlock = null; }
                if (combined != null) { Array.Clear(combined, 0, combined.Length); combined = null; }
                if (userEntropy != null) { Array.Clear(userEntropy, 0, userEntropy.Length); userEntropy = null; }
                secPasw.Focus();
            }
        } 
        void Selection()
        {
            var algoIndex = cmbNmb.SelectedIndex;
            labDesc.Text = string.Empty;

            var generators = new Dictionary<int, (string Description, int Score)>
            {
                [0] = (
                       "This generator uses the Windows CNG (Cryptography Next Generation) API to produce random numbers. " +
                       "It provides system-level security, strong seeding, and is suitable for most cryptographic purposes. " +
                       "It is fast and reliable, but fully dependent on the Windows platform implementation.\r\n" +
                       "●  Security: High | Performance: Fast\r\n" +
                       "●  Notes: Reliable, system-based",
                       80
                ),

                [1] = (
                       "This generator is a well-known design based on multiple entropy pools and AES encryption. " +
                       "It continuously mixes new entropy into its state, making backtracking attacks very difficult. " +
                       "It offers excellent robustness and cross-platform security, though slightly slower in performance.\r\n" +
                       "●  Security: Very High | Performance: Slow\r\n" +
                       "●  Notes: Strong backtracking resistance",
                       95
                ),

                [2] = (
                       "This generator implements the NIST-approved Deterministic Random Bit Generator based on AES in CTR mode. " +
                       "It provides strong predictability resistance and well-studied security guarantees. " +
                       "Performance is generally fast, depends on efficient AES support on the hardware.\r\n" +
                       "●  Security: High | Performance: Fast\r\n" +
                       "●  Notes: NIST standard, fast on hardware AES",
                       85
                ),

                [3] = (
                       "This generator uses the system cryptographic random API, mapped directly to a secure random provider. " +
                       "It is simple, efficient, and inherits the strength of the underlying operating system. " +
                       "However, it offers less configurability compared to advanced designs like Fortuna or DRBG.\r\n" +
                       "●  Security: Medium | Performance: Very Fast\r\n" +
                       "●  Notes: Simple, OS-dependent",
                       70
                ),

                [4] = (
                       "This generator is based on number-theoretic properties of quadratic residues. " +
                       "It is mathematically secure under the assumption that factoring large integers is hard. " +
                       "Although very strong in theory, it is significantly slower than practical alternatives.\r\n" +
                       "●  Security: Very High | Performance: Slow\r\n" +
                       "●  Notes: Very strong mathematically",
                       90
                )
            };

            if (generators.ContainsKey(algoIndex))
            {
                labDesc.Text = generators[algoIndex].Description;
                qualityProgressBar2.Value = generators[algoIndex].Score; // Update the progress bar
            }
        }
        void SaveProfile()
        {
            try
            {
                 // Ensure the Profiles folder exists
                ProfileFolder();

                string profilesFolder = Path.Combine(Application.StartupPath, "Profiles");
                string profileName = cmbProfile.Text.Trim();

                // Do nothing if combo is empty
                if (string.IsNullOrEmpty(profileName))
                    return;

                string filePath = Path.Combine(profilesFolder, profileName + ".json");

                var profile = new PasswordProfile
                {
                    Length = (int)nmUpDo.Value,
                    UseUppercase = chkUppercase.Checked,
                    UseLowercase = chkLowercase.Checked,
                    UseDigits = chkDigits.Checked,
                    UseSymbols = chkSymbols.Checked,
                    UseMinus = chkMinus.Checked,
                    UseUnderline = chkUnderline.Checked,
                    UseSpace = chkSpace.Checked,
                    UseBrackets = chkBrackets.Checked,
                    UseLatin1 = chkLatin.Checked,
                    UseCustomChars = chkCustomChars.Checked,
                    CustomChars = txtCustomChars.Text ?? string.Empty,
                    ForceEachCategory = chkForceEachCategory.Checked,
                    NoConsecutive = chkNoConsecutive.Checked,
                    PatternMode = rdbPattern.Checked,
                    PatternText = labPattern.Text ?? string.Empty,
                    PatternValue = cmbPatterns.Text ?? string.Empty,
                    Permute = chkPermute.Checked,
                    AdvancedPattern = chkAdvancedPattern.Checked,
                    PseudoNumberGen = cmbNmb.SelectedIndex,
                    CharsetMode = rdbCharSet.Checked,
                    StandardPatterns = rbStandardPatterns.Checked,
                    AdvancedPatterns = rbAdvancedPatterns.Checked,
                    CorporatePatterns = rbCorporatePatterns.Checked,
                    UserEntropyDialog = chkUserEntropyDialog.Checked,
                    Backup = chkBackup.Checked,
                    BckStandard = chkBckStandard.Checked,
                    BckAdvanced = chkBckAdvanced.Checked,
                    BckCorporate = chkBckCorporate.Checked,
                    UserFile = rbUserFile.Checked,
                    OriginalFile = rbOriginalFile.Checked,                    
                };
                
                btnDeleteProfile.Enabled = true;
                string json = JsonConvert.SerializeObject(profile, Formatting.Indented);

                // Save the profile: overwrite if it already exists
                File.WriteAllText(filePath, json);

                // Add new profile to combo if not already present
                if (!cmbProfile.Items.Contains(profileName))
                    cmbProfile.Items.Add(profileName);
                labProfnum.Text = cmbProfile.Items.Count.ToString();

                // Note: If the profile already exists, it is overwritten silently, no prompts are shown
                bool exists = cmbProfile.Items.Cast<object>().Any(item => string.Equals(item.ToString(), cmbProfile.Text, StringComparison.OrdinalIgnoreCase));
                if (!exists)
                   MessageBox.Show("Profile " + profileName + " successfully created!", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
                else
                    MessageBox.Show("Profile " + profileName + " successfully updated!", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);

                btnSaveProfile.Enabled = false;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to save profile! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Failed to save profile! " + ex.Message);
            }
        }
        private void LoadProfile()
        {
            try
            {
                // Ensure the Profiles folder exists
                ProfileFolder();

                string profilesFolder = Path.Combine(Application.StartupPath, "Profiles");
                string profileName = cmbProfile.Text.Trim();

                // Do nothing if combo is empty
                if (string.IsNullOrEmpty(profileName))
                    return;

                string filePath = Path.Combine(profilesFolder, profileName + ".json");

                // If the profile file does not exist, do nothing
                if (!File.Exists(filePath))
                    return;

                string json = File.ReadAllText(filePath);
                var profile = JsonConvert.DeserializeObject<PasswordProfile>(json);

                // If deserialization fails, do nothing
                if (profile == null)
                    return;

                // Populate controls with loaded profile data
                chkUppercase.Checked = profile.UseUppercase;
                chkLowercase.Checked = profile.UseLowercase;
                chkDigits.Checked = profile.UseDigits;
                chkSymbols.Checked = profile.UseSymbols;
                chkMinus.Checked = profile.UseMinus;
                chkUnderline.Checked = profile.UseUnderline;
                chkSpace.Checked = profile.UseSpace;
                chkBrackets.Checked = profile.UseBrackets;
                chkLatin.Checked = profile.UseLatin1;
                chkCustomChars.Checked = profile.UseCustomChars;
                txtCustomChars.Text = profile.CustomChars ?? string.Empty;
                chkForceEachCategory.Checked = profile.ForceEachCategory;
                chkNoConsecutive.Checked = profile.NoConsecutive;
                rdbPattern.Checked = profile.PatternMode;
                chkPermute.Checked = profile.Permute;
                cmbNmb.SelectedIndex = profile.PseudoNumberGen;
                rdbCharSet.Checked = profile.CharsetMode;
                chkUserEntropyDialog.Checked = profile.UserEntropyDialog;
                chkBackup.Checked = profile.Backup;
                chkBckStandard.Checked = profile.BckStandard;
                chkBckAdvanced.Checked = profile.BckAdvanced;
                chkBckCorporate.Checked = profile.BckCorporate;
                rbUserFile.Checked = profile.UserFile;
                rbOriginalFile.Checked = profile.OriginalFile;

                if (rdbCharSet.Checked) nmUpDo.Value = profile.Length; // Only Character Profile

                if (rdbPattern.Checked) // Only Pattern Profile
                {
                    chkAdvancedPattern.Checked = profile.AdvancedPattern;
                    rbStandardPatterns.Checked = profile.StandardPatterns;
                    rbAdvancedPatterns.Checked = profile.AdvancedPatterns;
                    rbCorporatePatterns.Checked = profile.CorporatePatterns;
                    labPattern.Text = profile.PatternText ?? string.Empty;
                    LoadPatterns(); // Indispensable
                    if (!string.IsNullOrWhiteSpace(profile.PatternValue))
                    {
                        int index = cmbPatterns.FindStringExact(profile.PatternValue);

                        if (index >= 0)
                            cmbPatterns.SelectedIndex = index;
                        else if (cmbPatterns.Items.Count > 0)
                            cmbPatterns.SelectedIndex = 0;
                    }
                    else if (cmbPatterns.Items.Count > 0)
                    {
                        cmbPatterns.SelectedIndex = 0;
                    }
                }

                // Store original loaded profile for change tracking
                _originalProfile = JsonConvert.DeserializeObject<PasswordProfile>(json);

                // Reset save button state after loading
                btnSaveProfile.Enabled = false;

                // Note: Profile is loaded automatically based on the combo selection
                // If the profile does not exist, nothing happens and no warnings are shown
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to load profile! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Failed to load profile! " + ex.Message);
            }
        }        
        private void CancelProfile()
        {
            try
            {
                // Check if a profile name is selected
                string profileName = cmbProfile.Text.Trim();
                if (string.IsNullOrEmpty(profileName))
                {
                    MessageBox.Show("No profile selected.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Confirm deletion
                DialogResult result = MessageBox.Show($"Are you sure you want to delete the profile \"{profileName}\"?", ForAllUnits.BoxWrg,  MessageBoxButtons.YesNo, MessageBoxIcon.Question);

                if (result != DialogResult.Yes)
                    return;

                // Build the profile file path
                string profilesFolder = Path.Combine(Application.StartupPath, "Profiles");
                string filePath = Path.Combine(profilesFolder, profileName + ".json");

                // Check if file exists before deleting
                if (!File.Exists(filePath))
                {
                    MessageBox.Show("The selected profile file does not exist.", ForAllUnits.BoxWrg,MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Delete the file
                File.Delete(filePath);

                // Remove the deleted profile from combo box
                cmbProfile.Items.Remove(profileName);
                cmbProfile.Text = string.Empty;

                ResetPlaceHolder();
                LoadProfile();

                labProfnum.Text = cmbProfile.Items.Count.ToString();

                MessageBox.Show("Profile deleted successfully.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to delete profile! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Failed to delete profile! " + ex.Message);
            }
        }
        void LoadProfileNames()
        {
            try
            {
                ProfileFolder();

                string profilesFolder = Path.Combine(Application.StartupPath, "Profiles");
                cmbProfile.Items.Clear();

                if (!Directory.Exists(profilesFolder))
                    return;

                string[] profileFiles = Directory.GetFiles(profilesFolder, "*.json");

                foreach (string file in profileFiles)
                {
                    string profileName = Path.GetFileNameWithoutExtension(file);
                    cmbProfile.Items.Add(profileName);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to load profile names! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Failed to load profile names! " + ex.Message);
            }
        }
        public void MastKey()
        {
            _SCR = 0;

            TruncateSecurePassword(); // Clear any previous sensitive data

            Zxcvbn zx = new Zxcvbn();
            char[] passwordChars = null;

            try
            {
                // Extract password securely from SecureString using AdapterCharString
                passwordChars = AdapterCharString.ToCharArray(secPasw.SecureText);
                int passwordLength = passwordChars.Length;

                if (passwordLength == 0)
                {
                    // Reset UI if password is empty
                    qualityProgressBar1.Value = qualityProgressBar1.Minimum;
                    labScor.Text = $"Chars 0 / 0 Bits / Score 0";
                    btnAcpt.Enabled = false;
                    btnPsw.Enabled = false;
                    btnPsw.Text = string.Empty;
                    return;
                }

                // Create a temporary string only for the internal matchers
                string tempPasswordString = new string(passwordChars);

                // Pass the string directly to hit the original evaluation method
                var result = zx.EvaluatePassword(tempPasswordString);

                // Scope variables to hold evaluation results safely
                int resultScore = result.Score;
                int entropyBits = Math.Min(Math.Max(Convert.ToInt32(result.Entropy), 0), qualityProgressBar1.Maximum);

                // Clamp entropy for progress bar display
                qualityProgressBar1.Value = entropyBits;

                // Update UI with password length, entropy, and score
                labScor.Text = $"Chars {passwordLength} / {entropyBits} Bits / Score {resultScore}";

                // Enable/disable buttons according to rules
                btnAcpt.Enabled = resultScore > 2;
                btnPsw.Enabled = passwordLength > 0;
                if (!btnPsw.Enabled) btnPsw.Text = string.Empty;

                // Protect _SCR in memory using ProtectedMemory
                _SCR = resultScore;
                byte[] scrBytes = BitConverter.GetBytes(_SCR);

                _SCR = BitConverter.ToInt32(scrBytes, 0);
                Array.Clear(scrBytes, 0, scrBytes.Length);
            }
            finally
            {
                // Clear passwordChars securely before leaving scope
                if (passwordChars != null)
                {
                    Array.Clear(passwordChars, 0, passwordChars.Length);
                    passwordChars = null;
                }

                // Force GC as optional extra hygiene
                try
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
                catch { }
            }
        }
        void ProfileFolder()
        {
            string profilesFolder = Path.Combine(Application.StartupPath, "Profiles");
            if (!Directory.Exists(profilesFolder))
                Directory.CreateDirectory(profilesFolder);
        }
        void ResetPlaceHolder()
        {
            btnDeleteProfile.Enabled = false;
            cmbProfile.Text = placeholderText;
            cmbProfile.ForeColor = Color.Gray;
            isPlaceholderActive = true;
            cmbProfile.SelectionStart = 0;
        }
        private void ProfileExists()
        {
            string profileName = cmbProfile.Text.Trim();
            string profilesFolder = Path.Combine(Application.StartupPath, "Profiles");
            string filePath = Path.Combine(profilesFolder, profileName + ".json");
            btnDeleteProfile.Enabled = false;
            if (File.Exists(filePath))
            {
                btnDeleteProfile.Enabled = true;
            }
        }

        #endregion Candidate Master Key

        #region Characters Set
        private void TabControl1_SelectedIndexChanged(object sender, EventArgs e)
        {
            // Check if the selected tab is the one dedicated to Pattern update
            if (tabControl1.SelectedTab == tabPage2)
            {
                try
                {
                    // Load or refresh patterns data inside the DataGridView
                    UpdatePatterns();
                }
                catch (Exception ex)
                {
                    // Show an error message if something goes wrong
                    MessageBox.Show("Error while loading patterns! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    CentralLog.LogException(ex, "PASSWORD GENERATOR", "Error while loading patterns! " + ex.Message);
                }
            }
            else if (tabControl1.SelectedTab == tabPage1) LoadPatterns();

            // Generation Profile
            if (tabControl1.SelectedIndex == 1)             
                SaveCurrentPatternSelection();
            
            if (tabControl1.SelectedIndex == 0)
                RestorePatternSelection();       
        }
        private void RbCharSet_CheckedChanged(object sender, EventArgs e)
        {
            nmUpDo.Enabled = true;
            picChr.Image = ForAllUnits.Ledgreen16;
            picPat.Image = ForAllUnits.Ledred16; ;
            GeneratePasswordButtonState();
        }
        private void ChkUppercase_CheckedChanged(object sender, EventArgs e)
        {
            GeneratePasswordButtonState();           
        }
        void GeneratePasswordButtonState()
        {
            if (rdbCharSet.Checked)
            {
                btnGen.Enabled = chkUppercase.Checked || chkLowercase.Checked || chkDigits.Checked || chkSymbols.Checked ||
                                 chkForceEachCategory.Checked || chkMinus.Checked || chkUnderline.Checked || chkSpace.Checked ||
                                 chkBrackets.Checked || chkLatin.Checked || chkCustomChars.Checked;
            }
        }
        void ApplyAdvancedOptions(Dictionary<string, bool> opts)
        {
            // Sync checkboxes in the main form with Advanced options
            chkCustomChars.Checked = opts["CustomChars"];
            chkForceEachCategory.Checked = opts["ForceEachCategory"];
            chkMinus.Checked = opts["Minus"];
            chkUnderline.Checked = opts["Underline"];
            chkSpace.Checked = opts["Space"];
            chkBrackets.Checked = opts["Brackets"];
            chkLatin.Checked = opts["Latin1"];
            chkPermute.Checked = opts["Permute"];            
            chkNoConsecutive.Checked = opts["NoConsecutive"];
        }
        void TruncateSecurePassword()
        {
            const int maxLength = 32;

            // Direct check on the unmanaged capsule length to avoid extracting text prematurely
            if (secPasw.SecureText.Length > maxLength)
            {
                char[] passwordChars = null;
                string fullString = null;
                string truncatedString = null;

                try
                {
                    // 1. Extract the plaintext into a mutable array using your Adapter
                    passwordChars = AdapterCharString.ToCharArray(secPasw.SecureText);

                    // 2. Generate the temporary full string only to clear the UI property later
                    fullString = new string(passwordChars);

                    // 3. Create the truncated string segment
                    truncatedString = new string(passwordChars, 0, maxLength);

                    // 4. Update the UI Text property with the truncated segment
                    secPasw.Text = truncatedString;

                    // 5. Rebuild the SecureText capsule using your extension method
                    // This safely injects the chars and freezes the state
                    secPasw.SecureText = truncatedString.ToSecureString(leaveOriginal: true, makeReadOnly: true);
                }
                finally
                {
                    // Deterministic erasure of the primary mutable char array
                    if (passwordChars != null)
                    {
                        Array.Clear(passwordChars, 0, passwordChars.Length);
                    }

                    // Destructively wipe the cleartext temporary strings instantly from the managed heap
                    if (fullString != null)
                    {
                        fullString.SecureClear();
                    }

                    if (truncatedString != null)
                    {
                        truncatedString.SecureClear();
                    }
                }
            }
        }

        #endregion Characters Set

        #region Geration Profiles
        private bool AreProfilesEqual(PasswordProfile a, PasswordProfile b)
        {
            return JsonConvert.SerializeObject(a) == JsonConvert.SerializeObject(b);
        }

        // Character profiles
        private void RbStandardPatterns_CheckedChanged(object sender, EventArgs e)
        {
            if (!rbStandardPatterns.Checked)
            {
                return;
            }

            SaveCurrentPatternSelection();

            LoadPatterns();

            RestorePatternSelection();

            EvaluateProfileChanges();
        }
        private void ChkUppercase_MouseUp(object sender, MouseEventArgs e)
        {
            if (cmbProfile.Text != placeholderText && rdbCharSet.Checked)
                EvaluateProfileChanges();
        }

        // Patterns profiles
        private void RbStandardPatterns_Click(object sender, EventArgs e)
        {
            Patternlaunch();         
            EvaluateProfileChanges();
        }

        // Character and Patterns
        private void CmbPatterns_DropDownClosed(object sender, EventArgs e)
        {
            Patternlaunch();
            EvaluateProfileChanges();            
        }
        private void CmbNmb_DropDownClosed(object sender, EventArgs e)
        {
            if (cmbProfile.Text != placeholderText)
                EvaluateProfileChanges();
        }
        void Patternlaunch()
        {
            // This procedure cannot be placed in the Change event of cmbPatterns.
            if (cmbPatterns.SelectedItem is PatternItem item)
            {
                labPattern.Text = item.Pattern;
                labPatternChr.Text = labPattern.Text.Length.ToString();
            }
        }
        void SaveCurrentPatternSelection()
        {
            if (rbStandardPatterns.Checked)
            {
                _standardPatternIndex = cmbPatterns.SelectedIndex;
            }
            else if (rbAdvancedPatterns.Checked)
            {
                _advancedPatternIndex = cmbPatterns.SelectedIndex;
            }
            else if (rbCorporatePatterns.Checked)
            {
                _corporatePatternIndex = cmbPatterns.SelectedIndex;
            }
        }
        private void RestorePatternSelection()
        {
            if (rbStandardPatterns.Checked)
            {
                if (_standardPatternIndex >= 0 &&
                    _standardPatternIndex < cmbPatterns.Items.Count)
                {
                    cmbPatterns.SelectedIndex = _standardPatternIndex;
                }
            }
            else if (rbAdvancedPatterns.Checked)
            {
                if (_advancedPatternIndex >= 0 &&
                    _advancedPatternIndex < cmbPatterns.Items.Count)
                {
                    cmbPatterns.SelectedIndex = _advancedPatternIndex;
                }
            }
            else if (rbCorporatePatterns.Checked)
            {
                if (_corporatePatternIndex >= 0 &&
                    _corporatePatternIndex < cmbPatterns.Items.Count)
                {
                    cmbPatterns.SelectedIndex = _corporatePatternIndex;
                }
            }
        }
        private void EvaluateProfileChanges()
        {
            if (_originalProfile == null)
            {
                btnSaveProfile.Enabled = false;
                return;
            }

            var currentProfile = BuildCurrentProfile();

            bool isDifferent = !AreProfilesEqual(_originalProfile, currentProfile);

            btnSaveProfile.Enabled = isDifferent;
        }
        private PasswordProfile BuildCurrentProfile()
        {
            return new PasswordProfile
            {
                Length = (int)nmUpDo.Value,
                UseUppercase = chkUppercase.Checked,
                UseLowercase = chkLowercase.Checked,
                UseDigits = chkDigits.Checked,
                UseSymbols = chkSymbols.Checked,
                UseMinus = chkMinus.Checked,
                UseUnderline = chkUnderline.Checked,
                UseSpace = chkSpace.Checked,
                UseBrackets = chkBrackets.Checked,
                UseLatin1 = chkLatin.Checked,
                UseCustomChars = chkCustomChars.Checked,
                CustomChars = txtCustomChars.Text,
                ForceEachCategory = chkForceEachCategory.Checked,
                NoConsecutive = chkNoConsecutive.Checked,
                PatternMode = rdbPattern.Checked,
                PatternText = labPattern.Text,
                Permute = chkPermute.Checked,
                AdvancedPattern = chkAdvancedPattern.Checked,
                PseudoNumberGen = cmbNmb.SelectedIndex,
                CharsetMode = rdbCharSet.Checked,
                StandardPatterns = rbStandardPatterns.Checked,
                AdvancedPatterns = rbAdvancedPatterns.Checked,
                CorporatePatterns = rbCorporatePatterns.Checked,
                UserEntropyDialog = chkUserEntropyDialog.Checked,
                Backup = chkBackup.Checked,
                BckStandard = chkBckStandard.Checked,
                BckAdvanced = chkBckAdvanced.Checked,
                BckCorporate = chkBckCorporate.Checked,
                UserFile = rbUserFile.Checked,
                OriginalFile = rbOriginalFile.Checked,
                PatternValue = cmbPatterns.Text
            };
        }

        #endregion Geration Profiles

        #region Patterns
        private void RbAdvancedPatterns_CheckedChanged(object sender, EventArgs e)
        {
            if (!rbAdvancedPatterns.Checked)
            {
                return;
            }

            SaveCurrentPatternSelection();

            LoadPatterns();

            RestorePatternSelection();

            EvaluateProfileChanges();
        }
        private void RbCorporatePatterns_CheckedChanged(object sender, EventArgs e)
        {
            if (!rbCorporatePatterns.Checked)
            {
                return;
            }

            SaveCurrentPatternSelection();

            LoadPatterns();

            RestorePatternSelection();

            EvaluateProfileChanges();
        }
        private void RbPattern_CheckedChanged(object sender, EventArgs e)
        {
            btnGen.Enabled = true;
            nmUpDo.Enabled = false;
            picChr.Image = ForAllUnits.Ledred16;
            picPat.Image = ForAllUnits.Ledgreen16;
        }
        private void RbFileStandardPatterns_CheckedChanged(object sender, EventArgs e)
        {
            UpdatePatterns();
            PatternTest();
            EnableFlag();
        }
        private void TxtPatternFlag_KeyPress(object sender, KeyPressEventArgs e)
        {
            // Allow only '0', '1', and control keys (backspace, delete)
            if (e.KeyChar != '0' && e.KeyChar != '1' && !char.IsControl(e.KeyChar))
            {
                e.Handled = true; // reject the input
                System.Media.SystemSounds.Beep.Play(); // optional feedback
                return;
            }

            // Prevent more than one character
            if (!char.IsControl(e.KeyChar) && txtPatternFlag.Text.Length >= 1)
            {
                e.Handled = true; // reject additional input
                System.Media.SystemSounds.Beep.Play(); // optional feedback
            }
        }
        private void BtnTest_Click(object sender, EventArgs e)
        {
            try
            {                
                // Reset buttons
                btnSave.Enabled = false;
                btnModif.Enabled = false;
                btnTest.Enabled = false;

                // Trim input fields
                string name = txtPatternName.Text.Trim().Replace("|", "");
                string rule = txtPatternRule.Text.Trim().Replace("|", "");
                string flag = txtPatternFlag.Text.Trim().Replace("|", "");

                // Construct pattern string
                string patternRecord;
                if (rbFileStandardPatterns.Checked || rbFileAdvancedPatterns.Checked)
                    patternRecord = $"{name}|{rule}";
                else if (rbFileCorporatePatterns.Checked)
                    patternRecord = $"{name}|{rule}|{(string.IsNullOrEmpty(flag) ? "0" : flag)}";
                else
                {
                    MessageBox.Show("Please select the pattern type.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                txtPreview.Text = patternRecord;

                if (string.IsNullOrEmpty(patternRecord))
                {
                    MessageBox.Show("The pattern cannot be empty.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    txtTestResult.Text = string.Empty;
                    return;
                }

                // Determine file type
                string fileType = rbFileStandardPatterns.Checked ? "Standard" :
                                  rbFileAdvancedPatterns.Checked ? "Advanced" : "Corporate";

                // Check pattern compatibility
                if (!CheckPatternModeCompatibility(patternRecord, fileType))
                {
                    MessageBox.Show("The pattern does not match the selected mode.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    txtTestResult.Text = string.Empty;
                    return;
                }

                // HARD VALIDATION ONLY FOR USER PATTERNS (SAFE MODE)
                bool isUserPattern = true;

                if (isUserPattern && !PatternHardValidator.IsValid(patternRecord))
                {
                    MessageBox.Show("Pattern rejected: structurally weak or invalid.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);

                    txtTestResult.Text = string.Empty;
                    return;
                }

                // Generate test password
                string previewPassword = GeneratePasswordForTest(patternRecord, fileType);
                if (string.IsNullOrEmpty(previewPassword))
                {
                    MessageBox.Show("Test failed! Check the pattern syntax or file type.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    txtTestResult.Text = string.Empty;
                    return;
                }

                txtTestResult.Text = previewPassword;

                // --- Check if pattern already exists in list ---
                bool existsInList = false;
                foreach (ListViewItem item in listPatterns.Items)
                {
                    string itemRecord = rbFileCorporatePatterns.Checked
                                        ? $"{item.SubItems[1].Text}|{item.SubItems[2].Text}|{item.SubItems[3].Text}"
                                        : $"{item.SubItems[1].Text}|{item.SubItems[2].Text}";

                    if (itemRecord.Equals(patternRecord, StringComparison.Ordinal))
                    {
                        existsInList = true;
                        break;
                    }
                }

                // --- Decide which button to enable ---
                if (listPatterns.SelectedItems.Count > 0)
                {
                    var sel = listPatterns.SelectedItems[0];

                    string selectedItemRecord = rbFileCorporatePatterns.Checked
                        ? $"{sel.SubItems[1].Text}|{sel.SubItems[2].Text}|{sel.SubItems[3].Text}"
                        : $"{sel.SubItems[1].Text}|{sel.SubItems[2].Text}";

                    if (!selectedItemRecord.Equals(patternRecord, StringComparison.Ordinal))
                        btnModif.Enabled = true;
                }
                else
                {
                    if (!existsInList)
                        btnSave.Enabled = true;
                }

                MessageBox.Show("Test passed! Pattern is valid.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);

                btnTest.Enabled = true;
                listPatterns.Focus();                
            }
            catch (Exception ex)
            {
                MessageBox.Show("An error occurred during pattern test! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "An error occurred during pattern test! " + ex.Message);
                txtTestResult.Text = string.Empty;
            }
        }
        private void BtnSave_Click(object sender, EventArgs e)
        {
            try
            {
                string patternRecord = txtPreview.Text.Trim();
                if (string.IsNullOrEmpty(patternRecord))
                {
                    MessageBox.Show("No pattern to save.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Ensure the Patterns folder exists
                string basePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Patterns");
                Directory.CreateDirectory(basePath);

                // Select correct file path
                string filePath = string.Empty;
                if (rbFileStandardPatterns.Checked)
                    filePath = Path.Combine(basePath, "StandardPatterns.txt");
                else if (rbFileAdvancedPatterns.Checked)
                    filePath = Path.Combine(basePath, "AdvancedPatterns.txt");
                else if (rbFileCorporatePatterns.Checked)
                    filePath = Path.Combine(basePath, "CorporatePatterns.txt");
                else
                {
                    MessageBox.Show("Please select the pattern type.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (PatternExists(patternRecord))
                {
                    MessageBox.Show("Duplicate pattern detected. Save aborted.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Add new pattern to listPatterns with image index 0
                string[] parts = patternRecord.Split('|');
                ListViewItem newItem = new ListViewItem("", 0); // image index 0
                foreach (string p in parts)
                    newItem.SubItems.Add(p);
                listPatterns.Items.Add(newItem);

                // Rewrite the file with all patterns from listPatterns
                using (StreamWriter writer = new StreamWriter(filePath, false, Encoding.UTF8))
                {
                    foreach (ListViewItem item in listPatterns.Items)
                    {
                        var rowParts = new List<string>();
                        for (int i = 1; i < item.SubItems.Count; i++) // skip image column
                            rowParts.Add(item.SubItems[i].Text);
                        writer.WriteLine(string.Join("|", rowParts));
                    }
                }
                ResetAfterOperation();
                if (chkBackup.Checked) BackupPatternFile();

                labCount.Text = listPatterns.Items.Count.ToString();
                MessageBox.Show("Pattern saved successfully.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
                listPatterns.EnsureVisible(listPatterns.Items.Count - 1);
                listPatterns.Focus();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving pattern! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Error saving pattern! " + ex.Message);
            }
        }
        private void BtnModif_Click(object sender, EventArgs e)
        {
            // Check that an item is selected
            if (listPatterns.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a pattern to modify.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Get the selected ListView item
            ListViewItem selectedItem = listPatterns.SelectedItems[0];

            // Read and trim input fields
            string name = txtPatternName.Text?.Trim() ?? string.Empty;
            string rule = txtPatternRule.Text?.Trim() ?? string.Empty;
            string flag = txtPatternFlag.Text?.Trim() ?? string.Empty;

            bool isCorporate = rbFileCorporatePatterns.Checked;

            // Validate required fields depending on file type
            if (isCorporate)
            {
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(rule) || string.IsNullOrWhiteSpace(flag))
                {
                    MessageBox.Show("All fields must be filled.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            else
            {
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(rule))
                {
                    MessageBox.Show("Both fields must be filled.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }

            // Ensure selected ListViewItem has at least 4 subitems (index 0..3)
            // We keep index 0 untouched (your layout uses subitems starting at index 1 for name)
            while (selectedItem.SubItems.Count < 4)
                selectedItem.SubItems.Add(string.Empty);

            // --- UPDATE THE SELECTED ITEM (respecting your mapping) ---
            // Mapping required by you:
            // [1] = txtPatternName, [2] = txtPatternRule, [3] = txtPatternFlag
            selectedItem.SubItems[1].Text = name;
            selectedItem.SubItems[2].Text = rule;
            if (isCorporate)
                selectedItem.SubItems[3].Text = flag;

            // Determine the target file path based on selected RadioButton
            string filePath;
            if (rbFileStandardPatterns.Checked)
                filePath = Path.Combine(Application.StartupPath, "StandardPatterns.txt");
            else if (rbFileAdvancedPatterns.Checked)
                filePath = Path.Combine(Application.StartupPath, "AdvancedPatterns.txt");
            else
                filePath = Path.Combine(Application.StartupPath, "CorporatePatterns.txt");

            try
            {
                string patternsDir = Path.Combine(Application.StartupPath, "Patterns");

                if (rbFileStandardPatterns.Checked)
                    filePath = Path.Combine(patternsDir, "StandardPatterns.txt");
                else if (rbFileAdvancedPatterns.Checked)
                    filePath = Path.Combine(patternsDir, "AdvancedPatterns.txt");
                else if (rbFileCorporatePatterns.Checked)
                    filePath = Path.Combine(patternsDir, "CorporatePatterns.txt");
                else
                    throw new InvalidOperationException("No pattern file type selected.");

                // Save the whole ListView to the file
                using (var writer = new StreamWriter(filePath, false))
                {
                    foreach (ListViewItem item in listPatterns.Items)
                    {
                        string outName = item.SubItems.Count > 1 ? item.SubItems[1].Text : string.Empty;
                        string outRule = item.SubItems.Count > 2 ? item.SubItems[2].Text : string.Empty;

                        if (rbFileCorporatePatterns.Checked)
                        {
                            string outFlag = item.SubItems.Count > 3 ? item.SubItems[3].Text : string.Empty;
                            writer.WriteLine($"{outName}|{outRule}|{outFlag}");
                        }
                        else
                        {
                            writer.WriteLine($"{outName}|{outRule}");
                        }
                    }
                }
                ResetAfterOperation();
                if (chkBackup.Checked) BackupPatternFile();
                MessageBox.Show("Patterns file updated successfully!", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving patterns file! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Error saving patterns file! " + ex.Message);
            }
        }
        private void BtnDelete_Click(object sender, EventArgs e)
        {
            try
            {
                // Ensure at least one pattern is selected
                if (listPatterns.SelectedItems.Count == 0)
                {
                    MessageBox.Show("Please select one or more patterns to delete.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Prevent deletion if it would remove all items
                if (listPatterns.SelectedItems.Count == listPatterns.Items.Count)
                {
                    MessageBox.Show("Cannot delete all patterns. At least one pattern must remain.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Confirm deletion
                DialogResult result = MessageBox.Show($"Are you sure you want to delete the selected {listPatterns.SelectedItems.Count} patterns)?", ForAllUnits.BoxConf,
                                      MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                
                if (result != DialogResult.Yes)
                {
                    listPatterns.Focus();
                    return;
                }

                // Collect selected items
                List<ListViewItem> itemsToDelete = new List<ListViewItem>();
                foreach (ListViewItem item in listPatterns.SelectedItems)
                    itemsToDelete.Add(item);

                // Remove items from ListView
                foreach (var item in itemsToDelete)
                    listPatterns.Items.Remove(item);

                // Ensure the Patterns folder exists
                string basePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Patterns");
                Directory.CreateDirectory(basePath);

                // Determine file path based on selected RadioButton
                string filePath = string.Empty;
                if (rbFileStandardPatterns.Checked)
                    filePath = Path.Combine(basePath, "StandardPatterns.txt");
                else if (rbFileAdvancedPatterns.Checked)
                    filePath = Path.Combine(basePath, "AdvancedPatterns.txt");
                else if (rbFileCorporatePatterns.Checked)
                    filePath = Path.Combine(basePath, "CorporatePatterns.txt");

                if (!string.IsNullOrEmpty(filePath))
                {
                    // Rewrite the file with remaining items
                    using (StreamWriter writer = new StreamWriter(filePath, false, Encoding.UTF8))
                    {
                        foreach (ListViewItem item in listPatterns.Items)
                        {
                            var rowParts = new List<string>();
                            for (int i = 1; i < item.SubItems.Count; i++) // skip icon column
                                rowParts.Add(item.SubItems[i].Text);

                            writer.WriteLine(string.Join("|", rowParts));
                        }
                    }
                }

                labCount.Text = listPatterns.Items.Count.ToString();
                ResetAfterOperation();

                MessageBox.Show("Selected pattern(s) deleted successfully.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error while deleting pattern(s)! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Error while deleting pattern(s)! " + ex.Message);
            }
        }
        private void BtnClear_Click(object sender, EventArgs e)
        {
            ResetAfterOperation();
        }
        private void ListPatterns_Click(object sender, EventArgs e)
        {
            btnTest.Enabled = false;
        }
        private void ListPatterns_DoubleClick(object sender, EventArgs e)
        {
            try
            {
                btnSave.Enabled = false;
                btnModif.Enabled = false;
                if (listPatterns.SelectedItems.Count == 0)
                    return;

                txtTestResult.Text = string.Empty; ;
                // Get the selected item
                ListViewItem selectedItem = listPatterns.SelectedItems[0];

                // Build the record skipping the first subitem (icon column)
                var fullRecord = new List<string>();
                for (int i = 1; i < selectedItem.SubItems.Count; i++)
                {
                    fullRecord.Add(selectedItem.SubItems[i].Text ?? string.Empty);
                }

                // Set the TextBox to contain the complete record
                txtPreview.Text = string.Join("|", fullRecord);

                // Split into individual textboxes based on selected mode
                if (rbFileStandardPatterns.Checked || rbFileAdvancedPatterns.Checked)
                {
                    txtPatternName.Text = fullRecord.ElementAtOrDefault(0) ?? string.Empty;
                    txtPatternRule.Text = fullRecord.ElementAtOrDefault(1) ?? string.Empty;
                    txtPatternFlag.Clear();
                }
                else if (rbFileCorporatePatterns.Checked)
                {
                    txtPatternName.Text = fullRecord.ElementAtOrDefault(0) ?? string.Empty;
                    txtPatternRule.Text = fullRecord.ElementAtOrDefault(1) ?? string.Empty;
                    txtPatternFlag.Text = fullRecord.ElementAtOrDefault(2) ?? string.Empty;
                }

                if (rbFileStandardPatterns.Checked) _PTR_TEST = 0;
                if (rbFileAdvancedPatterns.Checked) _PTR_TEST = 1;
                if (rbFileCorporatePatterns.Checked) _PTR_TEST = 2;

                _originalPatternRecord = txtPreview.Text.Trim();
                btnTest.Enabled = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error while loading the full record into TextBox! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Error while loading the full record into TextBox! " + ex.Message);
            }
        }
        private void ListPatterns_MouseUp(object sender, MouseEventArgs e)
        {
            btnDelete.Enabled = false;
            if (listPatterns.HitTest(e.X, e.Y).Item != null)
                btnDelete.Enabled = true;
        }
        private void TxtTestResult_TextChanged(object sender, EventArgs e)
        {
            txtTestResult.BackColor = Color.White;
            if (txtTestResult.Text != string.Empty) txtTestResult.BackColor = Color.Yellow;
            labTestCount.Text = txtTestResult.Text.Length.ToString();
        }
        private void ChkBckStandard_CheckedChanged(object sender, EventArgs e)
        {
            UpdateRestoreButtonState();
        }
        private void TxtPreview_TextChanged(object sender, EventArgs e)
        {
            txtPreview.BackColor = Color.White;
            if (txtPreview.Text != string.Empty)
                txtPreview.BackColor = Color.Yellow;
        }

        // Backup
        private void BackupPatternFile()
        {
            try
            {
                // Base folder for pattern files
                string patternsFolder = Path.Combine(Application.StartupPath, "Patterns");
                // Backup folder inside Patterns
                string backupFolder = Path.Combine(patternsFolder, "Backup");

                // Ensure the Backup folder exists
                if (!Directory.Exists(backupFolder))
                {
                    Directory.CreateDirectory(backupFolder);
                }

                // Determine which pattern file is selected
                string fileName;

                if (rbFileStandardPatterns.Checked)
                {
                    fileName = "StandardPatterns.txt";
                }
                else if (rbFileAdvancedPatterns.Checked)
                {
                    fileName = "AdvancedPatterns.txt";
                }
                else if (rbFileCorporatePatterns.Checked)
                {
                    fileName = "CorporatePatterns.txt";
                }
                else
                {
                    MessageBox.Show("No pattern file selected.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Build full source and destination paths
                string sourceFilePath = Path.Combine(patternsFolder, fileName);
                string destinationFilePath = Path.Combine(backupFolder, fileName);

                // Copy the file to the Backup folder (overwrites if already exists)
                File.Copy(sourceFilePath, destinationFilePath, true);

                // Inform the user that the backup was successful
                MessageBox.Show($"Backup of {fileName} completed successfully.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                // Handle and display any errors during the backup process
                MessageBox.Show("An error occurred during backup! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "An error occurred during backup! " + ex.Message);
            }
        }

        // Restore
        private void BtnRestore_Click(object sender, EventArgs e)
        {
            try
            {
                // Define base and backup paths
                string basePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Patterns");
                string backupPath = Path.Combine(basePath, "Backup");

                if (rbUserFile.Checked && !File.Exists(Path.Combine(backupPath, "StandardPatterns.txt"))
                                       && !File.Exists(Path.Combine(backupPath, "AdvancedPatterns.txt"))
                                       && !File.Exists(Path.Combine(backupPath, "CorporatePatterns.txt")))
                {
                    MessageBox.Show("There are no files to restore.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                else if (rbOriginalFile.Checked && !File.Exists(Path.Combine(backupPath, "StandardPatterns.sbck"))
                                       && !File.Exists(Path.Combine(backupPath, "AdvancedPatterns.sbck"))
                                       && !File.Exists(Path.Combine(backupPath, "CorporatePatterns.sbck")))
                {
                    MessageBox.Show("There are no files to restore.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Check that at least one radio button is selected
                if (!rbUserFile.Checked && !rbOriginalFile.Checked)
                {
                    MessageBox.Show("Please select the type of backup to restore.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Check that at least one checkbox is selected
                if (!chkBckStandard.Checked && !chkBckAdvanced.Checked && !chkBckCorporate.Checked)
                {
                    MessageBox.Show("Please select at least one pattern file to restore.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                bool restoredAnyFile = false; // Flag to track if at least one file was restored

                // Restore StandardPatterns if selected
                if (chkBckStandard.Checked)
                {
                    string sourceFile = rbOriginalFile.Checked ? Path.Combine(backupPath, "StandardPatterns.sbck")
                                                                : Path.Combine(backupPath, "StandardPatterns.txt");
                    if (File.Exists(sourceFile))
                    {
                        string destFile = Path.Combine(basePath, "StandardPatterns.txt");
                        File.Copy(sourceFile, destFile, true);
                        restoredAnyFile = true;
                    }
                    else
                    {
                        MessageBox.Show($"Backup file {Path.GetFileName(sourceFile)} is missing.\nThis file will be skipped.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }

                // Restore AdvancedPatterns if selected
                if (chkBckAdvanced.Checked)
                {
                    string sourceFile = rbOriginalFile.Checked ? Path.Combine(backupPath, "AdvancedPatterns.sbck")
                                                                : Path.Combine(backupPath, "AdvancedPatterns.txt");
                    if (File.Exists(sourceFile))
                    {
                        string destFile = Path.Combine(basePath, "AdvancedPatterns.txt");
                        File.Copy(sourceFile, destFile, true);
                        restoredAnyFile = true;
                    }
                    else
                    {
                        MessageBox.Show($"Backup file {Path.GetFileName(sourceFile)} is missing.\nThis file will be skipped.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }

                // Restore CorporatePatterns if selected
                if (chkBckCorporate.Checked)
                {
                    string sourceFile = rbOriginalFile.Checked ? Path.Combine(backupPath, "CorporatePatterns.sbck")
                                                                : Path.Combine(backupPath, "CorporatePatterns.txt");
                    if (File.Exists(sourceFile))
                    {
                        string destFile = Path.Combine(basePath, "CorporatePatterns.txt");
                        File.Copy(sourceFile, destFile, true);
                        restoredAnyFile = true;
                    }
                    else
                    {
                        MessageBox.Show($"Backup file {Path.GetFileName(sourceFile)} is missing.\nThis file will be skipped.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }

                // Show success message if at least one file was restored
                if (restoredAnyFile)
                {
                    MessageBox.Show("Selected pattern files restored successfully.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    UpdatePatterns();
                }
                else
                {
                    MessageBox.Show("No backup files were restored because none of the selected files exist.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error restoring pattern files! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "Error restoring pattern files! " + ex.Message);
            }
        }
        void LoadPatterns()
        {
            string folder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Patterns");
            string fileName = null;

            if (rbStandardPatterns.Checked)
            {
                fileName = "StandardPatterns.txt";
                chkAdvancedPattern.Checked = false;
            }
            else if (rbAdvancedPatterns.Checked)
            {
                fileName = "AdvancedPatterns.txt";
                chkAdvancedPattern.Checked = true;
            }

            else if (rbCorporatePatterns.Checked)
            {
                fileName = "CorporatePatterns.txt";
                chkAdvancedPattern.Checked = false;
            }
            else
                return; // no radio selected

            string patternsFile = Path.Combine(folder, fileName);

            cmbPatterns.Items.Clear();

            if (!File.Exists(patternsFile))
                return;

            var lines = File.ReadAllLines(patternsFile);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                string[] parts = line.Split('|');

                if (parts.Length >= 2)
                {
                    string name = parts[0].Trim();
                    string pattern = parts[1].Trim();
                    bool advanced = false;

                    // if the third option exists, interpret as Advanced flag
                    if (parts.Length == 3)
                        bool.TryParse(parts[2].Trim(), out advanced);

                    cmbPatterns.Items.Add(new PatternItem(name, pattern, advanced));
                }
            }

            labPatCount.Text = cmbPatterns.Items.Count.ToString();

            if (cmbPatterns.Items.Count > 0)
                cmbPatterns.SelectedIndex = 0;
        }
        void UpdatePatterns()
        {
            try
            {
                // Clear previous content
                listPatterns.BeginUpdate();
                listPatterns.Clear();
                listPatterns.View = View.Details;
                listPatterns.FullRowSelect = true;
                listPatterns.GridLines = true;

                // Ensure the ListView uses the ImageList
                listPatterns.SmallImageList = imageList1;

                // Determine which file to load
                string filePath = string.Empty;

                if (rbFileStandardPatterns.Checked)
                    filePath = Path.Combine(Application.StartupPath, "Patterns", "StandardPatterns.txt");
                else if (rbFileAdvancedPatterns.Checked)
                    filePath = Path.Combine(Application.StartupPath, "Patterns", "AdvancedPatterns.txt");
                else if (rbFileCorporatePatterns.Checked)
                    filePath = Path.Combine(Application.StartupPath, "Patterns", "CorporatePatterns.txt");

                if (string.IsNullOrEmpty(filePath))
                {
                    listPatterns.EndUpdate();
                    return;
                }

                if (!File.Exists(filePath))
                {
                    listPatterns.EndUpdate();

                    if (!fileErrorShown)
                    {
                        fileErrorShown = true;
                        MessageBox.Show("The selected pattern file does not exist.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    return;
                }
                else
                {
                    // Reset the flag once a valid file is found
                    fileErrorShown = false;
                }

                string[] lines = File.ReadAllLines(filePath);

                // Define fixed columns
                listPatterns.Columns.Clear();
                if (rbFileCorporatePatterns.Checked)
                {
                    listPatterns.Columns.Add("ID", 30, HorizontalAlignment.Left);
                    listPatterns.Columns.Add("Pattern Name", 180, HorizontalAlignment.Left);
                    listPatterns.Columns.Add("Pattern Rule", 300, HorizontalAlignment.Left);
                    listPatterns.Columns.Add("Flag", 35, HorizontalAlignment.Center);
                }
                else
                {
                    listPatterns.Columns.Add("ID", 30, HorizontalAlignment.Left);
                    listPatterns.Columns.Add("Pattern Name", 180, HorizontalAlignment.Left);
                    listPatterns.Columns.Add("Pattern Rule", 300, HorizontalAlignment.Left);
                }

                // Populate ListView
                foreach (string line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    string[] parts = line.Split('|');

                    if (rbFileCorporatePatterns.Checked)
                    {
                        if (parts.Length == 3)
                        {
                            ListViewItem item = new ListViewItem("", 0); // empty text + icon index 0
                            item.SubItems.Add(parts[0]);
                            item.SubItems.Add(parts[1]);
                            item.SubItems.Add(parts[2]);
                            listPatterns.Items.Add(item);
                        }
                    }
                    else
                    {
                        if (parts.Length == 2)
                        {
                            ListViewItem item = new ListViewItem("", 0);
                            item.SubItems.Add(parts[0]);
                            item.SubItems.Add(parts[1]);
                            listPatterns.Items.Add(item);
                        }
                    }
                }

                listPatterns.EndUpdate();
                labCount.Text = listPatterns.Items.Count.ToString();
            }
            catch (Exception ex)
            {
                MessageBox.Show("An error occurred while updating patterns! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "An error occurred while updating patterns! " + ex.Message);
            }
        }
        void PatternTest()
        {
            btnTest.Enabled = false;
            btnDelete.Enabled = false;
            if (rbFileStandardPatterns.Checked && _PTR_TEST == 0 && txtPatternName.Text != string.Empty && txtPatternRule.Text != string.Empty)
            {
                btnTest.Enabled = true;
            }
            if (rbFileAdvancedPatterns.Checked && _PTR_TEST == 1 && txtPatternName.Text != string.Empty && txtPatternRule.Text != string.Empty)
            {
                btnTest.Enabled = true;
            }
            if (rbFileCorporatePatterns.Checked && _PTR_TEST == 2 && txtPatternName.Text != string.Empty && txtPatternRule.Text != string.Empty
                                                && txtPatternFlag.Text != string.Empty)
            {
                btnTest.Enabled = true;
            }
        }
        void EnableFlag()
        {
            txtPatternFlag.Enabled = false;
            labPatternFlag.ForeColor = Color.Gray;
            if (rbFileCorporatePatterns.Checked)
            {
                txtPatternFlag.Enabled = true;
                labPatternFlag.ForeColor = Color.Black;
            }
        }
        void ResetAfterOperation()
        {
            listPatterns.SelectedItems.Clear();
            btnSave.Enabled = false;
            btnModif.Enabled = false;
            btnDelete.Enabled = false;
            txtTestResult.Text = string.Empty;
            txtPreview.Text = string.Empty;
            txtPatternName.Clear();
            txtPatternRule.Clear();
            txtPatternFlag.Clear();
            txtPreview.Text = string.Empty;
            txtTestResult.Text = string.Empty;
            labPatternRuleChr.Text = "0";
        }
        void UpdateBtnTest()
        {
            // Reset buttons
            btnTest.Enabled = false;
            btnModif.Enabled = false;

            // Update the character counter for the Rule textbox
            labPatternRuleChr.Text = txtPatternRule.TextLength.ToString();

            if (rbFileStandardPatterns.Checked || rbFileAdvancedPatterns.Checked)
            {
                // Enable btnTest only if Name and Rule have text and Rule has at least 4 chars
                btnTest.Enabled = !string.IsNullOrWhiteSpace(txtPatternName.Text) &&
                                  !string.IsNullOrWhiteSpace(txtPatternRule.Text) &&
                                  txtPatternRule.TextLength > 3;
            }
            else if (rbFileCorporatePatterns.Checked)
            {
                // Corporate patterns: Name, Rule, Flag must have text and Rule at least 4 chars
                btnTest.Enabled = !string.IsNullOrWhiteSpace(txtPatternName.Text) &&
                                  !string.IsNullOrWhiteSpace(txtPatternRule.Text) &&
                                  !string.IsNullOrWhiteSpace(txtPatternFlag.Text) &&
                                  txtPatternRule.TextLength > 3;
            }

            // btnClear mirrors the state of btnTest
            btnClear.Enabled = btnTest.Enabled;
        }
        void UpdateRestoreButtonState()
        {
            btnRestore.Enabled = chkBckStandard.Checked || chkBckAdvanced.Checked || chkBckCorporate.Checked;
        }
        void PatternFolder()
        {
            // Build paths for Patterns and Backup folders
            string patternsDir = Path.Combine(Application.StartupPath, "Patterns");
            string backupDir = Path.Combine(patternsDir, "Backup");

            // Create Patterns folder if it doesn't exist
            if (!Directory.Exists(patternsDir))
                Directory.CreateDirectory(patternsDir);

            // Create Backup folder if it doesn't exist
            if (!Directory.Exists(backupDir))
                Directory.CreateDirectory(backupDir);
        }
        private bool PatternExists(string patternRecord)
        {
            foreach (ListViewItem item in listPatterns.Items)
            {
                string existing = string.Join("|", item.SubItems.Cast<ListViewItem.ListViewSubItem>()
                    .Skip(1).Select(s => s.Text));

                if (string.Equals(existing, patternRecord, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
        private bool CheckPatternModeCompatibility(string patternRecord, string selectedMode)
        {
            if (string.IsNullOrWhiteSpace(patternRecord) || string.IsNullOrWhiteSpace(selectedMode))
                return false;

            string[] fields = patternRecord.Split('|');
            if (fields.Length < 2)
                return false;

            string rulePart = fields[1].Trim();

            // Detect type by rule syntax
            bool isCorporate = fields.Length == 3 || rulePart.StartsWith("L=", StringComparison.OrdinalIgnoreCase) || rulePart.StartsWith("Type=passphrase", StringComparison.OrdinalIgnoreCase);
            bool isAdvanced = rulePart.IndexOfAny(new char[] { '[', ']', '{', '}' }) >= 0 && !isCorporate;
            bool isStandard = !isCorporate && !isAdvanced;

            switch (selectedMode)
            {
                case "Standard":
                    return isStandard;
                case "Advanced":
                    return isAdvanced;
                case "Corporate":
                    return isCorporate;
                default:
                    return false;
            }
        }
        private string GeneratePasswordForTest(string patternRecord, string fileType)
        {
            if (string.IsNullOrWhiteSpace(patternRecord)) return null;

            string description;
            string ruleString;

            // Split pattern into description and rule
            var parts = patternRecord.Split('|');
            description = string.IsNullOrWhiteSpace(parts[0]) ? "Custom" : parts[0].Trim();
            ruleString = parts.Length > 1 ? parts[1].Trim() : "";

            if (string.IsNullOrEmpty(ruleString)) return null;

            const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string LOWER = "abcdefghijklmnopqrstuvwxyz";
            const string DIGITS = "0123456789";
            const string SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?";

            var checkboxCharSet = new List<char>();
            if (chkUppercase.Checked) checkboxCharSet.AddRange(UPPER);
            if (chkLowercase.Checked) checkboxCharSet.AddRange(LOWER);
            if (chkDigits.Checked) checkboxCharSet.AddRange(DIGITS);
            if (chkSymbols.Checked) checkboxCharSet.AddRange(SYMBOLS);
            if (chkMinus.Checked) checkboxCharSet.Add('-');
            if (chkUnderline.Checked) checkboxCharSet.Add('_');
            if (chkSpace.Checked) checkboxCharSet.Add(' ');
            if (chkBrackets.Checked) checkboxCharSet.AddRange("()[]{}<>");
            if (chkLatin.Checked)
                for (int cp = 0x00A0; cp <= 0x00FF; cp++) checkboxCharSet.Add((char)cp);
            if (chkCustomChars.Checked && !string.IsNullOrEmpty(txtCustomChars.Text))
                checkboxCharSet.AddRange(txtCustomChars.Text);

            var passwordChars = new List<char>();
            var rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
            byte NextByte()
            {
                var b = new byte[1];
                rng.GetBytes(b);
                return b[0];
            }            

            int CountInCategory(List<char> list, string category)
            {
                int cnt = 0;
                foreach (var ch in list)
                    if (category.IndexOf(ch) >= 0) cnt++;
                return cnt;
            }

            string ExpandRange(string token)
            {
                var charsList = new List<char>();
                for (int i = 0; i < token.Length; i++)
                {
                    if (i + 2 < token.Length && token[i + 1] == '-')
                    {
                        char start = token[i];
                        char end = token[i + 2];
                        if (start <= end)
                            for (char c = start; c <= end; c++) charsList.Add(c);
                        else
                            for (char c = start; c >= end; c--) charsList.Add(c);
                        i += 2;
                    }
                    else
                    {
                        charsList.Add(token[i]);
                    }
                }
                return new string(charsList.ToArray());
            }

            bool advancedAllowed = fileType.Equals("Advanced", StringComparison.OrdinalIgnoreCase) || chkAdvancedPattern.Checked;

            // ---------- FUNCTION TO EXTRACT FIXED PREFIX ----------
            string ExtractFixedPrefix(ref string pattern)
            {
                if (string.IsNullOrEmpty(pattern)) return "";

                int idx = 0;
                while (idx < pattern.Length && pattern[idx] != '[' && pattern[idx] != '{')
                    idx++;

                string fixedPrefix = pattern.Substring(0, idx);
                pattern = pattern.Substring(idx); // Remove the prefix from pattern
                return fixedPrefix;
            }

            try
            {
                if (fileType.Equals("Corporate", StringComparison.OrdinalIgnoreCase))
                {
                    if (!PatternValidator.ValidateCorporatePattern(ruleString)) return null;

                    // ---------- CORPORATE PATTERN HANDLING ----------
                    if (ruleString.StartsWith("Type=passphrase", StringComparison.OrdinalIgnoreCase))
                    {
                        var partsPass = ruleString.Split(';');
                        int wordCount = 4;
                        string separator = "-";
                        foreach (var part in partsPass)
                        {
                            if (part.StartsWith("Words=")) int.TryParse(part.Substring(6), out wordCount);
                            else if (part.StartsWith("Separator=")) separator = part.Substring(10);
                        }
                        for (int w = 0; w < wordCount; w++)
                        {
                            int wordLen = 3 + (NextByte() % 4);
                            for (int j = 0; j < wordLen; j++)
                                passwordChars.Add(LOWER[NextByte() % LOWER.Length]);
                            if (w < wordCount - 1 && !string.IsNullOrEmpty(separator))
                                foreach (char sep in separator) passwordChars.Add(sep);
                        }
                    }
                    else if (ruleString.StartsWith("L=", StringComparison.OrdinalIgnoreCase))
                    {
                        int targetLength = 0, minUpper = 0, minLower = 0, minDigits = 0, minSymbols = 0;
                        bool noConsecutive = false;
                        string[] partsL = ruleString.Split(';');
                        foreach (var part in partsL)
                        {
                            if (part.StartsWith("L=")) int.TryParse(part.Substring(2), out targetLength);
                            else if (part.StartsWith("U>=")) int.TryParse(part.Substring(3), out minUpper);
                            else if (part.StartsWith("Lw>=")) int.TryParse(part.Substring(4), out minLower);
                            else if (part.StartsWith("D>=")) int.TryParse(part.Substring(3), out minDigits);
                            else if (part.StartsWith("S>=")) int.TryParse(part.Substring(3), out minSymbols);
                            else if (part.Equals("NoConsecutive=1", StringComparison.OrdinalIgnoreCase)) noConsecutive = true;
                        }

                        while (CountInCategory(passwordChars, UPPER) < minUpper && passwordChars.Count < targetLength)
                            passwordChars.Add(UPPER[NextByte() % UPPER.Length]);
                        while (CountInCategory(passwordChars, LOWER) < minLower && passwordChars.Count < targetLength)
                            passwordChars.Add(LOWER[NextByte() % LOWER.Length]);
                        while (CountInCategory(passwordChars, DIGITS) < minDigits && passwordChars.Count < targetLength)
                            passwordChars.Add(DIGITS[NextByte() % DIGITS.Length]);
                        while (CountInCategory(passwordChars, SYMBOLS) < minSymbols && passwordChars.Count < targetLength)
                            passwordChars.Add(SYMBOLS[NextByte() % SYMBOLS.Length]);

                        string allChars = UPPER + LOWER + DIGITS + SYMBOLS;
                        while (passwordChars.Count < targetLength)
                        {
                            char sel = allChars[NextByte() % allChars.Length];
                            int safety = 0;
                            while (noConsecutive && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safety < 64)
                            {
                                sel = allChars[NextByte() % allChars.Length];
                                safety++;
                            }
                            passwordChars.Add(sel);
                        }
                    }
                    else
                    {
                        // Regex-based corporate pattern handling
                        var regex = new System.Text.RegularExpressions.Regex(@"(\[[^\]]+\]|[^\[\]]+)(\{(\d+),?(\d+)?\})?");
                        var matches = regex.Matches(ruleString);
                        foreach (System.Text.RegularExpressions.Match m in matches)
                        {
                            string token = m.Groups[1].Value;
                            int minRepeat = 1, maxRepeat = 1;
                            if (m.Groups[3].Success)
                            {
                                // Enforce InvariantCulture to safely parse the minimum repeat constraint from the third regex group
                                minRepeat = Math.Max(1, int.Parse(m.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture));
                            }

                            if (m.Groups[4].Success)
                            {
                                // Enforce InvariantCulture to safely parse the maximum repeat constraint from the fourth regex group
                                maxRepeat = Math.Max(minRepeat, int.Parse(m.Groups[4].Value, System.Globalization.CultureInfo.InvariantCulture));
                            }

                            string charSet = token.StartsWith("[") && token.EndsWith("]") ? ExpandRange(token.Substring(1, token.Length - 2)) : token;
                            if (string.IsNullOrEmpty(charSet)) continue;

                            int repeat = minRepeat + (maxRepeat > minRepeat ? NextByte() % (maxRepeat - minRepeat + 1) : 0);
                            for (int r = 0; r < repeat; r++)
                                passwordChars.Add(charSet[NextByte() % charSet.Length]);
                        }
                    }
                }
                else
                {
                    // ---------- STANDARD / ADVANCED ----------
                    if (advancedAllowed)
                    {
                        // Validate advanced pattern
                        if (!PatternValidator.ValidateAdvancedPattern(ruleString)) return null;

                        // Extract fixed prefix
                        string fixedPrefix = ExtractFixedPrefix(ref ruleString);
                        foreach (char c in fixedPrefix) passwordChars.Add(c);

                        var regex = new System.Text.RegularExpressions.Regex(@"(\[[^\]]+\]|[^\[\]]+)(\{(\d+),?(\d+)?\})?");
                        var matches = regex.Matches(ruleString);
                        foreach (System.Text.RegularExpressions.Match m in matches)
                        {
                            string token = m.Groups[1].Value;
                            int minRepeat = 1, maxRepeat = 1;
                            if (m.Groups[3].Success)
                            {
                                // Enforce InvariantCulture to safely parse the minimum repeat constraint from the third regex group
                                minRepeat = Math.Max(1, int.Parse(m.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture));
                            }

                            if (m.Groups[4].Success)
                            {
                                // Enforce InvariantCulture to safely parse the maximum repeat constraint from the fourth regex group
                                maxRepeat = Math.Max(minRepeat, int.Parse(m.Groups[4].Value, System.Globalization.CultureInfo.InvariantCulture));
                            }

                            string charSet = token.StartsWith("[") && token.EndsWith("]") ? ExpandRange(token.Substring(1, token.Length - 2)) : token;
                            if (string.IsNullOrEmpty(charSet)) continue;

                            int repeat = minRepeat + (maxRepeat > minRepeat ? NextByte() % (maxRepeat - minRepeat + 1) : 0);
                            for (int r = 0; r < repeat; r++)
                                passwordChars.Add(charSet[NextByte() % charSet.Length]);
                        }
                    }
                    else
                    {
                        // Validate standard pattern
                        if (!PatternValidator.ValidatePattern(ruleString)) return null;

                        foreach (char c in ruleString)
                        {
                            char sel = '?';
                            int safetyLimit = 0;

                            if (char.IsUpper(c)) sel = UPPER[NextByte() % UPPER.Length];
                            else if (char.IsLower(c)) sel = LOWER[NextByte() % LOWER.Length];
                            else if (char.IsDigit(c)) sel = DIGITS[NextByte() % DIGITS.Length];
                            else if (c == '!') sel = SYMBOLS[NextByte() % SYMBOLS.Length];
                            else if (c == '-') sel = '-';
                            else if (c == '_') sel = '_';
                            else if (c == ' ') sel = ' ';
                            else if (c == '?')
                            {
                                if (checkboxCharSet.Count == 0) return null;
                                sel = checkboxCharSet[NextByte() % checkboxCharSet.Count];
                            }
                            else sel = c;

                            while (chkNoConsecutive.Checked && passwordChars.Count > 0 && sel == passwordChars[passwordChars.Count - 1] && safetyLimit < 64)
                            {
                                sel = (char)((NextByte() % 94) + 33);
                                safetyLimit++;
                            }

                            passwordChars.Add(sel);
                        }
                    }
                }

                // ---------- PERMUTE PASSWORD ----------
                if (chkPermute.Checked && passwordChars.Count > 1)
                {
                    for (int i = passwordChars.Count - 1; i > 0; i--)
                    {
                        int j;
                        do { j = NextByte(); } while (j >= 256 - (256 % (i + 1)));
                        j = j % (i + 1);
                        char tmp = passwordChars[i];
                        passwordChars[i] = passwordChars[j];
                        passwordChars[j] = tmp;
                    }
                }
                
                return new string(passwordChars.ToArray());
            }
            catch { return null; }
            finally { try { rng.Dispose(); } catch { } }
        }

        #endregion Patterns

        #region Acept, Help and Close
        private void BtnAcpt_Click(object sender, EventArgs e)
        {
            try
            {
                // Clear the destination SecureText
                mainForm.secMasKey.SecureText.Clear();

                // Convert SecureText to a temporary char array safely
                char[] tempChars = SecureStringExtension.ConvertToString(secPasw.SecureText).ToCharArray();

                // Populate the destination SecureText securely
                foreach (char c in tempChars)
                    mainForm.secMasKey.SecureText.AppendChar(c);

                // Populate the TextBox visually (minimal exposure)
                mainForm.secMasKey.Text = new string(tempChars);

                // Clear the temporary array immediately
                Array.Clear(tempChars, 0, tempChars.Length);
                tempChars = null;

                // Update the main key
                mainForm.MastKey();
            }
            finally
            {
                // Close the form
                Close();
            }
        }
        private void BtnCanc_Click(object sender, EventArgs e)
        {
            Close();
        }
        private void BtnHelp_Click(object sender, EventArgs e)
        {
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.PasswGen);
        }

        #endregion Acept, Help and Close

        #region Miscellaneous       
        void SaveComboBoxSetting(string key, ComboBox comboBox)
        {
            if (comboBox.SelectedItem != null)
            {
                AppConfigHelper.XmlConfig.SetValue(key, comboBox.SelectedItem.ToString());
            }
        }
        void SaveCheckboxSetting(string key, CheckBox checkbox)
        {
            AppConfigHelper.XmlConfig.SetValue(key, checkbox.Checked.ToString());
        }
        void SaveRadioButtonSetting(string key, RadioButton radioButton)
        {
            AppConfigHelper.XmlConfig.SetValue(key, radioButton.Checked.ToString());
        }

        #endregion Miscellaneous

        #region Override
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);

            try
            {
                // Pseudo Number Generator
                SaveComboBoxSetting("Result.PSWPeseudoNumberGen", cmbNmb);

                // Password Length
                _xmlConfig.SetValue("Result.PSWPasswLength", nmUpDo.Value.ToString());

                // Generation Mode
                SaveRadioButtonSetting("Result.PSWCharset", rdbCharSet);
                SaveRadioButtonSetting("Result.PSWPatterns", rdbPattern);

                // Pattern Mode
                SaveRadioButtonSetting("Result.PSWStandardPatterns", rbStandardPatterns);
                SaveRadioButtonSetting("Result.PSWAdvancedPatterns", rbAdvancedPatterns);
                SaveRadioButtonSetting("Result.PSWCorporatePatterns", rbCorporatePatterns);
                SaveRadioButtonSetting("Result.PSWFileStandardPatterns", rbFileStandardPatterns);
                SaveRadioButtonSetting("Result.PSWFileAdvancedPatterns", rbFileAdvancedPatterns);
                SaveRadioButtonSetting("Result.PSWFileCorporatePatterns", rbFileCorporatePatterns);
                SaveComboBoxSetting("Result.PSWFileValuePatterns", cmbPatterns);
                
                // Character Set
                SaveCheckboxSetting("Result.PSWUpperCase", chkUppercase);
                SaveCheckboxSetting("Result.PSWLowerCase", chkLowercase);
                SaveCheckboxSetting("Result.PSWDigits", chkDigits);
                SaveCheckboxSetting("Result.PSWSymbols", chkSymbols);
                SaveCheckboxSetting("Result.PSWMinus", chkMinus);
                SaveCheckboxSetting("Result.PSWUnderline", chkUnderline);
                SaveCheckboxSetting("Result.PSWSpace", chkSpace);
                SaveCheckboxSetting("Result.PSWBrackets", chkBrackets);
                SaveCheckboxSetting("Result.PSWLatin", chkLatin);
                SaveCheckboxSetting("Result.PSWCustomChars", chkCustomChars);
                SaveCheckboxSetting("Result.PSWForceEachCategory", chkForceEachCategory);
                SaveCheckboxSetting("Result.PSWPermute", chkPermute);
                SaveCheckboxSetting("Result.PSWNoConsecutive", chkNoConsecutive);
                SaveCheckboxSetting("Result.PSWUserEntropyDialog", chkUserEntropyDialog);

                // Backup Files
                SaveCheckboxSetting("Result.PSWBackup", chkBackup);
                SaveCheckboxSetting("Result.PSWBckStandard", chkBckStandard);
                SaveCheckboxSetting("Result.PSWBckAdvanced", chkBckAdvanced);
                SaveCheckboxSetting("Result.PSWBckCorporate", chkBckCorporate);
                SaveRadioButtonSetting("Result.PSWUserFile", rbUserFile);
                SaveRadioButtonSetting("Result.PSWOriginalFile", rbOriginalFile);

                // Save configuration
                AppConfigHelper.Save();
            }
            catch (Exception ex)
            {
                // Silent Exception
                CentralLog.LogException(ex, "PASSWORD GENERATOR", "An error occurred while closing the module! " + ex.Message);
            }
        }
       
        #endregion Override
    }
}