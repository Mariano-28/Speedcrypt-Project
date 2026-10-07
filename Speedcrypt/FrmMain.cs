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
using System.Text;
using System.Linq;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.SALT;
using Speedcrypt.Crypto;
using Speedcrypt.Protect;
using System.Diagnostics;
using Speedcrypt.EstimMST;
using Speedcrypt.Autotest;
using Speedcrypt.XMLConfig;
using Speedcrypt.MasterKey;
using Speedcrypt.SecureText;
using Speedcrypt.Interfaces;
using Speedcrypt.Crypto.PGP;
using Speedcrypt.WindowsShell;
using Speedcrypt.StringCrypto;
using Speedcrypt.Exceptionlog;
using Speedcrypt.Distribution;
using Speedcrypt.SecureDesktop;
using Speedcrypt.HASHLibraries;
using Speedcrypt.Secureerase.Overwrite;

namespace Speedcrypt
{
    public partial class FrmMain : Form
    {
        #region Cryptographic Fields

        // Key material
        internal byte[] Filepass { get; private set; } // Raw master key directly provided by user input
        internal byte[] Hashpass { get; private set; } // Derived cryptographic key generated via the selected hash function
        internal byte[] Hashrec { get; private set; }  // Key reconstruction and recovery data
        internal byte[] Salt { get; private set; }     // Cryptographic salt used for key derivation operations
        internal byte[] NewSalt { get; private set; }  // Salt generated for key rotation or update operations
        internal byte[] DecSalt { get; private set; }  // Decrypted cryptographic salt retrieved during processing

        // Configuration and protection
        private PrivateXmlConfig _xmlConfig; // Component managing XML configuration file persistence
        private ProtectedSalt _protectedSalt; // Component managing secure storage and protection of cryptographic salts
        private readonly SpeedcryptProtection _speedcryptProtection = new SpeedcryptProtection(); // Component enforcing anti-tamper and anti-debugging protection

        // PGPRSA key counter
        readonly PGPRSAKeyCounter mkPGPRSACounter = new PGPRSAKeyCounter(); // Counter instance for PGP RSA key operations

        // Increment / decrement PGP counters
        readonly EncryptionGroupCounters counters = new EncryptionGroupCounters(); // Tracks operational state metrics across encryption groups

        private EncryptionGroupCounters _counters; // Backing field or local state tracker for encryption group counters

        // UI helpers
        private ListViewRowAlternator _alternator; // Utility for alternating target background colors in ListView rows
        private ToolTipManager _tt; // Utility managing user interface tooltips and contextual hints

        // Key management
        private Keymasterexpoimpo _keymaster; // Handler facilitating cryptographic key import and export operations

        private string[] shellFiles; // Collection storing file paths passed via Windows Shell integration

        // Persistent structural component reference to govern target container navigation state mutations
        private DisableControlPage _tabSecurityEngine = new DisableControlPage();

        // Instantiates the isolated hardware synchronizer
        private GridScrollSynchronizer _synchronizer;

        DisableControlPage UIController = new DisableControlPage();

        public bool Obfs { get; set; } = false;         // Feature state: Toggles Speedcrypt obfuscation or ghost mode features
        public bool AutomaticDel { get; set; } = false; // Policy state: Enforces automatic source file deletion based on configuration  
        public bool Sett { get; set; } = false;         // UI state: Tracks visibility or active status of the settings form

        private bool _activeList = false, // Operational state: Enables encryption actions and decryption context menus
                     _pgpK = false,       // Verification state: Controls active PGP key validation
                     _hmacFail = false,   // Integrity state: Signals integrity verification failure during decryption
                     _encDec = false;     // Processing mode: State flag where false denotes encryption and true denotes decryption
               
        // Algorithm and password metrics
        private int _scrPin = 0,  // Metric tracking the cryptographic strength score for export/import PINs
                    _lenPsw = 0,  // Metric tracking the length of the master password string
                    _upd = 0,     // Notification state: Signals updates or data modifications in the encrypted file list
                    _updown = 0,  // Execution state: Tracking flag for self-test sequence execution
                    _rescor = 0,  // Metric tracking the entropy and complexity score of the master key
                    _hmacCount = 0; // A single incorrect password notification for each group

        /// <summary>
        /// Sends the specified message to a window or windows.
        /// </summary>
        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, bool wParam, IntPtr lParam);

        /// <summary>
        /// Windows Message constant to enable or disable window redrawing.
        /// </summary>
        private const int WM_SETREDRAW = 0x000B;

        #endregion Cryptographic Fields

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="FrmMain"/> class.
        /// </summary>
        public FrmMain()
        {
            InitializeComponent(); // Initializes and configures the designer-generated UI components
            Loadall();             // Loads core application configuration settings and initializes the runtime environment state
        }

        #endregion Constructor

        #region Form Routines
        void Loadall()
        {
            #region Form Settings

            // Validate and restore configuration from backup if needed
            //BckConfigFile.RestoreFromBackup();
            BckConfigValidator.ValidateAndRestore(ForAllUnits.DirPath, labConf, picConf);

            // Executes the environment anti-tamper and structural integrity validation sequence
            if (!_speedcryptProtection.Validate())
            {
                string backupPath = Path.Combine(ForAllUnits.DirPath, "Backup");

                // Displays a critical alert to the user regarding the security boundary or integrity violation
                MessageBox.Show("Speedcrypt has detected an integrity or security violation in its execution environment. To protect your data, the application will now close",
                                ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);

                // Evaluates backup directory existence to conditionally spawn the rescue and recovery utility
                if (Directory.Exists(backupPath))
                {
                    try
                    {
                        Process.Start(Path.Combine(ForAllUnits.DirPath, "SpcUtility.exe"));
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Failed to launch SpcUtility! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        CentralLog.LogException(ex, "MAIN", "Failed to launch SpcUtility during integrity violation handling! ");
                    }
                }

                // Forces immediate process termination following a critical security or validation failure
                Environment.Exit(0);
            }
            else
            {
                // Integrity verification succeeded: updates the user interface indicators to reflect validated status
                _speedcryptProtection.SetAntiTamperPassedStatus(labTamp, picTamp, ForAllUnits.Ledgreen16);
            }

            // Initializes core user interface utilities and maps global persistent configuration state
            _tt = new ToolTipManager(); // Manages contextual tooltip rendering and lifecycle events
            _xmlConfig = AppConfigHelper.XmlConfig; // Synchronizes the reference to the global XML configuration provider

            // Form visual settings
            Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
            StartPosition = FormStartPosition.CenterScreen;
            Text = ForAllUnits.Ver; // Assigns the active application version string to the window title bar

            MaximizeBox = false;

            #endregion Form Settings

            #region Form Components

            // ==============================
            // Main menu
            // ==============================

            // ----- File menu -----
            // Initializes the top-level 'File' menu option with an access key shortcut
            fileToolStripMenuItem.Text = "&File";

            // Configures the UI metadata, resource images, and global hotkeys for file/directory entry actions
            addFileMenu.Text = "&Add file...";
            addFileMenu.Image = ForAllUnits.Fileopen22;
            addFileMenu.ShortcutKeys = Keys.Control | Keys.A;

            addFolderMenu.Text = "A&dd folder...";
            addFolderMenu.Image = ForAllUnits.Folder22;
            addFolderMenu.ShortcutKeys = Keys.Control | Keys.D;

            // Standard application termination entry point with standard Alt+F4 combination
            exitFileMenu.Text = "Exit";
            exitFileMenu.Image = ForAllUnits.Exit22;
            exitFileMenu.ShortcutKeys = Keys.Alt | Keys.F4;

            // ----- Encryption menu -----
            // Initializes the top-level core feature execution menu container
            encryptionToolStripMenuItem.Text = "&Encryption";

            // Setup for processing sequence initialization; defaults to disabled pending state validation
            encryptionListMenu.Text = "Encr&ypt list";
            encryptionListMenu.Image = ForAllUnits.Encrypted22;
            encryptionListMenu.ShortcutKeys = Keys.Control | Keys.Y;
            encryptionListMenu.Enabled = false;

            // ----- Options menu -----
            // Initializes the configuration and system environment adjustments container
            optionsToolStripMenuItem.Text = "&Options";

            // Map configuration, verification, system security parameters, utility tooling, OS integration, and direct config access pathways
            settingsMenu.Text = "&Settings...";
            settingsMenu.Image = ForAllUnits.Settings22;
            settingsMenu.ShortcutKeys = Keys.Control | Keys.S;

            selfTestMenu.Text = "Se&lf-test...";
            selfTestMenu.Image = ForAllUnits.Energy22;
            selfTestMenu.ShortcutKeys = Keys.Control | Keys.L;

            securityMenu.Text = "Securi&ty...";
            securityMenu.Image = ForAllUnits.Konsole22;
            securityMenu.ShortcutKeys = Keys.Control | Keys.T;

            utilityMenu.Text = "&Utility...";
            utilityMenu.Image = ForAllUnits.Configure22;
            utilityMenu.ShortcutKeys = Keys.Control | Keys.U;

            shellMenu.Text = "&Windows Shell...";
            shellMenu.Image = ForAllUnits.Shell22;
            shellMenu.ShortcutKeys = Keys.Control | Keys.W;

            configMenu.Text = "&Configuration file...";
            configMenu.Image = ForAllUnits.Ascii22;
            configMenu.ShortcutKeys = Keys.Control | Keys.N;

            emergencyMenu.Text = "E&mergency Recovery...";
            emergencyMenu.Image = ForAllUnits.Emergency22;
            emergencyMenu.ShortcutKeys = Keys.Control | Keys.M;

            // ----- Help menu -----
            contentsMenu.Text = "Contents...";
            contentsMenu.Image = ForAllUnits.Help22;
            contentsMenu.ShortcutKeys = Keys.Control | Keys.F1;

            topicSearchMenu.Text = "Topic search...";
            topicSearchMenu.Image = ForAllUnits.Helpindex22;
            topicSearchMenu.ShortcutKeys = Keys.Control | Keys.F2;

            firstStepsMenu.Text = "First steps...";
            firstStepsMenu.Image = ForAllUnits.Edumisc22;
            firstStepsMenu.ShortcutKeys = Keys.Control | Keys.F3;

            securityHelpMenu.Text = "Security...";
            securityHelpMenu.Image = ForAllUnits.Lock22;
            securityHelpMenu.ShortcutKeys = Keys.Control | Keys.F4;

            helpOnlineMenu.Text = "Help online...";
            helpOnlineMenu.Image = ForAllUnits.Network22;
            helpOnlineMenu.ShortcutKeys = Keys.Control | Keys.F5;

            speedcryptWebMenu.Text = "Speedcrypt website...";
            speedcryptWebMenu.Image = ForAllUnits.Speedcrypt22;
            speedcryptWebMenu.ShortcutKeys = Keys.Control | Keys.F6;

            marianoWebMenu.Text = "Mariano Ortu website...";
            marianoWebMenu.Image = ForAllUnits.Kformula22;
            marianoWebMenu.ShortcutKeys = Keys.Control | Keys.F7;

            aboutMenu.Text = "About Speedcrypt";
            aboutMenu.Image = ForAllUnits.About22;
            aboutMenu.ShortcutKeys = Keys.Control | Keys.F8;

            bMenuStrip1.TabStop = false;

            // ==============================
            // Toolbar
            // ==============================

            toolButton.BackgroundImage = ForAllUnits.Bord;
            toolButton.BackgroundImageLayout = ImageLayout.Stretch;

            tStripBtnExit.Image = exitFileMenu.Image;
            tStripBtnExit.ToolTipText = "Close Speedcrypt";

            tStripBtnAddFile.Image = addFileMenu.Image;
            tStripBtnAddFile.ToolTipText = "Add File";

            tStripBtnAddFolder.Image = addFolderMenu.Image;
            tStripBtnAddFolder.ToolTipText = "Add Folder";

            tStripBtnEncryption.Image = encryptionListMenu.Image;
            tStripBtnEncryption.ToolTipText = "Encrypt List";
            tStripBtnEncryption.Enabled = false;

            tStripBtnSettings.Image = settingsMenu.Image;
            tStripBtnSettings.ToolTipText = "Settings";

            tStripBtnSelfTest.Image = selfTestMenu.Image;
            tStripBtnSelfTest.ToolTipText = "Self-Test";

            tStripBtnSecurity.Image = securityMenu.Image;
            tStripBtnSecurity.ToolTipText = "Security";

            tStripBtnUtility.Image = utilityMenu.Image;
            tStripBtnUtility.ToolTipText = "Utility";

            tStripBtnShell.Image = shellMenu.Image;
            tStripBtnShell.ToolTipText = "Windows Shell";

            tStripBtnConfigFile.Image = configMenu.Image;
            tStripBtnConfigFile.ToolTipText = "Configuration File";

            tStripBtnEmergency.Image = emergencyMenu.Image;
            tStripBtnEmergency.ToolTipText = "Emergency Recovery";

            tStripBtnContents.Image = contentsMenu.Image;
            tStripBtnContents.ToolTipText = "Speedcrypt Help";

            tStripBtnFirst.Text = "First Steps";
            tStripBtnFirst.Image = firstStepsMenu.Image;

            tStripBtnHelpOnline.Text = "Help Online";
            tStripBtnHelpOnline.Image = helpOnlineMenu.Image;

            tStripBtnAbout.Text = "About Speedcrypt";
            tStripBtnAbout.Image = aboutMenu.Image;

            tStripLab.Image = ForAllUnits.Speedcrypt22;
            tStripLab.ImageAlign = ContentAlignment.MiddleLeft;
            tStripLab.Text = "Complete Cryptographic Suite";
            tStripLab.Font = new Font(tStripLab.Font.FontFamily, 10);
            tStripLab.ForeColor = Color.DarkSlateBlue;

            toolButton.TabStop = false;

            // ==============================
            // Toolbar cursor behavior
            // ==============================

            ToolStripCursor.EnableHandCursor(btnUp, bToolStrip);
            ToolStripCursor.EnableHandCursor(btnDown, bToolStrip);
            ToolStripCursor.EnableHandCursor(tStripBtnExit, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnAddFile, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnAddFolder, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnEncryption, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnSettings, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnSelfTest, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnSecurity, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnUtility, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnShell, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnConfigFile, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnEmergency, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnContents, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnFirst, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnHelpOnline, toolButton);
            ToolStripCursor.EnableHandCursor(tStripBtnAbout, toolButton);

            // ==============================
            // Status Bar
            // ==============================

            labAutoImage.Image = ForAllUnits.Ledred16;
            labAutoText.Text = "Speedcrypt Self-Test: FAILED";
            labFileList.Image = ForAllUnits.Editcopy16;
            labFileTot.Text = "File selection";
            labPic.Text = string.Empty;
            labPic.Image = ForAllUnits.Timer22;
            btnUp.Image = ForAllUnits.Playrev16;
            btnUp.ToolTipText = "Go to the start of the Self-Test list";
            btnDown.Image = ForAllUnits.Playfwd16;
            btnDown.ToolTipText = "Go to the end of the Self-Test list";
            bToolStrip.TabStop = false;

            // ==============================
            // Context menu – files to encrypt
            // ==============================

            addFolderStripMenu.Text = addFolderMenu.Text;
            addFolderStripMenu.Image = addFolderMenu.Image;
            addFolderStripMenu.ShortcutKeys = addFolderMenu.ShortcutKeys;

            addFilelStripMenu.Text = addFileMenu.Text;
            addFilelStripMenu.Image = addFileMenu.Image;
            addFilelStripMenu.ShortcutKeys = addFileMenu.ShortcutKeys;

            openFileStripMenu.Text = "Open File...";
            openFileStripMenu.ShortcutKeys = Keys.Control | Keys.P;
            openFileStripMenu.Image = addFileMenu.Image; 
            openFileStripMenu.Visible = false;

            openFolderStripMenu.Text = "Open Folder...";
            openFolderStripMenu.Image = addFolderMenu.Image; 
            openFolderStripMenu.ShortcutKeys = Keys.Control | Keys.R;

            encryptListStripMenu.Text = "Encrypt List";
            encryptListStripMenu.Image = encryptionListMenu.Image;
            encryptListStripMenu.ShortcutKeys = encryptionListMenu.ShortcutKeys;
            encryptListStripMenu.Enabled = false;
            encryptListStripMenu.Visible = openFileStripMenu.Visible;

            filePropertieslStripMenu.Text = "File Properties";
            filePropertieslStripMenu.Image = ForAllUnits.Ascii22;
            filePropertieslStripMenu.ShortcutKeys = Keys.Control | Keys.I;
            filePropertieslStripMenu.Visible = openFileStripMenu.Visible;

            deleteStripMenu.Text = "Delete Selected Items...";
            deleteStripMenu.Image = ForAllUnits.Critical22;
            deleteStripMenu.ShortcutKeys = Keys.Control | Keys.M;
            deleteStripMenu.Visible = openFileStripMenu.Visible;

            clearStripMenu.Text = "Clear File List...";
            clearStripMenu.Image = ForAllUnits.Empty22;
            clearStripMenu.ShortcutKeys = Keys.Control | Keys.C;
            clearStripMenu.Visible = openFileStripMenu.Visible;

            // ==============================
            // Context menu – encrypted files
            // ==============================

            openFileEncMenu.Text = openFileStripMenu.Text;
            openFileEncMenu.Image = openFileStripMenu.Image;
            openFileEncMenu.ShortcutKeys =  Keys.Control | Keys.Shift | Keys.O;

            openFolderEncMenu.Text = openFolderStripMenu.Text;
            openFolderEncMenu.Image = openFolderStripMenu.Image;
            openFolderEncMenu.ShortcutKeys = Keys.Control | Keys.Shift | Keys.F;

            decryptFilesEncMenu.Text = "Decrypt...";

            entireEncMenu.Text = "Decrypt the entire Group";
            entireEncMenu.Image = ForAllUnits.Encrypt22;
            entireEncMenu.ShortcutKeys = Keys.Control | Keys.Shift | Keys.G;            

            selectedEncMenu.Text = "Decrypt the selected Files";
            selectedEncMenu.Image = ForAllUnits.Decrypted22;
            selectedEncMenu.ShortcutKeys = Keys.Control | Keys.Shift | Keys.S;            

            filePropertiesEncMenu.Text = filePropertieslStripMenu.Text;
            filePropertiesEncMenu.Image = filePropertieslStripMenu.Image;
            filePropertiesEncMenu.ShortcutKeys = Keys.Control | Keys.Shift | Keys.P;

            // ==============================
            // ImageList initialization
            // ==============================

            // Loads icons into array for unified processing into imageList1
            // Declares an immutable array profile allocating the required visual resources for sequential instantiation
            Image[] images1 =
            {
                ForAllUnits.Encrypted22,
                ForAllUnits.Encrypt22,
                ForAllUnits.Math22,
                ForAllUnits.Atlantik22,
                ForAllUnits.Salt22,
                ForAllUnits.Processor22,
                ForAllUnits.Memory22,
                ForAllUnits.Round22,
                ForAllUnits.Trash22,
                ForAllUnits.Pakageutil22,
                ForAllUnits.Editcopy22,
                ForAllUnits.Folder22,
                ForAllUnits.Speedcrypt22,
                ForAllUnits.Keystretc22,
                ForAllUnits.Loadfolder22,
                ForAllUnits.Critical22,
            };

            // Adds each icon to imageList1 by converting byte[] to Image via MemoryStream
            // Iterates through the collection to populate the operational UI graphics container via batch registration
            foreach (var img in images1)
                imageList1.Images.Add(img);

            #endregion Form Components

            #region Master Key

            // Master Key input and labels
            // Configures container controls and visual constraints for the primary cryptographic key interface
            grbMasterKey.Text = "Enter the Master Key below...";
            grbMasterKey.ForeColor = Color.Brown;

            labExp.Text = "Enter the password below to export the Master Key...";
            labExp.ForeColor = grbMasterKey.ForeColor;

            // UI feedback for security compliance validation thresholds
            labScoreapprove.Text = "SCORE  >  2  to Approve!";
            labScoreapprove.ForeColor = Color.DarkGreen;
            labScoreapprove.Visible = false;

            labScor.Text = "Chars 0 / 0 Bits / Score 0";
            labScor.ForeColor = Color.RoyalBlue;

            // Sets maximum buffer length bounds for secure string arrays to mitigate overflow vectors
            secMasKey.MaxLength = 127;
            secPasw.MaxLength = 127;

            // Password strength group
            grbMast.Text = "Password Strength:";
            grbMast.ForeColor = grbMasterKey.ForeColor;
            grbMast.TabStop = false;

            // Password strength details (ListView)
            // Suppresses UI paint cycles during tabular column scheme layout allocation to optimize rendering performance
            listMast.BeginUpdate();
            listMast.Columns.Add("ID", 0, HorizontalAlignment.Center);
            listMast.Columns.Add("", 110, HorizontalAlignment.Left);
            listMast.Columns.Add("", 195, HorizontalAlignment.Left);
            listMast.EndUpdate();

            listMast.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Regular);

            // Password strength metrics
            // Populates the entropy reporting matrix with default key space and complexity metrics placeholders
            listMast.Items.Add(new ListViewItem(new[] { "", "Length / Bits", "" }, 17));
            listMast.Items.Add(new ListViewItem(new[] { "", "Calculation Time", "" }, 0));
            listMast.Items.Add(new ListViewItem(new[] { "", "Crack Time", "" }, 0));
            listMast.Items.Add(new ListViewItem(new[] { "", "Crack Time Display", "" }, 0));
            listMast.Items.Add(new ListViewItem(new[] { "", "Entropy / Score", "" }, 0));
            listMast.Items.Add(new ListViewItem(new[] { "", "Speedcrypt Score", "" }, 0));

            // Finalizes data grid layout properties and styles for the evaluation dashboard
            listMast.Items[5].ForeColor = Color.Blue;
            listMast.HeaderStyle = ColumnHeaderStyle.None;
            listMast.MultiSelect = false;
            listMast.BackColor = Color.OldLace;

            #endregion Master Key

            #region Other Options

            // Security test section
            // Initializes parameters for endpoint visualization security and environment monitoring subsystems
            grbSecurity.Text = "Security Test:";
            grbSecurity.ForeColor = Color.Brown;
            grbSecurity.TabStop = false;

            labScreen.Text = "Obfuscate Print Screen";
            picScreen.Image = ForAllUnits.Ledred16;

            // Other options section
            // Allocates structural layout containers for auxiliary application operational behaviors
            grbOthers.Text = "Other Options:";
            grbOthers.ForeColor = Color.Brown;
            grbOthers.TabStop = false;

            // Exception log section
            // Configures diagnostic logging interfaces and telemetry state monitoring components
            grbExcept.Text = "Exception Log:";
            grbExcept.ForeColor = Color.Brown;
            grbExcept.TabStop = false;

            labErr.Text = "Automatic Deletion";

            // Sets default status value properties and threshold alerts for error and system event matrices
            labErrLog.Text = "0";
            labErrLog.BackColor = Color.LightYellow;
            labErrLog.ForeColor = Color.Red;

            labAutomdel.Text = "0";
            labAutomdel.BackColor = Color.LightYellow;
            labAutomdel.ForeColor = Color.Red;

            #endregion Other Options

            #region Work Environment

            // TabControl image list
            // Binds the localized graphics asset collection to the primary container controller
            tabControl1.ImageList = imageList1;
            tabControl1.TabStop = false;

            // TabPages setup
            // Configures visual indexing and string metadata descriptors for core workspace compartments
            tabPageEnvironment.Text = "Working Environment";
            tabPageEnvironment.ImageIndex = 9;

            tabPagePGPKeys.Text = "PGP Keys";
            tabPagePGPKeys.ImageIndex = 13;

            tabPageAddFile.Text = "Add Files to Encrypt or Decrypt";
            tabPageAddFile.ImageIndex = 10;

            tabPageEncryptedFile.Text = "Encrypted Files";
            tabPageEncryptedFile.ImageIndex = 0;

            tabPageExceptionlog.Text = "Exception Log";
            tabPageExceptionlog.ImageIndex = 15;

            // Speedcrypt Settings
            // Instantiates logical control group domains for end-user preference definitions
            grbUser.Text = "User Settings:";
            grbUser.ForeColor = Color.Brown;
            grbUser.TabStop = false;

            // ListView for settings
            // Initializes the dynamic runtime data layout schema and internal tabular styling configurations
            listSett.View = View.Details;
            listSett.SmallImageList = imageList1;
            listSett.BeginUpdate();
            listSett.Columns.Add("ID", 26, HorizontalAlignment.Center);
            listSett.Columns.Add("SELECTION", 220, HorizontalAlignment.Left);
            listSett.Columns.Add("VALUES", 315, HorizontalAlignment.Left);
            listSett.EndUpdate();
            listSett.Font = new Font("Courier New", 9.25F, FontStyle.Regular);
            listSett.TabStop = false;

            listTest.TabStop = false;

            // Speedcrypt Self-Test
            // Establishes interface anchors for diagnostic integrity checking reporting structures
            grbSelfTest.Text = "Self-Test List:";
            grbSelfTest.ForeColor = Color.Brown;
            grbSelfTest.TabStop = false;

            #endregion Work Environment

            #region PGP Keys

            // PGP Key Creation
            // Instantiates logical control domains and styling boundaries for the cryptographic identity generation form
            grbPgp.Text = "Create PGP Keys...";
            grbPgp.ForeColor = Color.Brown;

            labRSAKeySize.TextAlign = ContentAlignment.MiddleCenter;
            labRSAKeySize.Font = new Font(labRSAKeySize.Font.FontFamily, 8, FontStyle.Regular);
            labRSAKeySize.ForeColor = Color.Red;
            labRSAKeySize.BackColor = Color.OldLace;

            picRsaKeys.Image = ForAllUnits.Keystretc22;

            labRSAKeyLength.Text = "RSA Key Length:";
            labRSAPath.Text = "RSA Key Path:";

            // Text description mapping out programmatic operations executed upon user key derivation routines
            labKeys.Text = "They will be created according to your preferences:\r\n\r\n" +
                            "●  A public key in a .asc file\r\n\r\n" +
                            "●  A private key in a .asc file\r\n\r\n" +
                            "●  Implementation in the configuration file";

            txtPGPFolderPath.ReadOnly = true;
            txtPGPFolderPath.TabStop = false;
            txtPGPFolderPath.ForeColor = Color.Blue;

            // Notes section
            // Allocates standard operating procedure informational labels for user key storage guidelines
            picNote.Image = ForAllUnits.Notes22;
            labNotes.Font = new Font(labNotes.Font.FontFamily, 10, FontStyle.Regular);
            labNotes.ForeColor = Color.Red;
            labNotes.Text = "Notes...";

            labPGPNote.Text = "●  Always store public and private keys on an external USB drive.\r\n\r\n" +
                              "●  The private key must be strictly kept hidden — never expose it.\r\n\r\n" +
                              "●  Encrypt the USB drive and enforce strict file permissions on key files.\r\n\r\n" +
                              "●  The password used to generate the keys will be required both to encrypt and to decrypt.";

            // View Public Key container
            // Finalizes output display constraints for verifying public key token payloads
            grbPublicKey.Text = "View the Public Key:";
            grbPublicKey.ForeColor = Color.Brown;
            grbPublicKey.TabStop = false;
            rchPublicKey.ReadOnly = true;
            rchPublicKey.TabStop = false;

            #endregion PGP Keys

            #region Add File to Encrypt

            // ListView for files to encrypt
            // Configures the primary tabular view control schema for data staging operations
            listFiles.View = View.Details;
            listFiles.SmallImageList = imageList1;
            listFiles.BeginUpdate();
            listFiles.Columns.Add("ID", 37, HorizontalAlignment.Center);
            listFiles.Columns.Add("NAME", 1, HorizontalAlignment.Left);
            listFiles.Columns.Add("PATH", 565, HorizontalAlignment.Left);
            listFiles.Columns.Add("SIZE", 80, HorizontalAlignment.Left);
            listFiles.Columns.Add("DATE", 120, HorizontalAlignment.Left);
            listFiles.Columns.Add("R.SIZE", 80, HorizontalAlignment.Left);
            listFiles.Columns.Add("ENG", 1, HorizontalAlignment.Center);
            listFiles.Columns.Add("KEY", 1, HorizontalAlignment.Center);
            listFiles.Columns.Add("GRP", 1, HorizontalAlignment.Center);
            listFiles.EndUpdate();
            listFiles.FullRowSelect = true;
            listFiles.MultiSelect = true;
            listFiles.AllowDrop = true;

            // Sets properties for the processing monitoring container
            grbOperation.Text = "Processing Status:";
            grbOperation.ForeColor = Color.Brown;
            labOperation.Text = "Ready for processing";
            picOperation.Image = ForAllUnits.Encrypted22;
            labRemainingFiles.Text = "0";
            labRemainingFiles.BackColor = Color.Black;
            labRemainingFiles.ForeColor = Color.LightGreen;
            labRemainingFiles.Font = new Font(labRemainingFiles.Font.FontFamily, 8, FontStyle.Bold);
           
            #endregion Add File to Encrypt

            #region File Encrypted

            // TreeView for encrypted file groups
            // Binds the structural directory navigation tree control to the global graphic catalog
            treeEngines.ImageList = imageList1;

            // ListView for encrypted files
            // Initializes the localized runtime grid schema for secure data persistence tracking
            listFileEnc.View = View.Details;
            listFileEnc.SmallImageList = imageList1;
            listFileEnc.BeginUpdate();
            listFileEnc.Columns.Add("ID", 37, HorizontalAlignment.Center);
            listFileEnc.Columns.Add("NAME", 1, HorizontalAlignment.Left);
            listFileEnc.Columns.Add("PATH", 450, HorizontalAlignment.Left);
            listFileEnc.Columns.Add("SIZE", 80, HorizontalAlignment.Left);
            listFileEnc.Columns.Add("DATE", 120, HorizontalAlignment.Left);
            listFileEnc.Columns.Add("R.SIZE", 80, HorizontalAlignment.Left);
            listFileEnc.Columns.Add("ENG", 1, HorizontalAlignment.Center);
            listFileEnc.Columns.Add("KEY", 1, HorizontalAlignment.Center);
            listFileEnc.Columns.Add("GRP", 1, HorizontalAlignment.Center);
            listFileEnc.EndUpdate();
            listFileEnc.ContextMenuStrip = contextMenuEncFile;
            listFileEnc.FullRowSelect = true;
            listFileEnc.MultiSelect = true;

            // Initializes system state containers and config display descriptors
            grbConfiguration.Text = "Configuration File...";
            grbConfiguration.ForeColor = Color.Brown;
            labConfiguration.Text = "Automatic key deletion is disabled. You can back up your encrypted files and decrypt them whenever necessary.";
            picConfiguration.Image = ForAllUnits.Ledgreen16;
            picMode.Image = ForAllUnits.Backup32;

            #endregion File Encrypted

            #region Exception Log

            // ListView for exceptions
            // Configures the dynamic schema matrix for runtime exception diagnostics and fatal system logs
            listLog.View = View.Details;
            listLog.SmallImageList = imageList1;
            listLog.BeginUpdate();
            listLog.Columns.Add("ID", 37, HorizontalAlignment.Center);
            listLog.Columns.Add("EXCEPTION", 180, HorizontalAlignment.Left);
            listLog.Columns.Add("STATUS", 100, HorizontalAlignment.Left);
            listLog.Columns.Add("MODULE", 80, HorizontalAlignment.Left);
            listLog.Columns.Add("TIMESTAMP", 80, HorizontalAlignment.Left);
            listLog.Columns.Add("METHOD", 80, HorizontalAlignment.Left);
            listLog.Columns.Add("STACKTRACE", 100, HorizontalAlignment.Left);
            listLog.Columns.Add("NOTES", 300, HorizontalAlignment.Left);
            listLog.Columns.Add("HANDLED", 75, HorizontalAlignment.Center);
            listLog.EndUpdate();
            listLog.FullRowSelect = true;
            listLog.TabStop = false;

            // Import Log section
            // Establishes interface boundaries for diagnostic telemetry ingestion operations
            grbImport.Text = "Import Log...";
            grbImport.ForeColor = Color.Brown;

            // Automatic deletion section
            // Instantiates logical parameter panels for database maintenance and automated cleanup thresholds
            grbAutomatic.Text = "Automatic Deletion...";
            grbAutomatic.ForeColor = Color.Brown;
            picAutom.Image = ForAllUnits.Ledred16;

            // Number of records to delete
            // Binds day intervals to the array collection governing automatic data aging policies
            cmbDeletion.Items.AddRange(new object[]
            {
                "30", "60", "90", "120", "150",
            });
            cmbDeletion.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbDeletion.SelectedIndex = 0;

            labdelafter.Text = "Delete after...";

            // Search/filter records
            // Populates data lookup keys mapped directly to columns in the diagnostic database layout
            cmbField.Items.AddRange(new object[]
            {
                "EXCEPTION", "STATUS", "MODULE", "TIMESTAMP", "METHOD", "STACKTRACE", "NOTES",
            });
            cmbField.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbField.SelectedIndex = 0;

            grbFind.Text = "Find Values...";
            grbFind.ForeColor = Color.Brown;
            labValues.Text = "Values:";

            labFilter.Text = "0";
            labFilter.BackColor = Color.LightYellow;
            labFilter.ForeColor = Color.Red;

            pnlLog.Enabled = false;

            #endregion Exception Log

            #region Miscellaneous

            // General buttons
            // Initialises a core functional button array profile encapsulating text metadata, tooltip alerts, and resource assets
            var allbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
               (btnGen, "", "Generate Master Key", ForAllUnits.Generatepassw22, true),
               (btnPsw, "", "View / Hide Master Key", ForAllUnits.Passwordview22, false),
               (btnPin, "", "View / Hide Master Key", ForAllUnits.Passwordview22, false),
               (btnMode, "", "Speedcrypt Secure Desktop", ForAllUnits.Securedesk22, true),
               (btnExpkey, "", "Export Master Key", ForAllUnits.Exportkey22, false),
               (btnImpokey, "", "Import Master Key", ForAllUnits.Importkey22, false),
               (btnClear, "", "Clear all entered values", ForAllUnits.Empty22, false),
               (btnCapture, "", "Capture Screen", ForAllUnits.Cut22, true),
            };

            foreach (var optionbut in allbutton)
            {
                optionbut.Button.Text = optionbut.Text;
                _tt.Set(optionbut.Button, optionbut.Tip);
                optionbut.Button.Cursor = Cursors.Hand;
                optionbut.Button.Image = optionbut.Icon;
                optionbut.Button.Enabled = optionbut.Enabled;
            }

            // Other buttons
            // Aggregates dedicated macro operational buttons applying consistent vertical padding alignment constraints
            var otherbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
               (btnPGPKeygen, "&Generate", "Generate the PGP key pair", ForAllUnits.Identity32, false),
               (btnCleartext, "Clear Te&xt", "Clear the public key text", ForAllUnits.Empty32, false),
               (btnDelog, "Delete Log", "Delete the Error Log", ForAllUnits.Empty32, true),
               (btnDelitem, "Remove Item", "Remove selected items (does not delete the log data)", ForAllUnits.Cancelitem32, false),
               (btnRestore, "Restore List", "Restore the log list", ForAllUnits.Reload32, false),
               (btnExplog, "Export Log", "Export the Error Log", ForAllUnits.Filesaveas32, true),
               (btnImplog, "Import Log", "Import the Error Log", ForAllUnits.Importfile32, true),
            };

            int verticalSpacing = 5;
            foreach (var othernbut in otherbutton)
            {
                othernbut.Button.Text = othernbut.Text;
                _tt.Set(othernbut.Button, othernbut.Tip);
                othernbut.Button.Cursor = Cursors.Hand;
                othernbut.Button.Image = othernbut.Icon;
                othernbut.Button.ImageAlign = ContentAlignment.MiddleCenter;
                othernbut.Button.TextAlign = ContentAlignment.BottomCenter;
                othernbut.Button.Enabled = othernbut.Enabled;
                othernbut.Button.Padding = new Padding(0, 0, 0, verticalSpacing);
            }

            // ComboBoxes
            // Registers standard configuration selector containers with specialized user-guidance descriptions
            var allcombo = new (ComboBox Box, string Tip, bool Enabled)[]
            {
                (cmbDeletion,  "Select the appropriate number of records to clear the error log", true),
                (cmbField,  "Select the field on which to perform the search or filter", true),
            };

            foreach (var option in allcombo)
            {
                _tt.Set(option.Box, option.Tip);
                option.Box.Enabled = option.Enabled;
                option.Box.Cursor = Cursors.Hand;
            }

            // CheckBoxes
            // Configures states and dynamic behaviors for system configuration toggle checkboxes
            var allChkBox = new (CheckBox Chk, string Text, string Tip, bool Checked, bool Enabled)[]
            {
                (chkDisplayRSA, "Display the RSA Public Key", "Display the RSA Public Key after each generation", false, true),
                (chkOpenFolder, "Open the folder after generation", "Open folder after each generation", false, true),
                (chkOverwrite, "Overwrite / Append", "Overwrite or append the contents of the list with the file to load", false, true),
                (chkAlternate, "Alternate Row Color", "Allows alternating row colors in the list", false, true),
                (chkAutomatic, "Enable automatic deletion", "Enable automatic deletion of the error log after a certain number of records", false, true),
            };

            foreach (var (chk, text, tip, isChecked, isEnabled) in allChkBox)
            {
                chk.Text = text;
                chk.Checked = isChecked;
                chk.Enabled = isEnabled;
                chk.Cursor = Cursors.Hand;
                _tt.Set(chk, tip);
            }

            #endregion Miscellaneous

            #region Event Handlers

            // Menu
            // ==============================
            // File
            // ==============================
            // Binds main window menu item click events to their corresponding procedural logic controllers
            addFileMenu.Click += AddFileMenu_Click;
            addFolderMenu.Click += AddFolderMenu_Click;
            exitFileMenu.Click += ExitFileMenu_Click;

            // ==============================
            // Encryption
            // ==============================
            encryptionListMenu.Click += EncryptionListMenu_Click;

            // ==============================
            // Options
            // ==============================
            settingsMenu.Click += SettingsMenu_Click;
            selfTestMenu.Click += SelfTestMenu_Click;
            securityMenu.Click += SecurityMenu_Click;
            utilityMenu.Click += UtilityMenu_Click;
            shellMenu.Click += ShellMenu_Click;
            configMenu.Click += ConfigMenu_Click;
            emergencyMenu.Click += EmergencyMenu_Click;

            // ==============================
            // Help
            // ==============================
            contentsMenu.Click += ContentsMenu_Click;
            topicSearchMenu.Click += TopicSearchMenu_Click;
            firstStepsMenu.Click += FirstStepsMenu_Click;
            securityHelpMenu.Click += SecurityHelpMenu_Click;
            helpOnlineMenu.Click += HelpOnlineMenu_Click;
            speedcryptWebMenu.Click += SpeedcryptWebMenu_Click;
            marianoWebMenu.Click += MarianoWebMenu_Click;
            aboutMenu.Click += AboutMenu_Click;

            // ==============================
            // ToolBar
            // ==============================
            // Maps toolbar functional macros directly onto predefined menu action pipelines
            tStripBtnExit.Click += ExitFileMenu_Click;
            tStripBtnAddFile.Click += AddFileMenu_Click;
            tStripBtnAddFolder.Click += AddFolderMenu_Click;
            tStripBtnEncryption.Click += EncryptionListMenu_Click;
            tStripBtnSettings.Click += SettingsMenu_Click;
            tStripBtnSelfTest.Click += SelfTestMenu_Click;
            tStripBtnSecurity.Click += SecurityMenu_Click;
            tStripBtnUtility.Click += UtilityMenu_Click;
            tStripBtnShell.Click += ShellMenu_Click;
            tStripBtnConfigFile.Click += ConfigMenu_Click;
            tStripBtnEmergency.Click += EmergencyMenu_Click;
            tStripBtnContents.Click += ContentsMenu_Click;
            tStripBtnFirst.Click += FirstStepsMenu_Click;
            tStripBtnHelpOnline.Click += HelpOnlineMenu_Click;
            tStripBtnAbout.Click += AboutMenu_Click;

            // ==============================
            // Popup Menu
            // ==============================
            // File to encrypt
            // Attaches dynamic context-menu action triggers for filesystem interaction routines
            addFilelStripMenu.Click += AddFileMenu_Click;
            addFolderStripMenu.Click += AddFolderMenu_Click;
            openFileStripMenu.Click += OpenFileStripMenu_Click;
            openFolderStripMenu.Click += OpenFolderStripMenu_Click;
            encryptListStripMenu.Click += EncryptionListMenu_Click;
            filePropertieslStripMenu.Click += FilePropertieslStripMenu_Click;
            deleteStripMenu.Click += DeleteStripMenuItem_Click;
            clearStripMenu.Click += ClearStripMenu_Click;

            // ==============================
            // Encrypted Files
            // ==============================
            openFileEncMenu.Click += OpenFileEncMenu_Click;
            openFolderEncMenu.Click += OpenFolderEncMenu_Click;
            filePropertiesEncMenu.Click += FilePropertieEncMenu_Click;
            selectedEncMenu.Click += SelectedEncMenu_Click;
            entireEncMenu.Click += EntireEncMenu_Click;
            tabControl1.SelectedIndexChanged += TabControl1_SelectedIndexChanged;

            // ==============================
            // Master Key
            // ==============================
            // Registers cryptographic string monitoring hooks and button state synchronization routines
            secMasKey.TextChanged += SecMasKey_TextChanged;
            secMasKey.MouseClick += SecMasKey_MouseClick;
            secMasKey.KeyUp += SecMasKey_KeyUp;
            secMasKey.KeyDown += SecMasKey_KeyDown;
            secMasKey.TextChanged += UpdateButtonStates;
            secPasw.TextChanged += UpdateButtonStates;
            btnGen.Click += BtnGen_Click;
            btnPsw.Click += BtnPsw_Click;
            btnMode.Click += BtnMode_Click;

            // ==============================
            // Export / Import Master Key
            // ==============================
            secPasw.TextChanged += SecPasw_TextChanged;
            secPasw.MouseClick += SecPasw_MouseClick;
            secPasw.KeyUp += SecPasw_KeyUp;
            secPasw.KeyDown += SecPasw_KeyDown;
            btnExpkey.Click += BtnExpkey_Click;
            btnImpokey.Click += BtnImpokey_Click;
            btnClear.Click += BtnClear_Click;
            btnPin.Click += BtnPin_Click;

            // ==============================
            // PGP Keys
            // ==============================
            // Hooks user interactions for secure identity generation routines
            btnPGPKeygen.Click += BtnPGPKeygen_Click;
            btnCleartext.Click += BtnCleartext_Click;
            btnPGPKeygen.MouseEnter += BtnPGPKeygen_MouseEnter;
            btnPGPKeygen.MouseLeave += BtnPGPKeygen_MouseLeave;

            // ==============================
            // Status Bar
            // ==============================
            btnUp.Click += BtnUp_Click;
            btnDown.Click += BtnDown_Click;

            // ==============================
            // Capture Screen
            // ==============================
            btnCapture.Click += BtnCapture_Click;

            // ==============================
            // Add File to Encrypt
            // ==============================
            // Registers drag-and-drop listener pipelines for batch file staging operations
            listFiles.DragEnter += ListFiles_DragEnter;
            listFiles.DragDrop += ListFiles_DragDrop;
            listFiles.MouseUp += ListFiles_MouseUp;         
            
            // ==============================
            // Encrypted Files
            // ==============================
            listFileEnc.MouseUp += ListFileEnc_MouseUp;

            // ==============================
            // Exception Log
            // ==============================
            // Establishes diagnostic log data navigation and retention maintenance triggers
            listLog.MouseUp += ListLog_MouseUp;
            btnDelog.Click += BtnDelog_Click;
            btnDelitem.Click += BtnDelitem_Click;
            btnRestore.Click += BtnRestore_Click;
            btnExplog.Click += BtnExplog_Click;
            btnImplog.Click += BtnImplog_Click;
            chkAlternate.CheckedChanged += ChkAlternate_CheckedChanged;
            cmbDeletion.SelectedIndexChanged += CmbDeletion_SelectedIndexChanged;
            chkAutomatic.CheckedChanged += ChkAutomatic_CheckedChanged;
            cmbField.SelectedIndexChanged += CmbField_SelectedIndexChanged;
            txtProcname.TextChanged += TxtProcname_TextChanged;
           
            // ==============================
            // Timer
            // ==============================
            // Hooks general purpose low-level system background loops
            timer1.Tick += Timer1_Tick;

            this.Shown += FrmMain_Shown;

            #endregion Event Handlers

            #region Speedcrypt Initialization

            // ENFORCE SYSTEM CONFIGURATION INTEGRITY BEFORE INTERFACE ALLOCATION
            ConfigSanityGuard.VerifyIntegrityOrTerminate();

            // Allows the form to intercept key presses before controls
            this.KeyPreview = true;
            SpaceKeyBlocker.Enable(this);

            // Configuration file handling
            // Determines application layout properties by validating the local XML backend configuration presence
            if (File.Exists(ForAllUnits.DirPath + @"\Speedcrypt.config.xml") && !string.IsNullOrEmpty(_xmlConfig.GetValue("Result.ImmediateTest")))
                LoadSettings();
            else
                DefaultSettings();

            // Additional for a successful project launch
            if (File.Exists(ForAllUnits.DirPath + @"\Speedcrypt.config.xml"))
            {
                chkOverwrite.Checked = _xmlConfig.GetValue("Result.OverwriteAppend") == "True";
                chkAlternate.Checked = _xmlConfig.GetValue("Result.AlternateRow") == "True";
                chkAutomatic.Checked = _xmlConfig.GetValue("Result.AutomaticDeletionLog") == "True";
                chkDisplayRSA.Checked = _xmlConfig.GetValue("Result.DisplayRSAKeys") == "True";
                chkOpenFolder.Checked = _xmlConfig.GetValue("Result.OpenFolderPGPKeys") == "True";
                cmbDeletion.Text = _xmlConfig.GetValue("Result.DeletionErrorLog");
                AutomaticDel = _xmlConfig.GetValue("Result.AutomaticDeletion") == "True"; // Automatic deletion
                
                if (AutomaticDel) DelConfigFile();
                    else DelNoConfigFile();
            }

            // Obfuscate print screen
            // Activates screenshot blocking subsystems to restrict screen capture routines
            ActivateGhost();

            // Speedcrypt self-test
            // Executes core self-test diagnostics to assert module and algorithm integrity
            SelfTest();

            // Encryption groups counter
            // Instantiates asynchronous counters tracking active secure processing batches
            _counters = new EncryptionGroupCounters();

            // Master key counter
            var masterKeyCounter = new MasterKeyCounter();

            // PGP RSA key counter
            var PGPRSACounter = new PGPRSAKeyCounter();

            // Connect log counter event
            // Binds real-time instrumentation alerts to diagnostic tracing monitors
            CentralLog.LogCountChanged += OnLogCountChanged;

            // Bind ListView to CentralLog
            CentralLog.LogListView = listLog;

            // Load log file into ListView
            CentralLog.LoadLogFromFile(listLog);

            // TextBox hover highlighting
            // Injects dynamic graphic interactions for active input structures
            TextBoxHoverHighlighter.Attach(this);

            // ListView alternating row colors
            _alternator = new ListViewRowAlternator(listLog);
            if (chkAlternate.Checked) _alternator.Enable();

            // Show / Hide the hint label
            new MouseHoverLabel(secMasKey, labScoreapprove);
            new MouseHoverLabel(secPasw, labScoreapprove);

            // Export Master Key
            // Pre-loads environment metrics required for secure key export operations
            Algoimport();

            // Mouse Cursor
            listFiles.EnableHandCursor();
            listLog.EnableHandCursor();
            listFileEnc.EnableHandCursor();
            treeEngines.EnableHandCursor();

            // Export Master Key
            // Builds the abstract operational pipeline binding key derivation metadata and iteration counts
            _keymaster = new Keymasterexpoimpo(cryptoService: new CryptoAdapter(roundsProvider: () => Convert.ToInt32(listSett.Items[3].SubItems[2].Text)), // NumericUpDown for user selection
            engineTextProvider: () => listSett.Items[3].SubItems[1].Text?.ToString() ?? "AES", keyMaterialProvider: null, onKeyMaterialPrepared: null); // Default

            // Distribution
            this.Text = SpeedcryptDistribution.MainTitle;

            // Anti Tamper Utility Tool
            // Triggers validation modules against environmental assets to prevent binary manipulation
            AntiTamperSpcUtility antiTamper = new AntiTamperSpcUtility();
            antiTamper.VerifyFileIntegrity(labUtil, picUtil);

            // Independent Tool Check
            UpdateUtilityControls();

            // Initialize the tip for the grid of files to encrypt
            _tt.Set(listFiles, "Right-click on the grid");

            // DoubleBuffer
            treeEngines.SetDoubleBuffered(true);
            listFiles.SetDoubleBuffered(true);
            listFileEnc.SetDoubleBuffered(true);

            // PGP Other Control
            PGPKeys();

            
            // Instantiates the isolated hardware synchronizer, linking the list, buttons, and state callback
            _synchronizer = new GridScrollSynchronizer(listTest, btnUp, btnDown, _updown, state => _updown = state);

            // Triggers the defensive startup sequence to purge any lingering temporary and BAK files
            SpcCleanupUtility.PurgeTemporaryFiles(AppDomain.CurrentDomain.BaseDirectory);

            // Run the automatic recovery to clean up any crash/blackout residues
            CryptoRollbackManager.RunStartupRecovery();

            // ====================================================================================================
            // ENTERPRISE DEVELOPER COMPLIANCE MEMORANDUM: ANTI-TAMPER INTEGRITY RECIPROCATION SUMMARY
            // ====================================================================================================
            // BEFORE EXECUTING THE FINAL PRODUCTION BUILD RELEASE SUBMISSION, THE DEVELOPER MUST PERFORM 
            // A FULL CRYPTOGRAPHIC SURFACE SCAN TO GENERATE THE ACTIVATED BINARY FILE INTEGRITY TOKENS.
            //
            // IF ANY STRUCTURAL MODIFICATIONS OR SOURCE CODE CHANGES ARE IMPLEMENTED WITHIN THE SYSTEM ARCHITECTURE, 
            // THE ANTI-TAMPER PIPELINE MUST BE SYNCHRONIZED BY RE-COMPILING WITH AN ACTIVE VALIDATION BYPASS,
            // EXTRACTING THE NEW CRYPTOGRAPHIC PAYLOADS, AND UPDATING THE HARDCODED MATRIX ACCORDINGLY.
            //
            // IMPLEMENTATION REFERENCE FOR TELEMETRY HARVESTING WITHIN AN ISOLATED DIAGNOSTIC SCOPE:
            //
            // private void button1_Click(object sender, EventArgs e)
            // {
            //     // Execute bulk cryptographic payload serialization and copy the resultant matrices to the system clipboard
            //     HashGenerator.CopyHashesToClipboard();
            // }
            // ====================================================================================================
            #endregion Speedcrypt Initialization
        }

        #endregion Form Routines

        #region Windows Shell

        /// <summary>
        /// Triggers immediate dashboard data replication and list refreshes upon the primary form finishing its first visual rendering pass.
        /// </summary>
        private void FrmMain_Shown(object sender, EventArgs e)
        {
            // Evaluates data collection presence within the container grid layout before launching the local synchronization thread
            if (listFiles.Items.Count > 0) Reload();// Update list data
        }
        /// <summary>
        /// Ingests file path payload arrays pushed dynamically via Windows Shell extensions contexts, setting specific cipher interface profiles.
        /// </summary>
        public void SetShellFiles(string[] files)
        {
            // Binds the native shell external pointer variables directly to local execution configuration tokens
            shellFiles = files;

            // Validates array bounds parameters before dispatching structural data ingestion passes to the global handler component
            if (shellFiles != null && shellFiles.Length > 0)
            {
                FileListHandler.AddFiles(listFiles, imageList1, shellFiles, labFileTot, ProgressBar);
            }
            // Intercepts the primary item file extension suffix notation to programmatically route the application toward the decryption workspace layer
            if (listFiles.Items[0].SubItems[2].Text.EndsWith(".SPCR"))
                DecryptSettings();
            else
                EncryptSettings();

            // Enforces immediate structural redirection driving user focus onto the file inventory tab container view
            tabControl1.SelectedIndex = 2;

            // Row Alternate Color
            AlternateList();
        }
        /// <summary>
        /// Traverses the interface lists, computing absolute metrics telemetry payload sizes, and enforces high-visibility interface tracking states.
        /// </summary>
        public void Reload()
        {
            // Allocates an isolated 64-bit integer tracker to perform linear aggregation over physical file sizes on disk
            long totalBytes = 0;

            // Iterates across the interface list items, executing strongly-typed property extraction patterns to eliminate casting faults
            foreach (ListViewItem item in listFiles.Items)
            {
                // Safely extract the exact byte size from the Tag property to avoid precision loss from string parsing
                if (item.Tag is long sizeInBytes)
                {
                    totalBytes += sizeInBytes;
                }
                else if (item.Tag is int sizeInBytesInt)
                {
                    totalBytes += sizeInBytesInt;
                }
            }

            // Update status label with precise data
            // Compiles absolute visual feedback tokens publishing active inventory data layouts based on localized tracking metrics
            labFileTot.Text = $"File list: {listFiles.Items.Count} files, {ByteCnt.FromBytes(totalBytes)} total";

            // Separators visibility enforcement
            // Forces baseline interface grid separators to publish and render accurately across layout threads
            toolStripSeparator3.Visible = true;
            toolStripSeparator4.Visible = true;
            toolStripSeparator5.Visible = true;
            toolStripSeparator6.Visible = true;

            // Context menu items visibility enforcement
            // Commands immediate contextual menu item activations, granting access to localized administrative actions profiles
            openFileStripMenu.Visible = true;
            openFolderStripMenu.Visible = true;
            encryptListStripMenu.Visible = true;
            filePropertieslStripMenu.Visible = true;
            deleteStripMenu.Visible = true;
            clearStripMenu.Visible = true;

            // Switch focus to the file list tab context
            // Re-routes visual layout container indexes to force background focus transitions straight onto security input target fields
            tabControl1.SelectedIndex = 2;
            secMasKey.Focus();
        }        

        #endregion Windows Shell

        #region File Menu        
        private void AddFileMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility(); // Close Speedcrypt Utility

            // Suspends visual rendering loops across the file inventory list to eliminate UI flickering during massive item insertion
            listFiles.BeginUpdate();

            try
            {
                // Instantiates native system navigation dialog box customized with operational targeting criteria flags
                OpenFileDialog ofd = new OpenFileDialog
                {
                    Title = "Speedcrypt: select files to Encrypt / Decrypt",
                    Multiselect = true,
                    Filter = "All Files | *.*",
                    RestoreDirectory = true
                };

                // Evaluates interactive workflow consent parameters and triggers processing ingestion loops upon successful selection
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    // Call the external class to handle all files
                    // Dispatches isolated external component routines to stream metadata profiles directly onto the target UI grid
                    FileListHandler.AddFiles(listFiles, imageList1, ofd.FileNames, labFileTot, ProgressBar);
                    // Updates centralized operational metrics trackers and binds specific contextual control items visibility properties
                    FileListHandler.RefreshTotals(listFiles, labFileTot, ProgressBar, contextMenuFile);

                    // Triggers state checking routines to dynamically evaluate operational execution button availability constraints
                    Activatelist();
                }
            }
            finally
            {
                // Forces the framework presentation layer to resume UI painting threads post-ingestion
                listFiles.EndUpdate();
                // Instantly shifts user input focus boundaries straight onto the master security parameter input target fields
                secMasKey.Focus();
            }
        }
        private void AddFolderMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility(); // Close Speedcrypt Utility            

            // Suspends visual layout rendering passes to optimize bulk directory traversal ingestion paths performance
            listFiles.BeginUpdate();

            try
            {
                // Instantiates native container layout selection dialog initializing new storage container allocation options
                FolderBrowserDialog fbd = new FolderBrowserDialog
                {
                    ShowNewFolderButton = true,
                    // Inietta il testo d'istruzione specifico richiesto nel corpo del dialogo nativo
                    Description = "Speedcrypt: select folder to Encrypt / Decrypt"
                };

                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    string selectedFolder = fbd.SelectedPath;
                    // Validates target path structural integrity parameters on disk before spawning recursive processing tasks
                    if (Directory.Exists(selectedFolder))
                    {
                        // Call the external class to handle all files in the folder
                        // Enforces deep filesystem parsing via proxy handler module loading targeted array sequences
                        FileListHandler.AddFiles(listFiles, imageList1, new string[] { selectedFolder }, labFileTot, ProgressBar);
                        FileListHandler.RefreshTotals(listFiles, labFileTot, ProgressBar, contextMenuFile);

                        Activatelist();
                    }
                }
            }
            finally
            {
                // Resumes layout rendering threads to reflect all nested folder asset discoveries accurately
                listFiles.EndUpdate();
                secMasKey.Focus();
            }
        }
        private void ExitFileMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility(); // Close Speedcrypt Utility

            // Commands immediate application lifetime termination, initiating underlying window disposal tasks
            Close();
        }

        /// <summary>
        /// Evaluates active cryptographic suites configuration states to dynamically calibrate operational processing button availability parameters.
        /// </summary>
        void Activatelist()
        {
            // PGP Control
            // Evaluates structural encryption engine settings tokens to identify highly specialized PGP environment profiles
            if (listSett.Items[1].SubItems[1].Text == "PGP")
            {
                // Deep state-validation boundary mapping master credential fields requirements and keys structures before unlocking actions
                if (_activeList == true && secMasKey.Text != string.Empty && _rescor > 2 && _pgpK == false && listFiles.Items.Count > 0)
                {
                    encryptionListMenu.Enabled = true;
                    tStripBtnEncryption.Enabled = true;
                    encryptListStripMenu.Enabled = true;
                }
            }
            else
            {
                // Standard cryptographic fallback validation routine checking inventory density targets before activation
                if (_activeList == true && listFiles.Items.Count > 0)
                {
                    encryptionListMenu.Enabled = true;
                    tStripBtnEncryption.Enabled = true;
                    encryptListStripMenu.Enabled = true;
                }
            }
            // Conditional structure tracking file signature extensions to configure on-the-fly encryption/decryption workspaces layouts
            if (listFiles.Items.Count > 0)
            {
                _encDec = false;
                // Sets operational environment layout modes optimized for incoming structural file data protection routines
                EncryptSettings();
                tabControl1.SelectedIndex = 2; // Shifts workspace target index onto the core inventory tracking container view
                                               // Intercepts specific file extension suffixes to dynamically reconfigure the application posture toward decryption pipelines
                if (listFiles.Items[0].SubItems[2].Text.Contains(".SPCR"))
                {
                    _encDec = true;
                    DecryptSettings();
                }
            }
            listFiles.Items[0].EnsureVisible();
            AlternateList();
        }

        /// <summary>
        /// Iterates through the structural collection elements to apply alternating background colors, 
        /// maximizing user interface scannability and structural visual contrast across dense dataset records.
        /// </summary>
        void AlternateList()
        {
            // ListView alternating row colors
            _alternator = new ListViewRowAlternator(listFiles);
            _alternator.Enable();
        }

        #endregion File menu

        #region Encryption Menu     
        private async void EncryptionListMenu_Click(object sender, EventArgs e)
        {           
            // The first check
            // Defensive guard clause verifying core credential parameters string visibility and security score density constraints
            if (secMasKey.Text == string.Empty || _rescor < 3)
            {
                // Enforces systematic isolation disengaging encryption trigger buttons across all UI surfaces upon validation failure
                encryptionListMenu.Enabled = false;
                tStripBtnEncryption.Enabled = false;
                encryptListStripMenu.Enabled = false;

                return; // Aborts execution thread workflow immediately
            }
            
            BckConfigFile.ActiveEngine = listSett.Items[1].SubItems[1].Text;

            // The UI view rendering consistently anchors to the top element of the collection index
            listFiles.Items[0].EnsureVisible();

            // Selects operational encryption routing if the inversion status flag evaluates to false
            if (_encDec == false)
            {
                // PGP Control
                // Evaluates configuration tokens to apply specific context structural validation targeting PGP environments
                if (listSett.Items[1].SubItems[1].Text == "PGP")
                {
                    // Instantiates an unmanaged provider validation logic proxy module
                    PgpValidator validator = new PgpValidator();

                    // Intercepts and parses target key rings directory availability schemas
                    PgpValidationResult result = validator.Validate(txtPGPFolderPath.Text);

                    // Bails out presenting a localized modal error dialog box if the key container status check fails
                    if (result != PgpValidationResult.Ok)
                    {
                        MessageBox.Show(validator.GetMessage(result), ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                try
                {
                    // Directs operational tab view indexes focus onto the active files inventory grid container
                    if (tabControl1.SelectedIndex != 2) tabControl1.SelectedIndex = 2;                    

                    // 1. Create the session journal file BEFORE the encryption process starts
                    // Commits active files metadata into a fault-tolerant atomic journaling tracking file to prevent unmanaged data loss
                    CryptoRollbackManager.CreateSessionJournal(listFiles);

                    // Calibrates UI timers and locks interaction controls to secure the active worker thread context
                    StartTimer();

                    // Launches asynchronous encryption pipelines processing physical file structures without freezing the GUI
                    await FileEncrypt();
                }
                finally
                {
                    // 2. Clear the session journal file after the encryption process completes
                    // Flushes the temporary crash recovery journal file upon successful cryptographic serialization pass
                    CryptoRollbackManager.ClearSessionJournal();

                    // Releases UI control bindings and restores default structural interface configurations
                    StopTimer();

                    // Dynamic Historical Auditing: Commits a post-decryption state snapshot of the active configuration to preserve execution timelines.
                    BckConfigFile.CreateChronologicalHistoryBackup();

                    // Flushes processing memory queues by clearing all rows from the inventory list control
                    listFiles.Items.Clear();

                    // Invalidate layout visualization graphs and updates underlying cryptographic node schemas
                    UpdateNodes();

                    // Recalibrates telemetry counters publishing updated execution metrics tracking parameters
                    FileListHandler.RefreshTotals(listFiles, labFileTot, ProgressBar, contextMenuFile);
                   
                    tabControl1.SelectedIndex = 3; // Warning: only here; routes user to final operations summary tab view
                }
            }
            else
            {
                // Alternately drives the execution sequence straight into structural decryption workflows
                if (tabControl1.SelectedIndex != 2) tabControl1.SelectedIndex = 2;
                try
                {
                    // 3. Create the session journal file BEFORE the decryption process starts
                    // Registers current state boundaries inside persistent fallback journal tracking maps
                    CryptoRollbackManager.CreateSessionJournal(listFiles);
                    
                    StartTimer();

                    // Dispatches asynchronous data digestion parsing threads targeting decryption endpoints routines
                    await FileDecrypt();

                    // Evaluates environment tracking variables to conditionally trigger encrypted lists visual refreshes
                    if (_upd == 1)
                        UpdateEncList(true);
                }
                finally
                {
                    // 4. Clear the session journal file after the decryption process completes
                    CryptoRollbackManager.ClearSessionJournal();

                    StopTimer();

                    // Defensively retains damaged file indicators within the visualization grid if HMAC authentication signatures fail
                    if (_hmacFail == false)
                        listFiles.Items.Clear();

                    UpdateNodes();

                    // Recalibrates telemetry counters publishing updated execution metrics tracking parameters
                    FileListHandler.RefreshTotals(listFiles, labFileTot, ProgressBar, contextMenuFile);                    
                }
            }
            // Repositions input cursor hooks onto the master credential entry textbox
            secMasKey.Focus();
            // Resets localized password telemetry entropy trackers to a zero state baseline post-execution
            _rescor = 0;
        }

        /// <summary>
        /// Initializes computational execution stopwatches and freezes primary window interface controls to enforce system process isolation.
        /// </summary>
        /// <summary>
        /// Initializes operational benchmarking execution routines, binds runtime structural UI locks, 
        /// and activates low-level input filtering loops prior to cryptographic processing.
        /// </summary>
        void StartTimer()
        {
            // Temporarily suspend UI tooltips to suppress layout flickering during cryptographic execution
            _tt.SetEnabledState(false);

            // Suspend dynamic cursor state processing and force absolute default layout rendering
            CursorExtensions.IsSuspended = true;

            // Force immediate visual update to ensure the control updates its state before entering the tight processing loop
            listFiles.Cursor = Cursors.Default;

            // Synchronizes the primary metrics display layout with the volatile file queue collection count.
            labRemainingFiles.Text = listFiles.Items.Count.ToString();            

            // Resets temporal execution display metrics and enforces high-visibility alert schema status.
            labTimer.Text = "00:00:00.00";
            labTimer.ForeColor = Color.Red; // Switches layout color scheme to alert execution state status
           
            // Systematically locks active menu panels, context wrappers, and capture capabilities during cryptographic operations
            grbMasterKey.Enabled = false;

            // Enforces absolute runtime navigation in listView
            UIController.Disable(listFiles);

            // Enforces absolute runtime navigation constraints on the target control container instance
            _tabSecurityEngine.Disable(tabControl1);
            
            // Suppresses auxiliary structural command triggers and navigational menu strip layouts.
            toolButton.Enabled = false;
            bMenuStrip1.Enabled = false;
            btnCapture.Enabled = false;

            // Disables auxiliary positional controls layouts
            SelfDisable();

            // Arm and trigger the deterministic background polling interval thread engine.
            timer1.Enabled = true;

            ForAllUnits.Start = DateTime.Now; // Captures absolute high-resolution entry time stamp
            timer1.Start();
        }
        
        /// Terminates temporal execution benchmarks, releases programmatic UI constraints, 
        /// and restores complete interactive device event routing across the control layout.
        /// </summary>
        void StopTimer()
        {
            // Halts the deterministic background polling thread engine interval.
            timer1.Stop();

            // Restore programmatic UI tooltip interactions upon cryptographic task completion
            _tt.SetEnabledState(true);

            // Resume normal runtime interaction routines for hand cursor presentation layer
            CursorExtensions.IsSuspended = false;

            // Restores default baseline visual color scheme aesthetics on the temporal metrics tracking layout.
            labTimer.ForeColor = Color.Black;

            timer1.Enabled = false;

            // Restores default user focus capability across interactive group boundaries elements
            grbMasterKey.Enabled = true;

            // Destroys operational tab view navigation constraints to unlock container layout interactivity.
            _tabSecurityEngine.Enable();

            // Disengages low-level mouse message filters to restore full interaction queues on the main inventory list.
            UIController.Enable();

            // Re-enables operational command triggers and structural navigational strips.
            toolButton.Enabled = true;
            bToolStrip.Enabled = true;
            bMenuStrip1.Enabled = true;
            btnCapture.Enabled = true;

            // Resets volatile display queue metrics counters to zero baseline limits post-execution.
            labRemainingFiles.Text = "0";            
        }

        /// <summary>
        /// Dynamically toggles availability metrics between inventory order manipulation controls.
        /// </summary>
        void SelfUpdown()
        {
            if (_updown == 0) btnUp.Enabled = true;
            else btnDown.Enabled = true;
        }
        /// <summary>
        /// Enforces comprehensive exclusion parameters stripping activation triggers from index transformation controls.
        /// </summary>
        void SelfDisable()
        {
            btnUp.Enabled = false;
            btnDown.Enabled = false;
        }

        #endregion Encryption Menu

        #region Options Menu
        private void SettingsMenu_Click(object sender, EventArgs e)
        {
            // If it is running, terminate the independent tool
            KillSpcUtility();

            // Instantiates the target sub-dialog panel and overrides window layout inheritance patterns
            FrmSettings frm = new FrmSettings(this)
            {
                // Set manual positioning and owner
                // Suppresses automated operating system window layout allocation to enforce strict developer-defined coordinates
                StartPosition = FormStartPosition.Manual,
                Owner = this // Registers parent execution window ownership boundary mapping parameters
            };
            // Center FrmSettings relative to main form
            // Math engine block calculating absolute spatial alignment to render the child form in the exact geometric center of the master canvas
            int x = this.Location.X + (this.Width - frm.Width) / 2;
            int y = this.Location.Y + (this.Height - frm.Height) / 2;
            frm.Location = new Point(x, y);

            // Displays the panel as an explicit operational modal barrier intercepting standard inputs threads
            frm.ShowDialog();
        }
        private void SelfTestMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility();

            // Instantiates a secure user consent interception panel loaded with descriptive informational queries
            FrmMessage frm = new FrmMessage(this, "You requested to run the self-test. Shall I proceed?");
            if (frm.ShowDialog() == DialogResult.No)
                return;

            // Dispatches automated low-level verification test suites evaluating cryptographic algorithms health
            SelfTest();

            // Forces structural view redirection shifting focus onto the baseline dashboard panel index target
            tabControl1.SelectedIndex = 0;
        }
        private void SecurityMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility();

            // Instantiates the localized security diagnostic dashboard form overlay interface configuration
            FrmSecurity frm = new FrmSecurity(this)
            {

                // Set manual positioning and owner
                StartPosition = FormStartPosition.Manual,
                Owner = this
            };
            // Center FrmSecurity relative to main form
            // Math engine block calculating absolute spatial alignment to render the child form in the exact geometric center of the master canvas
            int x = this.Location.X + (this.Width - frm.Width) / 2;
            int y = this.Location.Y + (this.Height - frm.Height) / 2;
            frm.Location = new Point(x, y);

            frm.ShowDialog();
        }
        private void UtilityMenu_Click(object sender, EventArgs e)
        {
            // Defensively tests storage presence parameters before trying to execute the external system recovery architecture
            if (File.Exists(Path.Combine(ForAllUnits.DirPath, "SpcUtility.exe")))
            {
                // Extracts the geometric center point coordinates of the primary application workspace
                int x = this.Location.X + (this.Width / 2);
                int y = this.Location.Y + (this.Height / 2);

                // Compiles operational parameter arguments driving hardware coordination flags straight into the separate binary startup pipeline
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = Path.Combine(ForAllUnits.DirPath, "SpcUtility.exe"),
                    Arguments = x + " " + y // Forwards center screen offsets mapping values for the external layout renderer logic
                };

                // Spawns the unmanaged child process environment instance tasking it with disaster recovery procedures
                Process.Start(psi);
            }
            else MessageBox.Show("Warning: SpcUtility.exe is missing from the program folder!", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        private void ShellMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility();

            // Instantiates the localized Windows Explorer registry integration layout panel
            FrmShell frm = new FrmShell(this)
            {

                // Set manual positioning and owner
                StartPosition = FormStartPosition.Manual,
                Owner = this
            };
            // Center FrmShell relative to main form
            // Math engine block calculating absolute spatial alignment to render the child form in the exact geometric center of the master canvas
            int x = this.Location.X + (this.Width - frm.Width) / 2;
            int y = this.Location.Y + (this.Height - frm.Height) / 2;
            frm.Location = new Point(x, y);

            frm.ShowDialog();
        }
        private void ConfigMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility();

            // Instantiates the localized cryptographic key counters infrastructure management interface setup
            FrmConfig frm = new FrmConfig(this)
            {

                // Set manual positioning and owner
                StartPosition = FormStartPosition.Manual,
                Owner = this
            };
            // Center FrmConfig relative to main form
            // Math engine block calculating absolute spatial alignment to render the child form in the exact geometric center of the master canvas
            int x = this.Location.X + (this.Width - frm.Width) / 2;
            int y = this.Location.Y + (this.Height - frm.Height) / 2;
            frm.Location = new Point(x, y);

            frm.ShowDialog();
        }
        private void EmergencyMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility();

            // Instantiates the localized cryptographic key counters infrastructure management interface setup
            FrmEmergency frm = new FrmEmergency(this)
            {

                // Set manual positioning and owner
                StartPosition = FormStartPosition.Manual,
                Owner = this
            };
            // Center FrmEmergency relative to main form
            // Math engine block calculating absolute spatial alignment to render the child form in the exact geometric center of the master canvas
            int x = this.Location.X + (this.Width - frm.Width) / 2;
            int y = this.Location.Y + (this.Height - frm.Height) / 2;
            frm.Location = new Point(x, y);

            frm.ShowDialog();
        }

        /// <summary>
        /// Proactively evaluates filesystem compliance parameters to dynamically calibrate operational availability across administrative recovery controls.
        /// </summary>
        void UpdateUtilityControls()
        {
            // Verifies deployment directory mapping status to ascertain the precise physical presence of the recovery executable file artifact
            bool fileExists = File.Exists(Path.Combine(ForAllUnits.DirPath, "SpcUtility.exe"));

            // Disable/enable menu item
            // Restricts access triggers across menu structures matching real-time file system tracking metrics
            utilityMenu.Enabled = fileExists;

            // Disable/enable ToolStripButton
            // Synchronizes toolbar action button capability values with backend deployment validation properties
            tStripBtnUtility.Enabled = fileExists;
        }

        #endregion Options Menu

        #region Help Menu
        private void ContentsMenu_Click(object sender, EventArgs e)
        {
            // Defensively checks the presence of the compiled help documentation file before invoking the native system viewer wrapper
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile);
        }
        private void TopicSearchMenu_Click(object sender, EventArgs e)
        {
            // Validates resource availability on disk and opens the help subsystem pointing directly to the keyword index navigation context
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.KeywordIndex);
        }
        private void FirstStepsMenu_Click(object sender, EventArgs e)
        {
            // Validates resource availability and routes user documentation navigation layout straight onto the localized onboarding topic
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.FirstStep);
        }
        private void SecurityHelpMenu_Click(object sender, EventArgs e)
        {
            // Validates layout parameters to launch the reference viewer targeted onto the advanced security posture documentation topic
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.Security);
        }
        private void HelpOnlineMenu_Click(object sender, EventArgs e)
        {
            try
            {
                // Dispatches processing operational threads tasking the system shell to execute default web browser host routing processes
                Process.Start("https://www.speedcrypt.info//requirements.html");
            }
            catch (System.ComponentModel.Win32Exception noBrowser)
            {
                // Explicitly intercepts native HRESULT error code (-2147467259 / E_FAIL) signifying missing application associations on the host OS
                if (noBrowser.ErrorCode == -2147467259)
                    MessageBox.Show(noBrowser.Message);
            }
            catch (Exception other)
            {
                // Safety boundary catch block capturing structural runtime system anomalies to alert the operator via standard dialog box
                MessageBox.Show(other.Message);
            }
        }
        private void MarianoWebMenu_Click(object sender, EventArgs e)
        {
            try
            {
                // Spawns the native shell navigation interface redirecting user context to the developer's official web domain infrastructure
                Process.Start("https://www.sicurpas.it");
            }
            catch (System.ComponentModel.Win32Exception noBrowser)
            {
                if (noBrowser.ErrorCode == -2147467259)
                    MessageBox.Show(noBrowser.Message);
            }
            catch (Exception other)
            {
                MessageBox.Show(other.Message);
            }
        }
        private void SpeedcryptWebMenu_Click(object sender, EventArgs e)
        {
            try
            {
                // Spawns the native shell navigation interface redirecting user context to the official product enterprise site
                Process.Start("https://www.speedcrypt.info");
            }
            catch (System.ComponentModel.Win32Exception noBrowser)
            {
                if (noBrowser.ErrorCode == -2147467259)
                    MessageBox.Show(noBrowser.Message);
            }
            catch (Exception other)
            {
                MessageBox.Show(other.Message);
            }
        }
        private void AboutMenu_Click(object sender, EventArgs e)
        {
            KillSpcUtility();

            // Instantiates the localized product credentials dialogue panel and overrides window layout inheritance patterns
            FrmAbout frm = new FrmAbout(this)
            {
                //StartPosition = FormStartPosition.CenterScreen
                // Set manual positioning and owner
                // Suppresses automated operating system window layout allocation to enforce strict developer-defined coordinates
                StartPosition = FormStartPosition.Manual,
                Owner = this // Registers parent execution window ownership boundaries for clean interface layering
            };
            // Center FrmAbout relative to main form
            // Analytical calculation block enforcing crisp absolute alignment to center the child modal view relative to the parent application layout
            int x = this.Location.X + (this.Width - frm.Width) / 2;
            int y = this.Location.Y + (this.Height - frm.Height) / 2;
            frm.Location = new Point(x, y);

            frm.ShowDialog();
        }

        #endregion Help Menu

        #region Add File to Encrypt (Drag and Drop)
        private void ListFiles_DragEnter(object sender, DragEventArgs e)
        {
            // Check if the data being dragged is a file
            // Validates incoming unmanaged shell streaming packages to ascertain if they match structured file dropped signatures
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy; // Allow copy; signals the system interface to display the copy mouse pointer icon transformation
            }
            else
            {
                e.Effect = DragDropEffects.None; // Do not allow; rejects drag operation and updates pointer layout to prohibited state
            }
        }
        private void ListFiles_DragDrop(object sender, DragEventArgs e)
        {
            // Get the dropped items (files or folders)
            // Deserializes the operating system input event buffer payload directly into a strongly-typed string array of file paths
            string[] droppedItems = (string[])e.Data.GetData(DataFormats.FileDrop);

            // Safeguards the pipeline entry boundary by checking parameter allocations before driving batch ingestion subroutines
            if (droppedItems != null && droppedItems.Length > 0)
            {
                // Call the external class to handle all files and folders
                // Dispatches the compiled string path array directly to the specialized proxy component to populate list entries
                FileListHandler.AddFiles(listFiles, imageList1, droppedItems, labFileTot, ProgressBar);

                // Refresh totals
                // Forces recalibration loops to synchronize global metadata indicators and transaction progress counters
                FileListHandler.RefreshTotals(listFiles, labFileTot, ProgressBar, contextMenuFile);
                // Triggers visual state checks to evaluate operational cipher button availability parameters in real-time
                Activatelist();
                // Shifts input focus instantly straight onto the master credential entry interface textbox
                secMasKey.Focus();
            }
        }
        private void ListFiles_MouseUp(object sender, MouseEventArgs e)
        {
             // Evaluates grid structural item count parameters to assign the default context action strip when the inventory is empty
             if (listFiles.Items.Count == 0)
             {
                 listFiles.ContextMenuStrip = contextMenuFile;
                 return;
             }

             // Filters hardware trigger interactions early, ignoring any clicks that do not map to the native right mouse button
             if (e.Button != MouseButtons.Right)
                 return;

             // Executes low-level visual spatial coordinates matching to identify if a valid row structure is underneath the pointer location
             ListViewItem item = listFiles.HitTest(e.Location).Item;

             // Defensively isolates empty grid areas to obstruct the contextual pop-up if the user clicks outside active list row boundaries
             if (item == null)
             {
                 listFiles.ContextMenuStrip = null;
                 return;
             }

             // Binds and anchors the localized menu panel directly over the coordinates where the pointer interaction event occurred
             listFiles.ContextMenuStrip = contextMenuFile;
             contextMenuFile.Show(listFiles, e.Location);            
        }
        
        #endregion Add File to Encrypt (Drag and Drop)

        #region Popup Menu

        // File to encrypted
        private void OpenFileStripMenu_Click(object sender, EventArgs e)
        {
            // Verifies data grid inventory allocation states before driving file spawning threads
            if (listFiles.Items.Count > 0)
            {
                // Intercepts the primary item suffix notation to explicitly check for encrypted binary signatures
                if (listFiles.Items[0].SubItems[2].Text.EndsWith(".SPCR"))
                {
                    // Displays a restrictive security warning interceptor modal box explaining file corruption hazards to the operator
                    DialogResult result = MessageBox.Show("You are about to open one or more encrypted files with a text editor.\r\n\r\n" +
                                                          "Encrypted files contain binary data and are not meant to be viewed or edited manually.\r\n" +
                                                          "Opening or modifying them may corrupt the file and make decryption impossible.\r\n\r\n" +
                                                          "Do you want to continue anyway?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

                    // Immediately aborts execution threads if user workspace operation explicit authorization is denied
                    if (result != DialogResult.Yes)
                        return;

                    // Traverses selected entries array inside the encryption tracking list view to stream binary data inside raw Notepad layout sheets
                    foreach (ListViewItem exploItem in listFileEnc.SelectedItems)
                    {
                        Process.Start("notepad.exe", exploItem.SubItems[2].Text);
                    }
                }
                else
                    // Alternatively loops across standard file selections to execute default unmanaged workspace association launchers
                    foreach (ListViewItem exploItem in listFiles.SelectedItems)
                    {
                        Process.Start("explorer.exe", exploItem.SubItems[2].Text);
                    }
            }
        }
        private void OpenFolderStripMenu_Click(object sender, EventArgs e)
        {
            // Evaluates item density bounds before launching physical operating system directory tracking targets
            if (listFiles.Items.Count > 0)
                // Iterates selected items mapping absolute targets coordinates to highlight them inside standard File Explorer panels
                foreach (ListViewItem exploItem in listFiles.SelectedItems)
                {
                    Process.Start("Explorer.exe", "/select, \"" + exploItem.SubItems[2].Text);
                }
        }
        private void FilePropertieslStripMenu_Click(object sender, EventArgs e)
        {
            // Validates collection allocations state before calling native unmanaged platform window property grids
            if (listFiles.Items.Count > 0)
                // Dispatches structural handle processing properties requests via custom shell execution proxy components
                foreach (ListViewItem exploItem in listFiles.SelectedItems)
                {
                    Shellexc.ShowFileProperties(exploItem.SubItems[2].Text);
                }
        }
        private void DeleteStripMenuItem_Click(object sender, EventArgs e)
        {
            // Triggers an absolute transactional action confirmation warning message to avoid accidental list mutation anomalies
            DialogResult result = MessageBox.Show("Are you sure you want want to delete the selected items?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result == DialogResult.No)
                return;

            // Prevent UI flickering while removing items
            // Suspends visual presentation redraw threads to optimize memory deletion routines and prevent screen flickering
            listFiles.BeginUpdate();
            try
            {
                // Traverses active selections maps backward to systematically strip selected row objects from layout models without enumeration faults
                for (int i = listFiles.SelectedItems.Count - 1; i >= 0; i--)
                {
                    listFiles.Items.Remove(listFiles.SelectedItems[i]);
                }
            }
            finally
            {
                // Commands immediate visual presentation layer restoration post-mutation routines execution
                listFiles.EndUpdate();
            }

            // Adjusts cryptographic controls capability states dynamically post-deletion passes
            DisableEnc();

            // Force UI synchronization to ensure items are completely removed from memory
            // Flushes outstanding visual paint messages inside unmanaged win32 message loops to complete structural memory garbage collection passes
            Application.DoEvents();

            // First call the handler refresh to update internal structures
            // Synchronizes telemetry status trackers to republish baseline inventory counters configurations
            FileListHandler.RefreshTotals(listFiles, labFileTot, ProgressBar, contextMenuFile);

            // Forces algebraic recalibrations targeting dataset tracking dimensions parameters
            RecalculateAll();

            // Enforces defensive fallback routines resetting application layouts profiles to default values if list elements hit zero bounds
            if (listFiles.Items.Count == 0)
            {
                EncryptSettings();
                labFileTot.Text = "File Selection";
            }
        }
        private void ClearStripMenu_Click(object sender, EventArgs e)
        {
            // Renders an immediate absolute destructive layout change confirmation prompt utilizing localized metrics tokens
            DialogResult result = MessageBox.Show("Are you sure you want to clear the File List?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result == DialogResult.No)
                return;

            // Flushes all row indexes properties data to reset the visualization pane inventory
            listFiles.Items.Clear();
            // Restores default baseline structural encryptions mode interface states configurations
            EncryptSettings();

            DisableEnc();
                 
            // Refresh totals
            // Forces synchronization updates across centralized dashboard trackers
            FileListHandler.RefreshTotals(listFiles, labFileTot, ProgressBar, contextMenuFile);
        }

        // File Encrypted
        private void OpenFileEncMenu_Click(object sender, EventArgs e)
        {
            // Boundary check: intercepts and aborts execution immediately if no rows are highlighted in the encrypted list container
            if (listFileEnc.SelectedItems.Count == 0)
                return;

            // Displays a restrictive security warning interceptor modal box explaining file corruption hazards to the operator
            DialogResult result = MessageBox.Show("You are about to open one or more encrypted files with a text editor.\r\n\r\n" +
                                                  "Encrypted files contain binary data and are not meant to be viewed or edited manually.\r\n" +
                                                  "Opening or modifying them may corrupt the file and make decryption impossible.\r\n\r\n" +
                                                  "Do you want to continue anyway?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            // Immediately aborts execution threads if user workspace operation explicit authorization is denied
            if (result != DialogResult.Yes)
                return;

            // Traverses selected entries array inside the encryption tracking list view to stream binary data inside raw Notepad layout sheets
            foreach (ListViewItem exploItem in listFileEnc.SelectedItems)
            {
                Process.Start("notepad.exe", exploItem.SubItems[2].Text);
            }
        }
        private void OpenFolderEncMenu_Click(object sender, EventArgs e)
        {
            // Evaluates encrypted item density bounds before launching physical operating system directory tracking targets
            if (listFileEnc.Items.Count > 0)
                // Iterates selected items mapping absolute targets coordinates to highlight them inside standard File Explorer panels
                foreach (ListViewItem exploItem in listFileEnc.SelectedItems)
                {
                    Process.Start("Explorer.exe", "/select, \"" + exploItem.SubItems[2].Text);
                }
        }
        private void FilePropertieEncMenu_Click(object sender, EventArgs e)
        {
            // Validates collection allocations state before calling native unmanaged platform window property grids
            if (listFileEnc.Items.Count > 0)
                // Dispatches structural handle processing properties requests via custom shell execution proxy components
                foreach (ListViewItem exploItem in listFileEnc.SelectedItems)
                {
                    Shellexc.ShowFileProperties(exploItem.SubItems[2].Text);
                }
        }
        private void SelectedEncMenu_Click(object sender, EventArgs e)
        {
            // Dispatches a transfer workflow signal routing only the explicitly selected target items into the active processing pipeline
            Transferenc(true);
        }
        private void EntireEncMenu_Click(object sender, EventArgs e)
        {
            // Dispatches a batch transfer workflow signal routing the complete encrypted inventory context into the active pipeline
            Transferenc(false);
        }
        void DisableEnc()
        {
            // Evaluates grid inventory occupancy states to programmatically lock cryptographic buttons when empty
            if (listFiles.Items.Count == 0)
            {
                encryptionListMenu.Enabled = false;
                tStripBtnEncryption.Enabled = false;
                encryptListStripMenu.Enabled = false;
            }
        }
        void RecalculateAll()
        {
            // Recalculate totals directly using the working text parsing logic from SubItems[3]
            // Allocates a 64-bit integer tracking variable to aggregate mathematical size signatures over physical data inputs
            long totalBytes = 0;

            // Iterates linearly across item blocks parsing layout text columns to extract structural size metadata
            foreach (ListViewItem item in listFiles.Items)
            {
                if (item.SubItems.Count > 3)
                {
                    string text = item.SubItems[3].Text.Trim();

                    if (!string.IsNullOrEmpty(text))
                    {
                        // Splits string components by white spacing to isolate raw numeric constants from standard unit notations
                        string[] parts = text.Split(' ');

                        if (parts.Length == 2)
                        {
                            string normalizedSize = parts[0].Trim();

                            // ENTERPRISE LOCALIZATION NORMALIZATION LAYER
                            // Safely handles localized culture formats (e.g., Italian vs. International notation)
                            if (normalizedSize.Contains(","))
                            {
                                // Handles decimal commas by stripping thousands dots and converting comma to dot: "1.234,56" -> "1234.56"
                                normalizedSize = normalizedSize.Replace(".", "").Replace(",", ".");
                            }
                            else
                            {
                                // Handles single or multiple thousands dots without decimals: "1.234" -> "1234" or "1.234.567" -> "1234567"
                                normalizedSize = normalizedSize.Replace(".", "");
                            }

                            // Attempts precision invariant floating-point parsing loops to prevent international serialization runtime faults
                            if (double.TryParse(normalizedSize, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out double size))
                            {
                                // Evaluates localized structural suffixes strings to drive exponential binary scale up conversions
                                // Enforces 64-bit long literals (L) to prevent destructive high-density math overflow exceptions on massive data sets
                                switch (parts[1].ToUpper().Trim())
                                {
                                    case "KB":
                                        totalBytes += (long)(size * 1024L);
                                        break;

                                    case "MB":
                                        totalBytes += (long)(size * 1024L * 1024L);
                                        break;

                                    case "GB":
                                        totalBytes += (long)(size * 1024L * 1024L * 1024L);
                                        break;

                                    case "TB":
                                        totalBytes += (long)(size * 1024L * 1024L * 1024L * 1024L);
                                        break;

                                    default:
                                        // Treat as raw bytes, ensuring bounding constraints prevent system conversion overflow
                                        totalBytes += (long)size;
                                        break;
                                }
                            }
                        }
                    }
                }
            }

            // Row Alternate Color
            AlternateList();

            // Update status label with the precise calculated data
            // Flushes accumulated calculation outputs onto localized layout feedback tracking strings controls
            labFileTot.Text = $"File list: {listFiles.Items.Count} files, {ByteCnt.FromBytes(totalBytes)} total";

            // Repositions hardware caret cursors onto the master security parameter input target textbox
            secMasKey.Focus();
        }

        #endregion Popup Menu

        #region Master Key

        // Master Key
        private void SecMasKey_TextChanged(object sender, EventArgs e)
        {
            // Evaluates data parameters inside the credential container to select the appropriate telemetry validation pipeline
            if (secMasKey.Text == string.Empty)
                // Refreshes the score telemetry feedback UI layer to indicate an empty or unassigned state profile
                UpdatePasswordScore();
            else MastKey(); // Dispatches structural entropy analysis passes across the active key sequence inputs
        }
        private void SecMasKey_MouseClick(object sender, MouseEventArgs e)
        {
            // Captures and caches the real-time layout positioning index tracking user pointer placement boundaries
            ForAllUnits.MousCurs = secMasKey.SelectionStart;
        }
        private void SecMasKey_KeyUp(object sender, KeyEventArgs e)
        {
            // Synchronizes global cursor position metrics following unmanaged user keystroke release events
            ForAllUnits.MousCurs = secMasKey.SelectionStart;

            // Conditionally alters operational visual targets configurations when system masking properties are engaged
            if (secMasKey.UseSystemPasswordChar == true)
            {
                btnPsw.Text = string.Empty;
                // Assigns the native password disclosure glyph representation asset to the actionable button control
                btnPsw.Image = ForAllUnits.Passwordview22;
            }
        }
        private void SecMasKey_KeyDown(object sender, KeyEventArgs e)
        {
            // Intercepts input signals early to obstruct systemic data modification attempts via destructive key overrides
            if (e.KeyCode == Keys.Delete)
                e.SuppressKeyPress = true; // Prevents the Delete key; enforces low-level buffer preservation boundaries
        }
        private void BtnGen_Click(object sender, EventArgs e)
        {
            // Instantiates the target password generation sub-dialog container panel
            FrmPasswgen pswgen = new FrmPasswgen(this)
            {
                // Set manual positioning and owner
                // Suppresses automated operating system window layout allocations to enforce strict absolute parameters positioning
                StartPosition = FormStartPosition.Manual,
                Owner = this // Registers parent application window thread ownership layout dependencies
            };
            // Center FrmSettings relative to main form
            // Analytical arithmetic calculation block enforcing geometric centering relative to the parent application presenter canvas
            int x = this.Location.X + (this.Width - pswgen.Width) / 2;
            int y = this.Location.Y + (this.Height - pswgen.Height) / 2;
            pswgen.Location = new Point(x, y);

            pswgen.ShowDialog();
        }
        private void BtnPsw_Click(object sender, EventArgs e)
        {
            // Intercepts input toggles to dynamically engage or disengage runtime password char rendering masks
            if (secMasKey.UseSystemPasswordChar == true)
            {
                secMasKey.UseSystemPasswordChar = false;
                // Hydrates the unmasked textual representation wrapper pulling text data directly from high-security structures memory pointers
                secMasKey.Text = SecureStringExtension.ConvertToString(secMasKey.SecureText);
                btnPsw.Image = null; // Purges active visual images assets before altering structural text indicators layouts
                btnPsw.Text = "\u25CF" + "\u25CF" + "\u25CF"; // Applies highly standardized bullet mask sequences text representations
            }
            else
            {
                // Restores default unmanaged operating system credential masking parameters layer constraints
                secMasKey.UseSystemPasswordChar = true;
                btnPsw.Image = ForAllUnits.Passwordview22;
                btnPsw.Text = string.Empty;
            }
            // Shifts user hardware input thread context focus straight back into the credential control
            secMasKey.Focus();

            // Enforces automated pointer alignment post-mask mutation sequence to optimize workflow re-entry parameters
            if (ForAllUnits.MousCurs == 0)
                secMasKey.SelectionStart = secMasKey.Text.Length;
            else
                secMasKey.SelectionStart = ForAllUnits.MousCurs;

            secMasKey.SelectionLength = 0; // Ensures selection spans are reset to zero metrics layout lengths
        }
        private void BtnMode_Click(object sender, EventArgs e)
        {
            // Instantiates an advanced high-security isolated proxy subsystem proxy component
            SpeedcryptSecureDesktop secureDesktop = new SpeedcryptSecureDesktop();
            // Swaps desktop context processing domains to execute credentials processing runs inside isolated system environments layers
            secureDesktop.ProtectionMode(this.secMasKey, () => MastKey(), this.secPasw);
        }

        // Export / Import Master Key
        /// <summary>
        /// Synchronizes the PIN validation state metrics upon security password control value modifications.
        /// </summary>
        private void SecPasw_TextChanged(object sender, EventArgs e)
        {
            Pinscor();
        }

        /// <summary>
        /// Captures and persists the active text selection pointer within the global context coordinates.
        /// </summary>
        private void SecPasw_MouseClick(object sender, MouseEventArgs e)
        {
            ForAllUnits.MousCurs = secPasw.SelectionStart;
        }

        /// <summary>
        /// Updates runtime cursor tracking positions and enforces UI state synchronization for system password masking properties.
        /// </summary>
        private void SecPasw_KeyUp(object sender, KeyEventArgs e)
        {
            ForAllUnits.MousCurs = secPasw.SelectionStart;

            if (secPasw.UseSystemPasswordChar == true)
            {
                btnPin.Text = string.Empty;
                btnPin.Image = ForAllUnits.Passwordview22;
            }
        }

        /// <summary>
        /// Evaluates incoming low-level keyboard events to intercept and suppress destructive key actions that compromise buffer integrity.
        /// </summary>
        private void SecPasw_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Delete)
            {
                e.SuppressKeyPress = true; // Prevents the Delete key from executing structural buffer modifications
            }
        }

        /// <summary>
        /// Executes the secure master key export sequence and triggers immediate cryptographic memory deallocation upon success.
        /// </summary>
        private void BtnExpkey_Click(object sender, EventArgs e)
        {
            try
            {
                bool exportSucceeded = _keymaster.ExportWithSaveDialog(this, secPasw, secMasKey, out string errorMessage);

                if (exportSucceeded)
                {
                    // Execute deterministic memory wipe sequence to eliminate plaintext remnants
                    SecureWipe.WipeSecureTextBox(secPasw);
                    btnPin.Text = string.Empty;
                    _scrPin = 0;
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "Master Key", "Handled exceptions during the export of the Master Key!");
            }
        }

        /// <summary>
        /// Initializes the file stream dialog for Master Key structural import and dynamically binds visual alternate row rendering logic.
        /// </summary>
        private void BtnImpokey_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog ofd = new OpenFileDialog
                {
                    Title = "Speedcrypt: Password Import...",
                    Filter = "msk files (*.msk)|*.msk"
                })
                {
                    if (ofd.ShowDialog() != DialogResult.OK)
                        return;

                    _keymaster.ImportFromFile(ofd.FileName, secPasw, secMasKey, out _);
                }

                if (chkAlternate.Checked)
                {
                    _alternator = new ListViewRowAlternator(listLog);
                    _alternator.Enable();
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "Master Key", "Import Master Key Failed!");
            }
        }

        /// <summary>
        /// Triggers the global application state and memory purge routine.
        /// </summary>
        private void BtnClear_Click(object sender, EventArgs e)
        {
            Eraseall();
        }

        /// <summary>
        /// Toggles the visual state of the cryptographic password buffer between system-level masking and explicit character visualization, managing stateful cursor focus preservation.
        /// </summary>
        private void BtnPin_Click(object sender, EventArgs e)
        {
            if (secPasw.UseSystemPasswordChar == true)
            {
                secPasw.UseSystemPasswordChar = false;
                secPasw.Text = SecureStringExtension.ConvertToString(secPasw.SecureText);
                btnPin.Image = null;
                btnPin.Text = "\u25CF" + "\u25CF" + "\u25CF"; // Render secure placeholder glyphs explicitly
            }
            else
            {
                secPasw.UseSystemPasswordChar = true;
                btnPin.Image = ForAllUnits.Passwordview22;
                btnPin.Text = string.Empty;
            }
            secPasw.Focus();

            // Re-establish accurate text insertion index context based on historic navigation points
            if (ForAllUnits.MousCurs == 0)
                secPasw.SelectionStart = secPasw.Text.Length;
            else
                secPasw.SelectionStart = ForAllUnits.MousCurs;
            secPasw.SelectionLength = 0;
        }

        /// <summary>
        /// Evaluates state vectors of essential secure data structures to dynamically calculate UI command availability metrics.
        /// </summary>
        private void UpdateButtonStates(object sender, EventArgs e)
        {
            btnClear.Enabled = !string.IsNullOrEmpty(secMasKey.Text) || !string.IsNullOrEmpty(secPasw.Text);
        }

        /// <summary>
        /// Executes the deterministic master key derivation sequence, evaluates human password entropy metrics via ZXCVBN, 
        /// synchronizes secure multi-column UI lists, and seals the derived material in-memory using Windows DPAPI.
        /// </summary>
        public void MastKey()
        {
            // Proactively purge and deallocate pre-existing cryptographic sensitive buffers
            if (Filepass != null)
            {
                Array.Clear(Filepass, 0, Filepass.Length);
                Filepass = null;
            }

            if (Hashpass != null)
            {
                Array.Clear(Hashpass, 0, Hashpass.Length);
                Hashpass = null;
            }

            char[] masterChars = null;
            byte[] masterBytes = null;

            try
            {
                // Extract raw credentials as a volatile character array directly from the unmanaged SecureString container
                masterChars = AdapterCharString.ToCharArray(secMasKey.SecureText);

                if (masterChars.Length == 0)
                {
                    // Revert interface indicators and structural variables to minimum default vectors upon blank input detection
                    qualityProgressBar2.Value = qualityProgressBar2.Minimum;
                    passwordStrengthControl1.Strength = 0;
                    passwordStrengthControl1.StrengthText = string.Empty;

                    listMast.Items[0].SubItems[2].Text = "0";
                    listMast.Items[1].SubItems[2].Text = "0";
                    listMast.Items[2].SubItems[2].Text = string.Empty;
                    listMast.Items[3].SubItems[2].Text = string.Empty;
                    listMast.Items[4].SubItems[2].Text = string.Empty;
                    listMast.Items[5].SubItems[2].Text = "0";

                    btnPsw.Enabled = false;
                    btnExpkey.Enabled = false;

                    _lenPsw = 0;
                    _scrPin = 0;
                    return;
                }

                // Quantify the exact allocation context for UTF-8 byte mapping to avoid heap fragmentation and GC tracing
                int byteCount = Encoding.UTF8.GetByteCount(masterChars);
                masterBytes = new byte[byteCount];

                // Transmute characters into raw bytes utilizing a stateful encoder context to completely eliminate managed string artifacts
                Encoding.UTF8.GetEncoder().GetBytes(masterChars, 0, masterChars.Length, masterBytes, 0, true);

                // Dynamically compute the required key length thresholds based on internal cryptographic sizing constraints
                int targetLen;
                int byteLen = masterBytes.Length;

                if (byteLen < 16) targetLen = 16;
                else if (byteLen < 32) targetLen = 32;
                else if (byteLen < 64) targetLen = 64;
                else targetLen = 128;

                // Delegate execution to the dedicated core engine to generate the key material
                Filepass = MasterKeyDerivation.DeriveMasterKey(masterBytes, targetLen);

                // Instatiate the computational linguistical matcher engine to parse complex human entropy patterns
                Zxcvbn zx = new Zxcvbn();

                // Initialize scoped variable structures to maintain clean register tracking during evaluation
                int strengthBits;
                int resultScore;
                string calcTimeStr;
                string crackTimeStr;
                string crackTimeDisplayStr;

                // Generate a localized, ephemeral structural sequence solely targeted at satisfying the evaluation API payload constraints
                string tempPasswordString = new string(masterChars);

                // Dispatch payload to execute structural matchers, pattern checks, and dictionary attacks
                var result = zx.EvaluatePassword(tempPasswordString);

                strengthBits = Convert.ToInt32(result.Entropy);
                resultScore = result.Score;
                calcTimeStr = result.CalcTime.ToString();
                crackTimeStr = result.CrackTime.ToString();
                crackTimeDisplayStr = result.CrackTimeDisplay.First().ToString().ToUpper() + string.Join("", result.CrackTimeDisplay.Skip(1)).ToLower();

                passwordStrengthControl1.Strength = strengthBits;
                passwordStrengthControl1.StrengthText = strengthBits > 15 ? strengthBits + " Bits" : string.Empty;

                // Column Update Row 0: Map human-input metric transformations and bitwise entropy values
                listMast.Items[0].SubItems[2].Text = masterChars.Length + " -> " + Filepass.Length + " Ch. / " + strengthBits + " Bits";

                listMast.Items[1].SubItems[2].Text = calcTimeStr;
                listMast.Items[2].SubItems[2].Text = crackTimeStr;
                listMast.Items[3].SubItems[2].Text = crackTimeDisplayStr;

                listMast.Items[4].SubItems[2].Text =
                    Convert.ToDouble(strengthBits) + " / " + resultScore;
                _rescor = resultScore;

                // Column Update Row 5: Process and print mathematical entropy of the derived key versus baseline numeric algorithms
                int derivedEntropyBits = DerivedKeyEntropyCalculator.CalculateEntropyBits(Filepass);
                int derivedScore = DerivedKeyEntropyCalculator.CalculateScore(Filepass);

                listMast.Items[5].SubItems[2].Text = masterChars.Length + " -> " + Filepass.Length + " Ch. / " +
                                                      derivedEntropyBits + " Bits (Score " + derivedScore + "/4)";

                // Toggle programmatic execution commands strictly adhering to verified character presence rules
                btnPsw.Enabled = masterChars.Length > 0;

                // Inspect non-allocating SecureString metadata properties to safely govern high-level master key export availability
                btnExpkey.Enabled = masterChars.Length > 7 && resultScore > 2 && secPasw.SecureText != null && secPasw.SecureText.Length > 0 && _scrPin > 2;

                _lenPsw = masterChars.Length;
                btnPGPKeygen.Enabled = resultScore > 2 && txtPGPFolderPath.Text != string.Empty && listSett.Items[1].SubItems[1].Text.Contains("PGP");

                if (listSett.Items[1].SubItems[1].Text == "PGP" && listFiles.Items.Count > 0 && !listFiles.Items[0].SubItems[2].Text.EndsWith(".SPCR"))
                {
                    encryptionListMenu.Enabled = resultScore > 2 && listFiles.Items.Count > 0 && _pgpK == false;
                    _activeList = true == resultScore > 2 && _pgpK == false;
                }
                else
                {
                    encryptionListMenu.Enabled = resultScore > 2 && listFiles.Items.Count > 0;
                    _activeList = true == resultScore > 2;
                }

                tStripBtnEncryption.Enabled = encryptionListMenu.Enabled;
                encryptListStripMenu.Enabled = encryptionListMenu.Enabled;

                // Immutable Memory Shielding: Encrypt underlying byte arrays utilizing DPAPI hardware-backed context isolation
                ProtectedMemory.Protect(Filepass, MemoryProtectionScope.SameLogon);
            }
            finally
            {
                // Deterministic Memory Purge: Overwrite residual memory locations aggressively to guarantee zero post-lifecycle visibility
                if (masterChars != null) Array.Clear(masterChars, 0, masterChars.Length);
                if (masterBytes != null) Array.Clear(masterBytes, 0, masterBytes.Length);
            }
        }

        /// <summary>
        /// Executes a definitive cryptographic PIN strength evaluation via computational linguistic matching,
        /// updates security progress indicators, and dynamically adjusts transactional UI control states.
        /// </summary>
        public void Pinscor()
        {
            Zxcvbn zx = new Zxcvbn();
            char[] passwordChars = null;

            try
            {
                // Extract raw credentials into a volatile character array directly from the unmanaged SecureString container
                passwordChars = AdapterCharString.ToCharArray(secPasw.SecureText);

                int passwordLength = passwordChars.Length;

                if (passwordLength == 0)
                {
                    // Revert systemic interface indicators, control bitmaps, and tracking metrics to their baseline minimum states
                    qualityProgressBar2.Value = qualityProgressBar2.Minimum;
                    labScor.Text = $"Chars 0 / 0 Bits / Score 0";
                    btnExpkey.Enabled = false;
                    btnImpokey.Enabled = false;
                    btnPin.Enabled = false;
                    btnPin.Image = ForAllUnits.Passwordview22;
                    btnPin.Text = string.Empty;
                    _scrPin = 0;
                    return;
                }

                // Instantiate an ephemeral string allocation targeted exclusively at satisfying internal computational matcher API definitions
                string tempPasswordString = new string(passwordChars);

                // Execute extensive pattern checks, dictionary matchers, and entropy calculations against the input vector
                var result = zx.EvaluatePassword(tempPasswordString);

                int entropyBits = Convert.ToInt32(result.Entropy);
                int resultScore = result.Score;

                // Perform boundary-safe value mapping to refresh the tracking progress UI safely
                qualityProgressBar2.Value = Math.Min(Math.Max(entropyBits, qualityProgressBar2.Minimum), qualityProgressBar2.Maximum);
                labScor.Text = $"Chars {passwordLength} / {entropyBits} Bits / Score {resultScore}";

                // Enforce transactional business rules to toggle cryptographic operation command availability
                btnExpkey.Enabled = resultScore > 2 && _lenPsw > 7;
                btnImpokey.Enabled = resultScore > 2;
                btnPin.Enabled = passwordLength > 0;

                _scrPin = resultScore;
            }
            finally
            {
                // Overwrite underlying memory structures immediately to prevent post-lifecycle credential tracing
                if (passwordChars != null)
                {
                    Array.Clear(passwordChars, 0, passwordChars.Length);
                }
            }
        }

        /// <summary>
        /// Monitors master key character changes, normalizes whitespace anomalies, and triggers the key derivation sequence.
        /// </summary>
        void UpdatePasswordScore()
        {
            string currentKey = secMasKey.Text;

            if (string.IsNullOrWhiteSpace(currentKey))
            {
                currentKey = string.Empty;
                secMasKey.Text = string.Empty; // Force comprehensive text block purge execution

                secMasKey.SelectionStart = 0;

                // Reset the target columns of the multi-column metric overview control structure
                foreach (ListViewItem item in listMast.Items)
                    item.SubItems[2].Text = string.Empty;

                passwordStrengthControl1.Strength = 0;

                // Command synchronous control redraw operations to ensure zero UI rendering latency
                listMast.Refresh();
                passwordStrengthControl1.Refresh();
                btnPsw.Text = string.Empty;
                btnPsw.Image = ForAllUnits.Passwordview22;
                btnPsw.Enabled = secMasKey.Text != string.Empty;
                encryptionListMenu.Enabled = false;
                tStripBtnEncryption.Enabled = false;
                encryptListStripMenu.Enabled = false;
                return;
            }

            try
            {
                // Delegate state data execution to the core derivation subsystem
                MastKey();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error during Key update! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "Master Key", "Error during Key update! " + ex.Message);
            }

            // Maintain operational focus context and re-establish accurate cursor position points
            secMasKey.Focus();
            secMasKey.SelectionStart = currentKey.Length;
            secMasKey.SelectionLength = 0;
        }

        /// <summary>
        /// Executes an absolute erasure routine across primary secure input structures and neutralizes operational lists.
        /// </summary>
        void Eraseall()
        {
            // Deploy specialized cryptographic scrubbing routines across managed text controls
            SecureWipe.WipeSecureTextBox(secMasKey);
            SecureWipe.WipeSecureTextBox(secPasw);
            _activeList = false; // Prevent logic leaks by resetting the structural list availability flag state
            _rescor = 0;
            btnPGPKeygen.Enabled = false;
            secMasKey.Focus();
        }

        /// <summary>
        /// Instantiates the key management interface with dynamic work-factor computation providers and fallback cipher mappings.
        /// </summary>
        void Algoimport()
        {
            // Inject runtime settings context and functional delegates into the export/import infrastructure layer
            _keymaster = new Keymasterexpoimpo(cryptoService: new CryptoAdapter(roundsProvider: () =>
                             Convert.ToInt32(listSett.Items[3].SubItems[2].Text)),
                             engineTextProvider: () => _keymaster.LastImportedAlgorithm ?? "AES",
                             mainForm: this, keyMaterialProvider: null, onKeyMaterialPrepared: null);
        }

        #endregion Master Key

        #region Timer

        /// <summary>
        /// Executes chronological state tracking calculations per hardware tick interval, 
        /// computing the precise execution delta to refresh standard multi-resolution UI timer indicators.
        /// </summary>
        private void Timer1_Tick(object sender, EventArgs e)
        {
            // Computes the absolute temporal delta elapsed since the foundational cryptographic execution sequence checkpoint initialization.
            TimeSpan diff = DateTime.Now.Subtract(ForAllUnits.Start);

            // Formats and commits the chronological metrics into the dedicated UI display element utilizing a high-density, multi-hour format (HH:mm:ss.ff) to ensure zero truncation across extended runtimes.
            labTimer.Text = String.Format("{0:00}:{1:00}:{2:00}.{3:00}", (int)diff.TotalHours, diff.Minutes, diff.Seconds, diff.Milliseconds / 10);
        }

        #endregion Timer

        #region Work Enviroment
        /// <summary>
        /// Parses the underlying application configuration schema from the persistent XML tree, 
        /// reconstructs the structural multi-column cryptographic properties display, 
        /// and maps active symmetric/asymmetric engine parameters.
        /// </summary>
        public void LoadSettings()
        {
            try
            {
                listSett.Items.Clear();
                encryptionListMenu.Enabled = false;
                string Notbcrypt = string.Empty;
                string keyStr = "100000"; // Default PBKDF2 Rounds value

                // ==========================================
                // ENCRYPTION ENGINES SECTION
                // ==========================================
                // Evaluates symmetric encryption profiles parsed from the programmatic XML configuration tree
                listSett.Items.Add(new ListViewItem(new[] { "", "ENCRYPTION ENGINE" }, 0));

                switch (_xmlConfig.GetValue("Result.CryptoEngine"))
                {
                    case "AES":
                        listSett.Items.Add(new ListViewItem(new[] { "", "AES", _xmlConfig.GetValue("Result.AESKeySize") }));
                        break;

                    case "PGP":
                        listSett.Items.Add(new ListViewItem(new[] { "", "PGP", _xmlConfig.GetValue("Result.RSAKeySize") }));
                        break;

                    case "IDEA":
                        listSett.Items.Add(new ListViewItem(new[] { "", "IDEA", "K128" }));
                        break;

                    case "GOST":
                        listSett.Items.Add(new ListViewItem(new[] { "", "GOST", "K256" }));
                        break;

                    case "AES-GCM":
                        listSett.Items.Add(new ListViewItem(new[] { "", "AES-GCM", "K256" }));
                        break;

                    case "SERPENT":
                        listSett.Items.Add(new ListViewItem(new[] { "", "SERPENT", _xmlConfig.GetValue("Result.SerpentKeySize") }));
                        break;

                    case "TWOFISH":
                        listSett.Items.Add(new ListViewItem(new[] { "", "TWOFISH", _xmlConfig.GetValue("Result.TwofishKeySize") }));
                        break;

                    case "CAMELLIA":
                        listSett.Items.Add(new ListViewItem(new[] { "", "CAMELLIA", _xmlConfig.GetValue("Result.CamelliaKeySize") }));
                        break;

                    case "THREEFISH":
                        listSett.Items.Add(new ListViewItem(new[] { "", "THREEFISH", _xmlConfig.GetValue("Result.ThreefishKeySize") }));
                        break;

                    case "KUZNYECHIK":
                        listSett.Items.Add(new ListViewItem(new[] { "", "KUZNYECHIK", "K256" }));
                        break;

                    case "XCHACHA20-POLY1305":
                        listSett.Items.Add(new ListViewItem(new[] { "", "XCHACHA20-POLY1305", "K256" }));
                        break;
                }

                // ==========================================
                // ENCRYPTION STRING SECTION
                // ==========================================
                // Configures high-iteration cryptographic key stretching mappings for runtime token generation
                listSett.Items.Add(new ListViewItem(new[] { "", "ENCRYPTION STRING" }, 1));

                switch (_xmlConfig.GetValue("Result.StringCrypto"))
                {
                    case "AES-GCM":
                        keyStr = _xmlConfig.GetValue("Result.FRSAES-CGMStrCrp") ?? "100000";
                        listSett.Items.Add(new ListViewItem(new[] { "", "AES-GCM", keyStr }));
                        break;

                    case "SERPENT":
                        keyStr = _xmlConfig.GetValue("Result.SERPENTStrCrp") ?? "100000";
                        listSett.Items.Add(new ListViewItem(new[] { "", "SERPENT", keyStr }));
                        break;

                    case "TWOFISH":
                        keyStr = _xmlConfig.GetValue("Result.TWOFISHStrCrp") ?? "100000";
                        listSett.Items.Add(new ListViewItem(new[] { "", "TWOFISH", keyStr }));
                        break;

                    case "THREEFISH":
                        keyStr = _xmlConfig.GetValue("Result.THREEFISHStrCrp") ?? "100000";
                        listSett.Items.Add(new ListViewItem(new[] { "", "THREEFISH", keyStr }));
                        break;

                    case "XCHACHA20":
                        keyStr = _xmlConfig.GetValue("Result.SECXCHACHA20StrCrp") ?? "100000";
                        listSett.Items.Add(new ListViewItem(new[] { "", "XCHACHA20", keyStr }));
                        break;

                    case "XCHACHA20POLY1305":
                        keyStr = _xmlConfig.GetValue("Result.XCHACHA20POLY1305StrCrp") ?? "100000";
                        listSett.Items.Add(new ListViewItem(new[] { "", "XCHACHA20POLY1305", keyStr }));
                        break;

                    case "AES":
                        keyStr = _xmlConfig.GetValue("Result.AESStrCrp") ?? "100000";
                        listSett.Items.Add(new ListViewItem(new[] { "", "AES", keyStr }));
                        break;
                }
                // ==========================================
                // HASH ENGINES SECTION
                // ==========================================
                // Allocates operational parameters for primitive hash generation functions and derivation models
                listSett.Items.Add(new ListViewItem(new[] { "", "HASH ENGINES" }, 2));
                Notbcrypt = _xmlConfig.GetValue("Result.HashEngine");
                if (Notbcrypt == "BCRYPT")
                    listSett.Items.Add(new ListViewItem(new[] { "", "SCRYPT", "IMPLICIT" }));
                else
                    listSett.Items.Add(new ListViewItem(new[] { "", _xmlConfig.GetValue("Result.HashEngine"), "IMPLICIT" }));

                // ==========================================
                // PSEUDO RANDOM NUMBER GENERATOR SECTION
                // ==========================================
                // Evaluates hardware or software entropy engine profiles for initialization vector generation
                listSett.Items.Add(new ListViewItem(new[] { "", "PSEUDO NUMBER GENERATOR" }, 3));
                listSett.Items.Add(new ListViewItem(new[] { "", _xmlConfig.GetValue("Result.SaltEngine"), "IMPLICIT" }));

                // ==========================================
                // INTERNAL FUNCTIONS SECTION
                // ==========================================
                // Maps baseline core auxiliary hashing mechanisms used for structural checksum validations
                listSett.Items.Add(new ListViewItem(new[] { "", "INTERNAL FUNCTIONS" }, 4));
                listSett.Items.Add(new ListViewItem(new[] { "", "BLAKE-256", "IMPLICIT" }));

                // ==========================================
                // ARGON2 KDF PARAMETERS SECTION
                // ==========================================
                // Parses and registers system memory cost, core count parallelism, and iteration vectors for Argon2
                listSett.Items.Add(new ListViewItem(new[] { "", "ARGON2 SETTINGS" }, 5));
                listSett.Items.Add(new ListViewItem(new[] { "", "MEMORY SIZE", _xmlConfig.GetValue("Result.ArgonMemSize") }));
                listSett.Items.Add(new ListViewItem(new[] { "", "ITERATIONS", _xmlConfig.GetValue("Result.ArgonIterations") }));
                listSett.Items.Add(new ListViewItem(new[] { "", "PARALLELISM", _xmlConfig.GetValue("Result.ArgonParallelism") }));
                listSett.Items.Add(new ListViewItem(new[] { "", "HASH SIZE", _xmlConfig.GetValue("Result.ArgonHashSize") }));

                // ==========================================
                // SCRYPT KDF PARAMETERS SECTION
                // ==========================================
                // Maps computing difficulty dimensions including structural block sizing and parallel tracking bounds
                listSett.Items.Add(new ListViewItem(new[] { "", "SCRYPT SETTINGS" }, 6));
                listSett.Items.Add(new ListViewItem(new[] { "", "MEMORY SIZE", _xmlConfig.GetValue("Result.ScryptMemSize") }));
                listSett.Items.Add(new ListViewItem(new[] { "", "BLOCK SIZE", _xmlConfig.GetValue("Result.ScryptBlockSize") }));
                listSett.Items.Add(new ListViewItem(new[] { "", "PARALLELIZATION", _xmlConfig.GetValue("Result.ScryptParallelization") }));
                listSett.Items.Add(new ListViewItem(new[] { "", "HASH SIZE", _xmlConfig.GetValue("Result.ScryptHashSize") }));

                // ==========================================
                // BCRYPT ROUNDS SECTION
                // ==========================================
                // Binds the exponential structural cost work factors for targeted legacy sub-modules
                listSett.Items.Add(new ListViewItem(new[] { "", "BCRYPT ROUNDS" }, 7));
                listSett.Items.Add(new ListViewItem(new[] { "", "ROUNDS", _xmlConfig.GetValue("Result.BCryptRounds") }));

                // ==========================================
                // PBKDF2 ROUNDS SECTION
                // ==========================================
                // Binds the static computational stretching repetition iteration parameters
                listSett.Items.Add(new ListViewItem(new[] { "", "PBKDF2 ROUNDS" }, 7));
                listSett.Items.Add(new ListViewItem(new[] { "", "ROUNDS", _xmlConfig.GetValue("Result.PBKDF2Rounds") }));

                // ==========================================
                // SECURE DELETION ENGINE SECTION
                // ==========================================
                // Maps data shredding schemas determining localized object lifecycle management
                listSett.Items.Add(new ListViewItem(new[] { "", "SECURE DELETION ENGINE" }, 8));
                listSett.Items.Add(new ListViewItem(new[] { "", "ENGINE", _xmlConfig.GetValue("Result.DeleteEngine") }));

                // Establishes runtime volatile flags governing screen capture blocking boundaries
                Obfs = _xmlConfig.GetValue("Result.ObfuscatePrintScreen") == "True";

                labRSAKeySize.Text = _xmlConfig.GetValue("Result.RSAKeySize");
                txtPGPFolderPath.Text = _xmlConfig.GetValue("Result.PGPKeyFolderPath");

                // Enforces active workspace layout re-indexing boundaries depending on preference state variables
                if ((tabControl1.SelectedIndex == 2 || tabControl1.SelectedIndex == 3 || tabControl1.SelectedIndex == 4) && Sett == true)
                {
                    tabControl1.SelectedIndex = 0;
                    Sett = false;
                }

                // Executes asynchronous keyset generation synchronization mappings for asymmetric components
                PGPKeys();

                // Evaluates runtime condition validation boundaries to safely toggle cryptographic UI execution hooks based on active engine states
                if (listSett.Items[1].SubItems[1].Text == "PGP")
                {
                    encryptionListMenu.Enabled = _rescor > 2 && listFiles.Items.Count > 0 && _pgpK == false;
                    tStripBtnEncryption.Enabled = encryptionListMenu.Enabled;
                    encryptListStripMenu.Enabled = encryptionListMenu.Enabled;
                    btnPGPKeygen.Enabled = secMasKey.Text != string.Empty && _rescor > 2 && txtPGPFolderPath.Text != string.Empty;
                }
                else
                {
                    encryptionListMenu.Enabled = _rescor > 2 && listFiles.Items.Count > 0;
                    tStripBtnEncryption.Enabled = encryptionListMenu.Enabled;
                    encryptListStripMenu.Enabled = encryptionListMenu.Enabled;
                    btnPGPKeygen.Enabled = false;
                }

            }
            catch (Exception ex)
            {
                // Traps unexpected framework processing configuration faults to prevent complete application execution failure
                CentralLog.LogException(ex, "MAIN", "Handled exceptions during module loading!");
            }
        }

        /// <summary>
        /// Populates the application configuration display structure with baseline cryptographic fallback vectors
        /// when specialized external XML layout specifications are absent or inaccessible.
        /// </summary>
        public void DefaultSettings()
        {
            try
            {
                listSett.Items.Clear();
                
                // ==========================================
                // DEFAULT ENCRYPTION ENGINES
                // ==========================================
                // Populates core symmetric configuration matrices with fallback security parameters
                listSett.Items.Add(new ListViewItem(new[] { "", "ENCRYPTION ENGINE" }, 0));
                listSett.Items.Add(new ListViewItem(new[] { "", "AES", "K128" }));

                // ==========================================
                // DEFAULT ENCRYPTION STRING STRETCHING
                // ==========================================
                listSett.Items.Add(new ListViewItem(new[] { "", "ENCRYPTION STRING" }, 1));
                listSett.Items.Add(new ListViewItem(new[] { "", "THREEFISH", "100000" }));

                // ==========================================
                // DEFAULT PRIMITIVE HASH SELECTION
                // ==========================================
                listSett.Items.Add(new ListViewItem(new[] { "", "HASH ENGINES" }, 2));
                listSett.Items.Add(new ListViewItem(new[] { "", "SCRYPT", "IMPLICIT" }));

                // ==========================================
                // DEFAULT ENTROPY GENERATION
                // ==========================================
                listSett.Items.Add(new ListViewItem(new[] { "", "PSEUDO NUMBER GENERATOR" }, 3));
                listSett.Items.Add(new ListViewItem(new[] { "", "BCRYPT", "IMPLICIT" }));

                // ==========================================
                // AUXILIARY CHECKSUM OPERATIONS
                // ==========================================
                listSett.Items.Add(new ListViewItem(new[] { "", "INTERNAL FUNCTIONS" }, 4));
                listSett.Items.Add(new ListViewItem(new[] { "", "BLAKE-256", "IMPLICIT" }));

                // ==========================================
                // FALLBACK ARGON2 DESCRIPTORS
                // ==========================================
                // Assigns memory dimensions, iteration steps, and core multi-threading vectors for Argon2 operational execution
                listSett.Items.Add(new ListViewItem(new[] { "", "ARGON2 SETTINGS" }, 5));
                listSett.Items.Add(new ListViewItem(new[] { "", "MEMORY SIZE", "65536" }));
                listSett.Items.Add(new ListViewItem(new[] { "", "ITERATIONS", "3" }));
                listSett.Items.Add(new ListViewItem(new[] { "", "PARALLELISM", "4" }));
                listSett.Items.Add(new ListViewItem(new[] { "", "HASH SIZE", "S64" }));

                // ==========================================
                // FALLBACK SCRYPT DESCRIPTORS
                // ==========================================
                listSett.Items.Add(new ListViewItem(new[] { "", "SCRYPT SETTINGS" }, 6));
                listSett.Items.Add(new ListViewItem(new[] { "", "MEMORY SIZE", "16384" }));
                listSett.Items.Add(new ListViewItem(new[] { "", "BLOCK SIZE", "8" }));
                listSett.Items.Add(new ListViewItem(new[] { "", "PARALLELIZATION", "1" }));
                listSett.Items.Add(new ListViewItem(new[] { "", "HASH SIZE", "S64" }));

                // ==========================================
                // HARDENED BCRYPT ROUNDS SELECTION
                // ==========================================
                // TECHNICAL NOTE: BCrypt default iterations are established at R12 to guarantee 
                // optimal cryptographic work-factor latency versus resource consumption constraints, 
                // strictly matching Speedcrypt core architectural principles of rigor and systemic trust.
                listSett.Items.Add(new ListViewItem(new[] { "", "BCRYPT ROUNDS" }, 7));
                listSett.Items.Add(new ListViewItem(new[] { "", "ROUNDS", "R12" }));

                // ==========================================
                // HARDENED PBKDF2 ROUNDS SELECTION
                // ==========================================
                listSett.Items.Add(new ListViewItem(new[] { "", "PBKDF2 ROUNDS" }, 7));
                listSett.Items.Add(new ListViewItem(new[] { "", "ROUNDS", "100000" }));

                // ==========================================
                // SECURE LIFE-CYCLE DATA DELETION
                // ==========================================
                listSett.Items.Add(new ListViewItem(new[] { "", "SECURE DELETION ENGINE" }, 8));
                listSett.Items.Add(new ListViewItem(new[] { "", "ENGINE", "Secure Delete" }));

                labRSAKeySize.Text = "K3072";

                // Establishes runtime volatile flags governing screen capture blocking boundaries
                Obfs = _xmlConfig.GetValue("Result.ObfuscatePrintScreen") == "True";// This code is also needed here
            }
            catch (Exception ex)
            {
                // Traps unexpected configuration processing anomalies to isolate UI state rendering breakdowns
                CentralLog.LogException(ex, "MAIN", "Handled exceptions during module loading!");
            }
        }
        /// <summary>
        /// Configures the user interface states and sets volatile operational flags 
        /// to reflect that the automated structural key destruction sequence is enabled.
        /// </summary>
        public void DelConfigFile()
        {
            AutomaticDel = true;
            grbConfiguration.Text = "Configuration File...";
            grbConfiguration.ForeColor = Color.Brown;
            labConfiguration.Text = "Automatic key deletion is enabled. Warning: Do not use this mode if you want to make copies of encrypted files!";

            // Assign structural indicator symbols to signify high-risk operational profiles
            picConfiguration.Image = ForAllUnits.Ledred16;
            picMode.Image = ForAllUnits.Warning32;
            labConfiguration.ForeColor = Color.Red;
        }

        /// <summary>
        /// Configures the user interface states and updates volatile operational flags 
        /// to reflect that the automated structural key destruction sequence is disabled.
        /// </summary>
        public void DelNoConfigFile()
        {
            AutomaticDel = false;
            grbConfiguration.Text = "Configuration File...";
            grbConfiguration.ForeColor = Color.Brown;
            labConfiguration.Text = "Automatic key deletion is disabled. You can back up your encrypted files and decrypt them whenever necessary!";

            // Assign structural indicator symbols to signify nominal operational backup profiles
            picConfiguration.Image = ForAllUnits.Ledgreen16;
            picMode.Image = ForAllUnits.Backup32;
            labConfiguration.ForeColor = Color.Black;
        }

        /// <summary>
        /// Executes the comprehensive automated diagnostics suite asynchronously to validate engine integrity, 
        /// updates visual telemetry indicators, and governs programmatic thread execution controls.
        /// </summary>
        void SelfTest()
        {
            // Initialize temporary diagnostic telemetry states and restrict interface interactions to prevent concurrency race conditions
            labAutoImage.Image = ForAllUnits.Ledorange16;
            labAutoText.Text = "Speedcrypt Self-Test: IN PROGRESS...";
            btnUp.Enabled = false;
            btnDown.Enabled = false;

            // Instantiate the primary hardware-accelerated test matrix container passing structural progress feedback pointers
            var autoTest = new SpeedcryptAutotest(SpeedcryptAutotest.TestMode.Complete, listTest, testProgressBar);

            // Invoke structural evaluation routines and capture block execution validation criteria
            bool allPassed = autoTest.Run();
            if (allPassed)
            {
                // Commit success validation tokens across localized UI tracking structures
                labAutoImage.Image = ForAllUnits.Ledgreen16;
                labAutoText.Text = "Speedcrypt Self-Test:  > [ PASSED ]";
            }
            else
            {
                // Enforce fallback alerting layout states to signify severe architectural verification failures
                labAutoImage.Image = ForAllUnits.Ledred16;
                labAutoText.Text = "Speedcrypt Self-Test:  > [ FAILED ]";
            }

            // Re-establish command chain interactions upon diagnostic verification completion
            btnUp.Enabled = true;
        }

        #endregion Work Enviroment

        #region PGP Keys

        /// <summary>
        /// Triggers the asynchronous RSA public/private keypair generation routine, manages off-thread rendering 
        /// metrics via localized progress callbacks, encrypts operational initialization vectors, 
        /// and commits structural dynamic context metadata to the localized XML storage configuration.
        /// </summary>
        /// <summary>
        /// Triggers the asynchronous RSA public/private keypair generation routine, manages off-thread rendering 
        /// metrics via localized progress callbacks, encrypts operational initialization vectors, 
        /// and commits structural dynamic context metadata to the localized XML storage configuration.
        /// </summary>
        private void BtnPGPKeygen_Click(object sender, EventArgs e)
        {
            bool success = false;
            try
            {
                if (secMasKey.Text == string.Empty) return;

                DialogResult result = MessageBox.Show("Warning: Speedcrypt is generating RSA keys. Any existing keys in the selected folder will be overwritten. I must continue?",
                                                      ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (result != DialogResult.Yes)
                    return;

                if (!Directory.Exists(txtPGPFolderPath.Text)) Directory.CreateDirectory(txtPGPFolderPath.Text);

                success = true;

                progressBar2.Minimum = 0;
                progressBar2.Maximum = 100;
                progressBar2.Value = 0;

                Keymaterial();

                // Temporarily elevate DPAPI unmanaged context to retrieve the plaintext target material for processing
                ProtectedMemory.Unprotect(Filepass, MemoryProtectionScope.SameLogon);

                int lastValue = 0;

                // Local function for progress updates
                // Enforces localized marshalling protocols back into the primary thread window context
                void ProgressCallback(int percent)
                {
                    this.Invoke(new Action(() =>
                    {
                        if (percent > lastValue)
                        {
                            int step = (percent - lastValue) / 5;
                            step = step == 0 ? 1 : step;

                            for (int i = lastValue + step; i <= percent; i += step)
                            {
                                progressBar2.Value = i > 100 ? 100 : i;
                                Application.DoEvents();
                            }

                            lastValue = percent;
                        }
                    }));
                }

                // Assign to Action<int> if needed elsewhere
                Action<int> progressCallback = ProgressCallback;

                // Dispatch heavy cryptographic task matrices to the background thread pool allocation layer
                Task.Run(() =>
                {
                    RSAkeygenerator.GenerateKey(BitConverter.ToString(Hashpass).ToLower().Replace("-", ""),
                    txtPGPFolderPath.Text, int.Parse(Regex.Match(labRSAKeySize.Text, @"\d+").Value,
                    System.Globalization.CultureInfo.InvariantCulture), progressCallback);

                    this.Invoke(new Action(() =>
                    {
                        MessageBox.Show("Keys generated successfully", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);

                        _pgpK = false;
                        btnPGPKeygen.Enabled = false;
                        progressBar2.Value = 0;

                        // Execute deterministic memory wipe sequences across input storage locations immediately
                        SecureWipe.WipeSecureTextBox(secMasKey);
                        SecureWipe.WipeSecureTextBox(secPasw);

                        NewSalt = _protectedSalt.GetUnprotected();

                        if (success)
                        {
                            var crypto = new CryptoAdapterByte();

                            // Encrypt volatile operational initialization components using structural data engine configurations
                            string encryptedsalt = BitConverter.ToString(crypto.Encrypt(listSett.Items[3].SubItems[1].Text, NewSalt, Filepass,
                            int.Parse(listSett.Items[3].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture))).ToLower().Replace("-", "");

                            Arrayclear();

                            string configKeyPrefix = "PGPEencryptedSalt";
                            int count = 0;

                            // Evaluate pre-existing structured key pairs within the programmatic tree to isolate duplicate tracking vectors
                            foreach (var kvp in AppConfigHelper.XmlConfig.GetAllKeyValuePairs())
                            {
                                if (kvp.Value.StartsWith(txtPGPFolderPath.Text + "|"))
                                {
                                    string[] parts = kvp.Key.Split('-');
                                    if (parts.Length == 2 && int.TryParse(parts[1], out int existingCount))
                                        count = existingCount;
                                    break;
                                }
                            }

                            if (count == 0)
                                count = mkPGPRSACounter.Increment();

                            // Construct high-density configuration data string compiling multi-column subsystem states explicitly mapping indices
                            string uniqueKey = $"{txtPGPFolderPath.Text}|{encryptedsalt}|{listSett.Items[3].SubItems[1].Text}|{listSett.Items[5].SubItems[1].Text}|" +
                                               $"{listSett.Items[11].SubItems[2].Text}|{listSett.Items[12].SubItems[2].Text}|{listSett.Items[13].SubItems[2].Text}|" +
                                               $"{listSett.Items[14].SubItems[2].Text}|{listSett.Items[16].SubItems[2].Text}|{listSett.Items[17].SubItems[2].Text}|" +
                                               $"{listSett.Items[18].SubItems[2].Text}|{listSett.Items[19].SubItems[2].Text}|{listSett.Items[21].SubItems[2].Text}|" +
                                               $"{listSett.Items[23].SubItems[2].Text}|{count}|{"EnginePGP"}";

                            AppConfigHelper.XmlConfig.SetValue($"{configKeyPrefix}-{count}", uniqueKey);
                            AppConfigHelper.Save();

                            if (chkOpenFolder.Checked)
                            {
                                Process.Start(txtPGPFolderPath.Text);
                            }
                            if (chkDisplayRSA.Checked)
                            {
                                rchPublicKey.Text = File.ReadAllText(Path.Combine(txtPGPFolderPath.Text, "PGPPublicKeyRSA.asc"));
                                btnCleartext.Enabled = true;
                            }
                        }
                    }));
                });
            }
            catch (Exception ex)
            {
                // Handle unexpected application breakdown vectors across the generation lifecycle components
                MessageBox.Show("Error during PGP keys generation! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "MAIN", "Error during PGP keys generation!");
            }
        }

        /// <summary>
        /// Clears the RichTextBox containing the PGP engine public key.
        /// </summary>
        private void BtnCleartext_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("Do you really want to clear the text displaying the PGP public key?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result == DialogResult.No)
                return;
            rchPublicKey.Clear();
            btnCleartext.Enabled = false;
        }
        /// <summary>
        /// Handles focus tracking mutations when the pointer input enters the operational boundary area.
        /// </summary>
        private void BtnPGPKeygen_MouseEnter(object sender, EventArgs e)
        {
            labKeys.ForeColor = Color.Red;
        }

        /// <summary>
        /// Restores default focus tracking layouts when the pointer input abandons the operational boundary area.
        /// </summary>
        private void BtnPGPKeygen_MouseLeave(object sender, EventArgs e)
        {
            labKeys.ForeColor = Color.Black;
        }

        /// <summary>
        /// Inspects target directory properties utilizing internal validator hooks to verify asymmetric infrastructure availability states.
        /// </summary>
        void PGPKeys()
        {
            _pgpK = false;
            bool hasEngine = MiniPgpPathValidator.HasPgpEngine(txtPGPFolderPath);
            if (!hasEngine) _pgpK = true;
        }

        /// <summary>
        /// Executes a comprehensive memory sanitization sequence over vital keys, arrays, and buffers, then commands structural score updates.
        /// </summary>
        void Arrayclear()
        {
            // Deploy specialized cryptographic scrubbing routines across volatile data arrays to guarantee zero remnant visibility
            SecureWipe.WipeArray(Filepass);
            Filepass = null;
            SecureWipe.WipeArray(Hashpass);
            Hashpass = null;
            SecureWipe.WipeArray(Hashrec);
            Hashrec = null;

            SecureWipe.WipeArray(Salt);
            Salt = null;
            SecureWipe.WipeArray(NewSalt);
            NewSalt = null;
            SecureWipe.WipeArray(DecSalt);
            DecSalt = null;

            // Securely purge managed structural UI input controls
            SecureWipe.WipeSecureTextBox(secMasKey);
            SecureWipe.WipeSecureTextBox(secPasw);
            _protectedSalt.Dispose();

            // Re-evaluate programmatic metric vectors after cleanup execution
            UpdatePasswordScore();
        }

        #endregion PGP Keys

        #region Encrypted Files

        /// <summary>
        /// Evaluates pointer location criteria within the encrypted file grid component during mouse release vectors,
        /// enforces conditional state boundaries based on item presence metrics, and binds context menus dynamic properties.
        /// </summary>
        private void ListFileEnc_MouseUp(object sender, MouseEventArgs e)
        {
            // Only right mouse button
            if (e.Button != MouseButtons.Right)
                return;

            listFileEnc.ContextMenuStrip = null;

            ListViewHitTestInfo hitTest = listFileEnc.HitTest(e.Location);

            if (hitTest.Item != null)
            {
                Missingcontrol();

                bool fileMissing = hitTest.Item.ForeColor == Color.Gray;

                // Single file actions
                openFolderEncMenu.Enabled = !fileMissing;
                openFileEncMenu.Enabled = !fileMissing;
                selectedEncMenu.Enabled = !fileMissing;
                filePropertiesEncMenu.Enabled = !fileMissing;

                // Entire group action
                bool allMissing = true;

                foreach (ListViewItem item in listFileEnc.Items)
                {
                    if (item.ForeColor != Color.Gray)
                    {
                        allMissing = false;
                        break;
                    }
                }

                entireEncMenu.Enabled = !allMissing;

                // Assign context menu
                listFileEnc.ContextMenuStrip = contextMenuEncFile;
            }
        }

        /// <summary>
        /// Intercepts active tab container navigation changes, executing targeted structural refresh sequences,
        /// metrics recalculation routines, and control state constraints depending on the focused layout index.
        /// </summary>
        private void TabControl1_SelectedIndexChanged(object sender, EventArgs e)
        {
            switch (tabControl1.SelectedIndex)
            {
                case 0:
                    
                    SelfUpdown();
                    labFileTot.Text = "File Selection";

                    break;
                case 2:
                    
                    if (listFiles.Items.Count == 0) labFileTot.Text = "File Selection";
                    else RecalculateAll();
                    
                    SelfDisable();

                    break;
                case 3:
                    
                    labFileTot.Text = "File Selection";
                    
                    SelfDisable();
                    UpdateNodes();

                    break;
                case 1:
                case 4:
                    
                    labFileTot.Text = "File Selection";
                    SelfDisable();

                    break;
            }
        }

        /// <summary>
        /// Scans the persistent encrypted files list view infrastructure, cross-references physical stream attributes 
        /// against structural grid row metadata using double-key validation parameters, and applies visual indicators dynamically.
        /// </summary>
        void Missingcontrol()
        {
            listFileEnc.BeginUpdate();

            foreach (ListViewItem item in listFileEnc.Items)
            {
                // Extract parameters directly from the main encrypted files list structure
                string encryptedFilePath = item.SubItems[2].Text;
                string recordAlgorithm = item.SubItems[6].Text?.Trim(); // Field 7 (Index 6) contains the algorithm
                string recordGroupId = item.SubItems[8].Text?.Trim();   // Field 9 (Index 8) contains the group ID

                bool isFileValid = false;

                if (File.Exists(encryptedFilePath))
                {
                    try
                    {
                        // Open file stream using volatile shared-access parameters for secure execution
                        using (var fs = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            // FIXED: Restrict memory boundaries by evaluating only the initial structural segment (max 1024 bytes) to prevent critical OutOfMemory exceptions on massive corrupted assets
                            byte[] buffer = new byte[1024];
                            int bytesRead = fs.Read(buffer, 0, buffer.Length);

                            if (bytesRead > 0)
                            {
                                string rawContent = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                                // Isolate the programmatic first line segment safely without standard text stream scanning vulnerabilities
                                int endOfLineIndex = rawContent.IndexOfAny(new char[] { '\r', '\n' });
                                string header = endOfLineIndex >= 0 ? rawContent.Substring(0, endOfLineIndex) : rawContent;

                                if (!string.IsNullOrEmpty(header))
                                {
                                    string[] headerParts = header.Split('|');
                                    if (headerParts.Length >= 3)
                                    {
                                        // Parse actual file attributes out of the raw stream line segment
                                        string actualAlgorithm = headerParts[1]?.Trim();
                                        string actualGroupId = headerParts[2]?.Trim();

                                        // Assert double-key verification (Engine identity matching + Target Group integrity)
                                        if (recordAlgorithm == actualAlgorithm && recordGroupId == actualGroupId)
                                        {
                                            isFileValid = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Suppress access violations silently to guarantee mainstream execution safety
                        isFileValid = false;
                    }
                }

                // Apply global context color rules based on combined validation criteria results
                Color color = isFileValid ? listFileEnc.ForeColor : Color.Gray;

                if (item.ForeColor != color)
                {
                    item.ForeColor = color;

                    foreach (ListViewItem.ListViewSubItem subItem in item.SubItems)
                        subItem.ForeColor = color;
                }
            }

            listFileEnc.EndUpdate();
        }

        /// <summary>
        /// Synchronizes the encrypted files data presentation grid by executing targeted item removal operations, 
        /// accumulates exact data size metrics from structural object tags, and updates boundary UI status text containers.
        /// </summary>
        void UpdateEncList(bool onlySelected)
        {
            // If the operation targets only selected items
            if (onlySelected)
            {
                // No selection means nothing to remove
                if (listFileEnc.SelectedItems.Count == 0)
                    return;

                // Remove selected items one by one
                // Copy to array to avoid modifying the collection during iteration
                ListViewItem[] itemsToRemove = new ListViewItem[listFileEnc.SelectedItems.Count];
                listFileEnc.SelectedItems.CopyTo(itemsToRemove, 0);

                foreach (ListViewItem item in itemsToRemove)
                {
                    listFileEnc.Items.Remove(item);
                }
            }
            else
            {
                // Explicitly remove all items
                listFileEnc.Items.Clear();
            }

            long totalBytes = 0;

            foreach (ListViewItem item in listFiles.Items)
            {
                // Safely extract the exact byte size from the Tag property to avoid precision loss from string parsing
                if (item.Tag is long sizeInBytes)
                {
                    totalBytes += sizeInBytes;
                }
                else if (item.Tag is int sizeInBytesInt)
                {
                    totalBytes += sizeInBytesInt;
                }
            }            

            // Update status label with precise data
            labFileTot.Text = $"File list: {listFiles.Items.Count} files, {ByteCnt.FromBytes(totalBytes)} total";

            // Enforce absolute structural layout string consistency ("File Selection") across all contextual list state evaluations
            if (listFileEnc.Items.Count == 0)
                labFileTot.Text = "File Selection";
        }
       
        /// <summary>
        /// Synchronizes the hierarchical engine tree structure by dynamically calculating active cipher configurations, 
        /// invoking asynchronous control marshalling, and executing regex-driven node targeting sequences.
        /// </summary>
        public void UpdateNodes()
        {
            // 1) Store the initial state of the current algorithm
            string currentAlgorithm = listSett.Items[1].SubItems[1].Text?.Trim();
            treeEngines.Tag = currentAlgorithm;

            // 2) Refresh engines and encrypted file counts
            TreeEngines engines = new TreeEngines(treeEngines, labFileTot, listFileEnc, _xmlConfig);
            engines.Initialize();
            engines.UpdateFilesEncryptedCount();

            // =========================================================================
            // UI APPLY & TAIL STRATEGY (Clean asynchronous execution)
            // =========================================================================
            treeEngines.BeginInvoke((MethodInvoker)delegate
            {
                if (treeEngines.Nodes.Count == 0)
                    return;

                // Safety guard: Ensure the absolute root node exists before inspecting its children
                if (treeEngines.Nodes.Count > 0 && treeEngines.Nodes[0].Nodes != null)
                {
                    // CRITICAL: Prevent flickering by suspending the control layout paint operations
                    treeEngines.BeginUpdate();

                    try
                    {
                        // Clean baseline: Collapse exclusively the direct child engine nodes under Node 0
                        foreach (TreeNode engineChildNode in treeEngines.Nodes[0].Nodes)
                        {
                            engineChildNode.Collapse(false);
                        }

                        // Fetch the target algorithm identifier with normalized whitespace processing
                        string targetAlgorithmText = listSett.Items[1].SubItems[1].Text?.Trim();

                        if (!string.IsNullOrEmpty(targetAlgorithmText))
                        {
                            string cleanTarget = targetAlgorithmText.ToLowerInvariant();

                            // Scan through the 11 engine nodes located under Node 0 using case-insensitive validation
                            foreach (TreeNode parentEngineNode in treeEngines.Nodes[0].Nodes)
                            {
                                string nodeTag = (parentEngineNode.Tag as string)?.Trim().ToLowerInvariant();
                                string nodeText = parentEngineNode.Text?.Trim().ToLowerInvariant();

                                if (nodeTag == cleanTarget || nodeText == cleanTarget)
                                {
                                    // Target identified: Expand this single container to display its nested group sub-elements
                                    parentEngineNode.Expand();
                                    parentEngineNode.EnsureVisible();

                                    // Resolve Target Child: Default to the last nested group child node if available
                                    TreeNode targetFocusNode = parentEngineNode;

                                    if (parentEngineNode.Nodes != null && parentEngineNode.Nodes.Count > 0)
                                    {
                                        // Dynamic target resolution: Identify the node with the highest sequential number in text
                                        var realLastNode = Enumerable.Cast<TreeNode>(parentEngineNode.Nodes)
                                            .Select(node => new
                                            {
                                                Node = node,
                                                // Extract numeric digit sequence from node text; default to -1 if no numbers exist
                                                Number = int.TryParse(Regex.Match(node.Text ?? "", @"\d+").Value, out int num) ? num : -1
                                            })
                                            .OrderByDescending(x => x.Number).Select(x => x.Node).FirstOrDefault();

                                        // Fallback guard: Use the physical index backup if the LINQ sorting strategy yields no match
                                        targetFocusNode = realLastNode ?? parentEngineNode.Nodes[parentEngineNode.Nodes.Count - 1];
                                    }

                                    // Target Selection Focus: Update active cursor node and assign hardware input focus
                                    treeEngines.SelectedNode = targetFocusNode;
                                    targetFocusNode.EnsureVisible();
                                    treeEngines.Focus();

                                    break;
                                }
                            }
                        }
                    }
                    finally
                    {
                        // CRITICAL: Resume control painting and apply all structural updates in a single frame render
                        treeEngines.EndUpdate();
                        if (listFileEnc.Items.Count == 0) labFileTot.Text = "File Selection"; // Required if the listview is empty
                    }
                }
            });
        }

        #endregion Encrypted Files

        #region Exception Log

        /// <summary>
        /// Evaluates mouse release locations within the logging grid to dynamically calculate 
        /// and enforce transactional state constraints for contextual item manipulation triggers.
        /// </summary>
        private void ListLog_MouseUp(object sender, MouseEventArgs e)
        {
            // Check if any item is under the mouse
            ListViewHitTestInfo hit = listLog.HitTest(e.Location);

            // Enable the delete button only if an item is selected and the click is on an item
            btnDelitem.Enabled = hit.Item != null && listLog.SelectedItems.Count > 0;
        }

        /// <summary>
        /// Triggers user validation dialog prompts before committing full destructive log clearing routines 
        /// through the persistent file manager infrastructure and synchronizes visualization components.
        /// </summary>
        private void BtnDelog_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("Do you really want to clear the Speedcrypt error log?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result != DialogResult.Yes)
                return;

            LogManager.ClearLog();
            CentralLog.LoadLogFromFile(CentralLog.LogListView);

            btnmanager();
        }

        /// <summary>
        /// Prompts confirmation validation boundaries to execute a localized volatile view item purge, 
        /// flags recovery availability, and updates structural command state tracking metrics.
        /// </summary>

        /// <summary>
        /// Executes conditional removal sequences on user-selected tracking entities, updates UI control lifecycle states 
        /// via transactional element purging, and synchronizes system status indicators through localized metric evaluation.
        /// </summary>
        /// <summary>
        /// Executes conditional removal sequences on user-selected tracking entities, optimizes UI rendering pathways 
        /// via visual state suspension, and synchronizes system status indicators through localized metric evaluation.
        /// </summary>
        private void BtnDelitem_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("Are you sure you want to remove the selected items?\r\nThis action does not delete the log data!",
                                                   ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result == DialogResult.No)
                return;

            // Suspends visual presentation redraw threads to optimize layout mutations and prevent screen flickering
            listLog.BeginUpdate();
            try
            {
                if (listLog.SelectedItems.Count > 0)
                {
                    // Cycles backward to safely remove items from the collection without triggering enumeration faults
                    for (int i = listLog.SelectedItems.Count - 1; i >= 0; i--)
                    {
                        listLog.Items.Remove(listLog.SelectedItems[i]);
                    }

                    btnRestore.Enabled = true;
                    btnmanager();
                    btnDelitem.Enabled = false; // Kept at false at the end of the batch operation as requested
                }
            }
            finally
            {
                // Commands immediate visual presentation layer restoration post-mutation routines execution
                listLog.EndUpdate();
            }
        }

        /// <summary>
        /// Re-initializes raw stream operational parsing mappings from local disk files to completely restore the view grid components.
        /// </summary>
        private void BtnRestore_Click(object sender, EventArgs e)
        {
            CentralLog.LoadLogFromFile(listLog);
            btnRestore.Enabled = false;
            btnmanager();
        }       

        /// <summary>
        /// Parses dynamic token entries, resolves matching evaluation column offsets via selection vectors, 
        /// and enforces differential sub-item foreground chromatic fading masks to optimize scannability metrics.
        /// </summary>
        private void TxtProcname_TextChanged(object sender, EventArgs e)
        {
            // ENTERPRISE UI LOCK: Initialize visual suppression framework immediately at method entry
            listLog.BeginUpdate();

            string filterText = txtProcname.Text.ToLower();
            string selectedField = cmbField.Text;

            int col = -1;
            if (selectedField == "EXCEPTION") col = 1;
            else if (selectedField == "STATUS") col = 2;
            else if (selectedField == "MODULE") col = 3;
            else if (selectedField == "TIMESTAMP") col = 4;
            else if (selectedField == "METHOD") col = 5;
            else if (selectedField == "STACKTRACE") col = 6;
            else if (selectedField == "NOTES") col = 7;

            int filteredCount = 0;

            foreach (ListViewItem item in listLog.Items)
            {
                // DEFENSIVE BOUNDARY VALIDATION: Prevent index out of range exceptions on dynamic sub-items
                if (col != -1 && item.SubItems.Count <= col)
                    continue;

                bool match = col == -1 || string.IsNullOrEmpty(filterText) ||
                             item.SubItems[col].Text.ToLower().Contains(filterText);

                for (int i = 0; i < item.SubItems.Count; i++)
                {
                    if (i == 2 || i == 8) // STATUS → They remain intact in color
                        continue;

                    item.SubItems[i].ForeColor = match
                        ? SystemColors.WindowText
                        : SystemColors.GrayText;
                }

                if (match)
                    filteredCount++;
            }

            // ENTERPRISE UI RELEASE: Commit visual changes synchronously to the screen surface
            listLog.EndUpdate();

            labFilter.Text = filteredCount.ToString();

            if (txtProcname.Text == string.Empty)
                labFilter.Text = listLog.Items.Count.ToString();
        }

        /// <summary>
        /// Resets active string filters and forces low-level hardware cursor focus acquisition into the primary query textbox control.
        /// </summary>
        private void CmbField_SelectedIndexChanged(object sender, EventArgs e)
        {
            // Encapsulates UI state transitions within an explicit redraw inhibition block to eliminate layout flickering
            listLog.BeginUpdate();

            // Flushes stale evaluation inputs and refocuses user hardware carets onto the pattern matching input textbox
            txtProcname.Clear();
            txtProcname.Focus();

            // Re-enables the visual rendering loop only after the data reset transaction is completely finalized
            listLog.EndUpdate();
        }

        /// <summary>
        /// Evaluates and registers operational deletion configuration matrices based on systemic list selection mutations.
        /// </summary>
        private void CmbDeletion_SelectedIndexChanged(object sender, EventArgs e)
        {
            Automaticdel();
        }

        /// <summary>
        /// Syncs automated removal behaviors reacting to user state modifications over global preference verification checkboxes.
        /// </summary>
        private void ChkAutomatic_CheckedChanged(object sender, EventArgs e)
        {
            Automaticdel();
        }

        /// <summary>
        /// Instantiates the alternating row coloration engine context, toggling structural visual contrast enhancements 
        /// across log list containers depending on checked validation states.
        /// </summary>
        private void ChkAlternate_CheckedChanged(object sender, EventArgs e)
        {
            _alternator = new ListViewRowAlternator(listLog);

            if (chkAlternate.Checked)
                _alternator.Enable();
            else
                _alternator.Disable();
        }

        /// <summary>
        /// Triggers external log record stream importation processes using stateful overwrite parameters 
        /// and re-synchronizes localized primary visualization structures upon operation success.
        /// </summary>
        private void BtnImplog_Click(object sender, EventArgs e)
        {
            bool overwrite = chkOverwrite.Checked;

            if (LogManager.ImportLog(overwrite))
                CentralLog.LoadLogFromFile(CentralLog.LogListView);

            btnRestore.Enabled = false;

            btnmanager();
        }

        /// <summary>
        /// Invokes core serialization infrastructure components to export persistent application log streams to local target storage.
        /// </summary>
        private void BtnExplog_Click(object sender, EventArgs e)
        {
            if (listLog.Items.Count > 0)
                LogManager.ExportLog();
        }

        /// <summary>
        /// Evaluates telemetry log volume parameters against user preference thresholds, updates visual indicator bitmaps, 
        /// and executes full log clearing routines upon overflow detection.
        /// </summary>
        void Automaticdel()
        {
            bool enabled = chkAutomatic.Checked;

            picAutom.Image = enabled ? ForAllUnits.Ledgreen16 : ForAllUnits.Ledred16;

            if (!enabled)
            {
                labAutomdel.Text = "0";
                return;
            }

            labAutomdel.Text = (int.Parse(cmbDeletion.Text, System.Globalization.CultureInfo.InvariantCulture) -
                               listLog.Items.Count).ToString(System.Globalization.CultureInfo.InvariantCulture);

            if (listLog.Items.Count >= int.Parse(cmbDeletion.Text, System.Globalization.CultureInfo.InvariantCulture))
            {
                LogManager.ClearLog();
                CentralLog.LoadLogFromFile(CentralLog.LogListView);
                picAutom.Image = ForAllUnits.Ledred16;
                labAutomdel.Text = "0";
            }
        }

        /// <summary>
        /// Intercepts system error telemetry changes, implements thread-safe control marshalling via invoking protocols, 
        /// updates badge metrics, and fires conditional cleanup handlers.
        /// </summary>
        void OnLogCountChanged(int count)
        {
            if (labErrLog.InvokeRequired)
            {
                labErrLog.Invoke(new Action(() => labErrLog.Text = count.ToString()));
                pnlLog.Enabled = count > 0;

                if (count == 0)
                    listLog.Items.Clear();

                Automaticdel();
            }
            else
            {
                labErrLog.Text = count.ToString();
                pnlLog.Enabled = count > 0;

                if (count == 0)
                    listLog.Items.Clear();

                Automaticdel();
            }
            labFilter.Text = labErrLog.Text;
        }

        /// <summary>
        /// Orchestrates interface element states by evaluating telemetry thresholds, enforces conditional control visibility 
        /// via dynamic validation protocols, and synchronizes real-time counter metrics across local runtime displays.
        /// </summary>
        void btnmanager()
        {
            btnExplog.Enabled = listLog.Items.Count > 0;
            btnDelog.Enabled = listLog.Items.Count > 0;
            grbAutomatic.Enabled = listLog.Items.Count > 0;
            grbFind.Enabled = listLog.Items.Count > 0;
            labFilter.Text = listLog.Items.Count.ToString();
        }

        #endregion Exception Log

        #region Encrypt

        /// <summary>
        /// Extracts and assigns execution vectors for the Argon2 key derivation function framework,
        /// parsing structural configuration metadata utilizing locale-invariant transformation protocols.
        /// </summary>
        void Argonparam() // Argon 2 Parameters
        {
            // Secure numerical extraction using InvariantCulture for advanced cryptographic parameters
            HASHLib.memoryCost = int.Parse(listSett.Items[11].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.iterations = int.Parse(listSett.Items[12].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.parallelism = int.Parse(listSett.Items[13].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.hashSize = int.Parse(Regex.Match(listSett.Items[14].SubItems[2].Text, @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Extracts and maps processing configurations for the Scrypt memory-hard function engine,
        /// isolating difficulty dimensions via high-precision sequence matching subroutines.
        /// </summary>
        void Scrparam() // Scrypt Parameters
        {
            // Secure numerical extraction using InvariantCulture for advanced cryptographic parameters
            HASHLib.srcmem = int.Parse(listSett.Items[16].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.scrblksz = int.Parse(listSett.Items[17].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.scrparal = int.Parse(listSett.Items[18].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.scrhashsz = int.Parse(Regex.Match(listSett.Items[19].SubItems[2].Text, @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Executes the primary asynchronous file encryption operational lifecycle, handles cryptographic counter serializations,
        /// orchestrates multi-engine streaming infrastructures, and enforces dynamic fallback rollback boundaries.
        /// </summary>
        async Task FileEncrypt()
        {
            await Task.Run(() =>
            {
                try
                {
                    this.Invoke(new Action(() =>
                    {
                        labOperation.Text = "Ready for processing";
                        labOperation.ForeColor = Color.Black;
                    }));

                    Keymaterial();

                    NewSalt = _protectedSalt.GetUnprotected();
                    ProtectedMemory.Unprotect(Filepass, MemoryProtectionScope.SameLogon);

                    string engineName = listSett.Items[1].SubItems[1].Text;

                    // ATOMIC SESSION RESOLUTION: Pull current state directly from synchronous counter component
                    int sessionGroup = counters.GetCount(engineName);
                    sessionGroup++;

                    if (engineName == "PGP")
                    {
                        // ATOMIC WRITEBACK: Keep configuration synchronization locked with the localized counter increment
                        _xmlConfig.SetValue("COUNT-PGP", sessionGroup.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        // ATOMIC WRITEBACK: Keep symmetric matrix metadata aligned with the master session index
                        _xmlConfig.SetValue("COUNT-" + engineName, sessionGroup.ToString(System.Globalization.CultureInfo.InvariantCulture));

                        string configKeyPrefix = engineName + "EencryptedSalt";

                        var crypto = new CryptoAdapterByte();

                        string encryptedsalt = BitConverter.ToString(crypto.Encrypt(listSett.Items[3].SubItems[1].Text, NewSalt, Filepass,
                        int.Parse(listSett.Items[3].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture))).ToLower().Replace("-", "");

                        // Configuration file
                        string uniqueKey = $"{engineName}|{encryptedsalt}|{listSett.Items[3].SubItems[1].Text}|" +
                                           $"{listSett.Items[5].SubItems[1].Text}|" +
                                           $"{listSett.Items[11].SubItems[2].Text}|{listSett.Items[12].SubItems[2].Text}|" +
                                           $"{listSett.Items[13].SubItems[2].Text}|{listSett.Items[14].SubItems[2].Text}|" +
                                           $"{listSett.Items[16].SubItems[2].Text}|{listSett.Items[17].SubItems[2].Text}|" +
                                           $"{listSett.Items[18].SubItems[2].Text}|{listSett.Items[19].SubItems[2].Text}|" +
                                           $"{listSett.Items[21].SubItems[2].Text}|{listSett.Items[23].SubItems[2].Text}|" +
                                           $"{sessionGroup}|Engine{engineName}";

                        AppConfigHelper.XmlConfig.SetValue($"{configKeyPrefix}-{sessionGroup}", uniqueKey);                        
                    }

                    List<string> virtualList = new List<string>();
                    bool isCustomUser = false;
                    bool isCustomClassic = true;

                    string customValue = _xmlConfig.GetValue("Result.CustomValue");

                    if (!string.IsNullOrWhiteSpace(customValue))
                    {
                        virtualList = customValue.Split('|').Where(x => !string.IsNullOrWhiteSpace(x)).ToList();

                        if (virtualList.Count > 0)
                        {
                            isCustomUser = true;
                            isCustomClassic = false;
                        }
                    }

                    ListBox tempList = new ListBox();
                    tempList.Items.AddRange(virtualList.ToArray());

                    foreach (ListViewItem fileItem in Enumerable.ToList<ListViewItem>(Enumerable.Cast<ListViewItem>(listFiles.Items)))
                    {
                        try
                        {
                            string filePath = fileItem.SubItems[2].Text;

                            // Enterprise sanitization: Trim paths and strip eventual quotes to prevent WinIOError
                            if (!string.IsNullOrEmpty(filePath))
                            {
                                filePath = filePath.Trim().Trim('"');
                            }

                            // Enterprise silent bypass for non-existent filesystem objects
                            if (!System.IO.File.Exists(filePath))
                            {
                                continue;
                            }
                            // =========================
                            // PGP ENCRYPT
                            // =========================
                            if (engineName == "PGP")
                            {
                                string inputFile = filePath;
                                string outputFile = inputFile + ".SPCR";
                                string pgpKeyPath = Path.Combine(txtPGPFolderPath.Text, "PGPPublicKeyRSA.asc");

                                PgpEncryptor.EncryptFile(inputFile, outputFile, pgpKeyPath);

                                // HEADER STREAMING (NO READALLBYTES)
                                string header = $"SPCR|PGP|{sessionGroup}{Environment.NewLine}";
                                byte[] headerBytes = Encoding.UTF8.GetBytes(header);

                                string tempFile = outputFile + ".tmp";

                                using (FileStream original = new FileStream(outputFile, FileMode.Open, FileAccess.Read))
                                using (FileStream final = new FileStream(tempFile, FileMode.Create, FileAccess.Write))
                                using (HMACSHA256 hmac = new HMACSHA256(Filepass))
                                {
                                    // write header
                                    final.Write(headerBytes, 0, headerBytes.Length);
                                    hmac.TransformBlock(headerBytes, 0, headerBytes.Length, null, 0);

                                    // copy encrypted stream
                                    byte[] buffer = new byte[1024 * 1024];
                                    int read;

                                    while ((read = original.Read(buffer, 0, buffer.Length)) > 0)
                                    {
                                        final.Write(buffer, 0, read);
                                        hmac.TransformBlock(buffer, 0, read, null, 0);
                                    }

                                    hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                                    byte[] mac = hmac.Hash;
                                    final.Write(mac, 0, mac.Length);
                                }

                                if (IsFileEncrypted(inputFile, outputFile))
                                {
                                    UiListMutationManager.SafeRemoveItem(this, listFiles, fileItem, labRemainingFiles);
                                }

                                File.Delete(outputFile);
                                File.Move(tempFile, outputFile);

                                foreach (var kvp in AppConfigHelper.XmlConfig.GetAllKeyValuePairs())
                                {
                                    if (kvp.Value.StartsWith(txtPGPFolderPath.Text + "|"))
                                    {
                                        // Unique key using a GUID to prevent overwrites.
                                        string childKeyName = $"{Guid.NewGuid():N}_{Path.GetFileName(outputFile)}";

                                        FileInfo fi = new FileInfo(outputFile);

                                        string sizeKB = string.Format("{0:#,##0} KB", fi.Length / 1024).Replace("0 KB", "1 KB");
                                        string sizeExtended = fi.Strbytes();

                                        string childValue = $"{outputFile}|{sizeKB}|{fileItem.SubItems[4].Text}|" +
                                                            $"{sizeExtended}|PGP|{listSett.Items[1].SubItems[2].Text}|{sessionGroup}";

                                        AppConfigHelper.XmlConfig.SetChild(kvp.Key, childKeyName, childValue);
                                        break;
                                    }
                                }
                            }

                            // =================================================================
                            // NON-PGP ENCRYPT
                            // =================================================================
                            else
                            {
                                string spcrFile = filePath + ".SPCR";

                                EncryptionManager.EncryptFile(filePath, filePath, Hashpass,
                                    int.Parse(Regex.Match(listSett.Items[1].SubItems[2].Text, @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture),
                                    engineName
                                );

                                string header = $"SPCR|{engineName}|{sessionGroup}{Environment.NewLine}";
                                byte[] headerBytes = Encoding.UTF8.GetBytes(header);

                                string tempFile = spcrFile + ".tmp";

                                using (FileStream original = new FileStream(spcrFile, FileMode.Open, FileAccess.Read, FileShare.Read))
                                using (FileStream final = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None))
                                using (HMACSHA256 hmac = new HMACSHA256(Filepass))
                                {
                                    final.Write(headerBytes, 0, headerBytes.Length);
                                    hmac.TransformBlock(headerBytes, 0, headerBytes.Length, null, 0);

                                    byte[] buffer = new byte[1024 * 1024];
                                    int read;

                                    while ((read = original.Read(buffer, 0, buffer.Length)) > 0)
                                    {
                                        final.Write(buffer, 0, read);
                                        hmac.TransformBlock(buffer, 0, read, null, 0);
                                    }

                                    hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                                    byte[] mac = hmac.Hash;
                                    final.Write(mac, 0, mac.Length);

                                    // CRITICAL ENTERPRISE I/O FLUSH: Force hardware serialization to guarantee integrity of trailing MAC signature blocks.
                                    final.Flush(true);
                                }

                                if (File.Exists(spcrFile)) File.Delete(spcrFile);
                                File.Move(tempFile, spcrFile);

                                if (IsFileEncrypted(filePath, spcrFile))
                                {
                                    UiListMutationManager.SafeRemoveItem(this, listFiles, fileItem, labRemainingFiles);
                                }

                                var allKeys = AppConfigHelper.XmlConfig.GetAllKeyValuePairs();
                                var engineParentKey = allKeys.Keys.FirstOrDefault(k => k.StartsWith(engineName + "EencryptedSalt-" + sessionGroup));

                                if (engineParentKey != null)
                                {
                                    string childKeyName = $"{Guid.NewGuid():N}_{Path.GetFileName(filePath)}";

                                    // SECURE METADATA RESOLUTION: Extract absolute cryptographic size directly from the finalized storage target.
                                    FileInfo fi = new FileInfo(spcrFile);

                                    string sizeKB = string.Format("{0:#,##0} KB", fi.Length / 1024).Replace("0 KB", "1 KB");
                                    string sizeExtended = fi.Strbytes();

                                    string normalizedChildPath = Path.GetFullPath(spcrFile).Trim().Trim('"');

                                    string childValue = $"{normalizedChildPath}|{sizeKB}|{fileItem.SubItems[4].Text}|" +
                                                         $"{sizeExtended}|{engineName}|{listSett.Items[1].SubItems[2].Text}|{sessionGroup}";

                                    AppConfigHelper.XmlConfig.SetChild(engineParentKey, childKeyName, childValue);
                                }
                            }

                            Allshredder.Execute(listSett.Items[25].SubItems[2].Text, filePath, isCustomClassic, isCustomUser, tempList);
                        }
                        catch (Exception ex)
                        {
                            CentralLog.LogException(ex, "FILE_ENCRYPT", "Single file encryption failed");

                            // Automated file-system rollback
                            CryptoRollbackManager.RollbackEncryption(fileItem.SubItems[2].Text);

                            this.Invoke(new Action(() =>
                            {
                                labOperation.Text = "Some files failed - check CentralLog";
                                labOperation.ForeColor = Color.Red;
                            }));

                            continue;
                        }
                    }
                }
                catch (Exception ex)
                {
                    this.Invoke(new Action(() =>
                    {
                        labOperation.Text = "Something went wrong during the encryption process - check CentralLog";
                        labOperation.ForeColor = Color.Red;
                    }));

                    CentralLog.LogException(ex, "MAIN", "Error during the Encryption Proces!");
                }
                finally
                {
                    // Executes a comprehensive memory sanitization sequence
                    Arrayclear();

                    timer1.Stop();
                    timer1.Enabled = false;

                    _activeList = false;

                    if (listSett.Items[1].SubItems[1].Text == "PGP")
                        counters.Increment("PGP");
                    else
                        counters.Increment(listSett.Items[1].SubItems[1].Text);

                    // Save the configuration file
                    AppConfigHelper.Save();

                    listFiles.Items.Clear();
                }
            });
        }     

        /// <summary>
        /// Orchestrates the critical cryptographic key derivation pipeline, elevating DPAPI protection states,
        /// extracting multi-engine parameters via invariant culture parsers, generating structural salting vectors,
        /// and executing deterministic memory scrubs upon derivation completion.
        /// </summary>
        public void Keymaterial()
        {
            try
            {
                // Load parameters
                Argonparam();
                Scrparam();

                ProtectedMemory.Unprotect(Filepass, MemoryProtectionScope.SameLogon);

                HASHLib.pbkdf2iterations = int.Parse(listSett.Items[23].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture);
                SaltManager.bcryptrnd = int.Parse(Regex.Match(listSett.Items[21].SubItems[2].Text, @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture);

                if (Filepass == null || Filepass.Length == 0)
                    throw new InvalidOperationException("Filepass is null or empty.");

                // Get user-defined rounds
                int userRounds = 100000; // Default
                string hashAlgo = listSett.Items[5].SubItems[1].Text;

                if (hashAlgo.StartsWith("HMAC") || hashAlgo == "PBKDF2-HASH")
                {
                    userRounds = int.Parse(listSett.Items[23].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture);
                }

                // Generate Salt
                Salt = SaltManager.GenerateSalt(listSett.Items[7].SubItems[1].Text.Trim(), SaltManager.bcryptrnd);
                if (Salt == null || Salt.Length == 0)
                    throw new InvalidOperationException("Salt generation failed.");

                // Combine Filepass + Salt into raw bytes
                byte[] combined = Filepass.Concat(Salt).ToArray();
                if (combined == null || combined.Length == 0)
                    throw new InvalidOperationException("Failed to combine Filepass and Salt.");

                // Derive key
                DeriveKey dk = new DeriveKey { Rounds = userRounds };
                dk.Derive(combined, Salt, hashAlgo);

                if (dk.Hashpass == null || dk.Hashpass.Length == 0)
                    throw new InvalidOperationException("Key derivation failed.");

                Hashpass = dk.Hashpass;

                // Protect salt in memory
                _protectedSalt = new ProtectedSalt(Salt);

                SecureWipe.WipeArray(Salt);
                Salt = null;

                ProtectedMemory.Protect(Filepass, MemoryProtectionScope.SameLogon);

                // Clear temporary buffer
                Array.Clear(combined, 0, combined.Length);
            }
            catch (Exception ex)
            {
                try { ProtectedMemory.Protect(Filepass, MemoryProtectionScope.SameLogon); } catch { /* guard */ }
                MessageBox.Show("Keymaterial error! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "MAIN", "Keymaterial error!");
                Passwerr.HandleDecryptionFailure();
            }
        }

        /// <summary>
        /// Synchronizes the high-level graphical interface elements to reflect an active encryption preparation state, 
        /// binding context menus, toolbar icons, tooltips, and validation labels to standard processing vectors.
        /// </summary>
        public void EncryptSettings()
        {
            _encDec = false;
            encryptionListMenu.Text = "Encr&ypt list";
            encryptionListMenu.Image = ForAllUnits.Encrypted22;
            tStripBtnEncryption.Image = encryptionListMenu.Image;
            tStripBtnEncryption.ToolTipText = "Encrypt List";
            encryptListStripMenu.Text = "Encrypt List";
            encryptListStripMenu.Image = encryptionListMenu.Image;
            picOperation.Image = ForAllUnits.Encrypted22;
            labOperation.Text = "Ready for processing";
            labOperation.ForeColor = Color.Black;            
        }

        #endregion Encrypt

        #region Decrypt 
        
        /// <summary>
        /// Marshals structured file records from the encrypted viewing grid into the primary processing queue layout,
        /// enforces strict extension isolation boundaries to prevent operational mixture anomalies,
        /// and re-indexes workspace control selections upon transactional inclusion.
        /// </summary>
        private void Transferenc(bool selectedOnly)
        {
            if (selectedOnly && listFileEnc.SelectedItems.Count == 0)
            {
                return;
            }

            if (!selectedOnly && listFileEnc.Items.Count == 0)
            {
                return;
            }

            bool added = false;

            // Prevent mixing encryption and decryption files
            if (listFiles.Items.Count > 0)
            {
                string firstDestinationFile = listFiles.Items[0].SubItems[2].Text.Trim();

                if (!string.Equals(Path.GetExtension(firstDestinationFile), ".SPCR", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            listFiles.BeginUpdate();

            try
            {
                var itemsToProcess = selectedOnly
                    ? listFileEnc.SelectedItems.Cast<ListViewItem>()
                    : listFileEnc.Items.Cast<ListViewItem>();

                foreach (ListViewItem sourceItem in itemsToProcess)
                {
                    string filePath = sourceItem.SubItems[2].Text.Trim();

                    // Enterprise path sanitization: strip dynamic string contamination or wrapping quotes
                    if (!string.IsNullOrEmpty(filePath))
                    {
                        filePath = filePath.Trim().Trim('"');
                    }

                    if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                    {
                        continue;
                    }

                    if (ItemExists(listFiles, sourceItem))
                    {
                        continue;
                    }

                    // Explicitly recreate the item and its subitems to bypass clone bugs
                    ListViewItem newItem = new ListViewItem(sourceItem.Text);
                    for (int i = 1; i < sourceItem.SubItems.Count; i++)
                    {
                        newItem.SubItems.Add(sourceItem.SubItems[i].Text);
                    }

                    newItem.Tag = sourceItem.Tag;
                    newItem.ImageIndex = sourceItem.ImageIndex;

                    listFiles.Items.Add(newItem);
                    added = true;
                }
            }
            finally
            {
                listFiles.EndUpdate();

                if (added)
                {
                    tabControl1.SelectedIndex = 2;
                    _encDec = true;
                    DecryptSettings();
                }

                // Force UI synchronization before calculating
                Application.DoEvents();

                // Refresh destination totals
                FileListHandler.RefreshTotals(listFiles, labFileTot, ProgressBar, contextMenuFile);

                // Recalculate the values
                RecalculateAll();
            }
        }

        /// <summary>
        /// Evaluates existence metrics within the target destination grid context by cross-referencing 
        /// unique file path string attributes extracted from the source item structures.
        /// </summary>
        private bool ItemExists(ListView target, ListViewItem source)
        {
            string sourceKey = source.SubItems[2].Text; // PATH

            foreach (ListViewItem item in target.Items)
            {
                // Enforce boundary verification over sub-item count properties before performing string content match checks
                if (item.SubItems.Count > 2 &&
                    item.SubItems[2].Text == sourceKey)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Executes asynchronous bulk cryptographic decryption operations over mapped file collections.
        /// Integrates multi-layered anti-tampering validation, streaming HMAC-SHA256 integrity verification,
        /// and failure-isolated transactional rollback mechanisms.
        /// </summary>
        async Task FileDecrypt()
        {
            // IMMUTABLE CONFIGURATION SNAPSHOT: Extract a thread-isolated memory state of the entire XML structure
            // prior to pipeline execution to insulate unsafe underlying ArrayList collections from concurrent runtime evaluation.
            Dictionary<string, string> xmlMasterSnapshot = AppConfigHelper.XmlConfig.GetAllKeyValuePairs().ToDictionary(k => k.Key, v => v.Value);
            Dictionary<string, Dictionary<string, string>> xmlChildSnapshot = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var parentKey in xmlMasterSnapshot.Keys)
            {
                var liveChildren = AppConfigHelper.XmlConfig.GetChildNodes(parentKey);
                xmlChildSnapshot[parentKey] = liveChildren.ToDictionary(k => k.Key, v => v.Value);
            }

            await Task.Run(() =>
            {
                _hmacFail = false;
                _hmacCount = 0; // Thread-isolated indicator for structural notification throttling per bulk group.

                byte[] reconstructedHash = null;

                // DEFERRED COMMIT TRACKER: Local state collection to isolate XML mutations from the active iterative evaluation loop.
                List<string> processedPaths = new List<string>();

                // POST-LOOP EVALUATION ANCHOR: Track unique parental configuration keys to defer structural purging until pipeline termination.
                HashSet<string> parentKeysToEvaluate = new HashSet<string>();

                try
                {
                    this.Invoke(new Action(() =>
                    {
                        labOperation.Text = "Ready for processing";
                        labOperation.ForeColor = Color.Black;
                    }));

                    _upd = 0;
                    Keymaterial();

                    ProtectedMemory.Unprotect(Filepass, MemoryProtectionScope.SameLogon);

                    // Materialize the list collection to isolate memory mutations from concurrent UI thread interaction.
                    foreach (ListViewItem fileItem in Enumerable.ToList<ListViewItem>(Enumerable.Cast<ListViewItem>(listFiles.Items)))
                    {
                        bool success = false;
                        string filePath = FileListMap.GetPath(fileItem);

                        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                        {
                            CentralLog.LogEvent("DECRYPT", "FILE MISSING OR INVALID: " + filePath, nameof(FileDecrypt));
                            this.Invoke(new Action(() =>
                            {
                                labOperation.Text = "Decrypt: File missing or invalid!";
                                labOperation.ForeColor = Color.Red;
                            }));
                            continue;
                        }

                        // =================================================================
                        // UNIFIED STREAM ACCESS: SINGLE-PASS MULTI-ROLE OPERATIONAL ENTRY
                        // =================================================================
                        const int macSize = 32;
                        bool hmacValidated = false;
                        long dataLength = 0;

                        string engine = null;
                        string sessionGroup = null;
                        long headerEnd = 0;

                        try
                        {
                            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                            {
                                if (fs.Length <= macSize)
                                    continue;

                                dataLength = fs.Length - macSize;
                                byte[] fileMac = new byte[macSize];
                                fs.Position = dataLength;
                                fs.Read(fileMac, 0, macSize);

                                fs.Position = 0;

                                // Utilizing a non-destructive StreamReader to safely isolate the textual header from the underlying binary cipher block
                                using (StreamReader reader = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true))
                                {
                                    string headerLine = reader.ReadLine();

                                    if (!string.IsNullOrEmpty(headerLine))
                                    {
                                        // Enforce precise stream offsetting by evaluating the exact byte count of the line and its network terminator
                                        headerEnd = Encoding.UTF8.GetByteCount(headerLine) + Environment.NewLine.Length;

                                        int p1 = headerLine.IndexOf('|');
                                        int p2 = headerLine.IndexOf('|', p1 + 1);

                                        if (p1 >= 0 && p2 >= 0)
                                        {
                                            engine = headerLine.Substring(p1 + 1, p2 - p1 - 1).Trim();
                                            sessionGroup = headerLine.Substring(p2 + 1).Trim();
                                        }
                                    }
                                }

                                // SUB-STEP B: EXECUTING STANDARD HMAC COMPILATION ON THE OPEN TRANSACTION
                                fs.Position = 0;

                                using (var hmac = new HMACSHA256(Filepass))
                                {
                                    byte[] buffer = new byte[1024 * 1024];
                                    long remaining = dataLength;

                                    while (remaining > 0)
                                    {
                                        int toRead = (int)Math.Min(buffer.Length, remaining);
                                        int read = fs.Read(buffer, 0, toRead);

                                        if (read <= 0)
                                            break;

                                        hmac.TransformBlock(buffer, 0, read, null, 0);
                                        remaining -= read;
                                    }

                                    hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                                    byte[] computed = hmac.Hash;
                                    bool valid = true;

                                    for (int i = 0; i < macSize; i++)
                                    {
                                        if (computed[i] != fileMac[i])
                                        {
                                            valid = false;
                                            break;
                                        }
                                    }

                                    if (!valid)
                                    {
                                        _hmacFail = true;
                                        if (_hmacCount == 0)
                                        {
                                            CentralLog.LogEvent("SECURITY", "HMAC FAILED: " + filePath, nameof(FileDecrypt));
                                            _hmacCount = 1;
                                        }
                                        this.Invoke(new Action(() =>
                                        {
                                            labOperation.Text = "Security: HMAC Failed!";
                                            labOperation.ForeColor = Color.Red;
                                        }));
                                        continue;
                                    }
                                    hmacValidated = true;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            CentralLog.LogException(ex, "DECRYPT", "Unified Stream Parsing Collision trap.");
                            hmacValidated = false;
                        }
                        if (!hmacValidated) continue;

                        long cipherLen = dataLength - headerEnd;

                        // =================================================================
                        // CONFIG LOOKUP (METADATA MAP UTILIZING IMMUTABLE SNAPSHOT MATRIX)
                        // =================================================================
                        string parentKey = null;
                        string targetCryptoMeta = null;

                        string currentFullPath = Path.GetFullPath(filePath).Trim().Trim('"');

                        // RESTORING ARCHITECTURAL RIGOR: Enforce strict triple-matching including sanitized session indices.
                        // Utilizing high-density trimming to eliminate dynamic multi-threaded string contamination (e.g., trailing carriage returns).
                        string sanitizedEngine = engine?.Trim().Replace("\r", "").Replace("\n", "");
                        string sanitizedSession = sessionGroup?.Trim().Replace("\r", "").Replace("\n", "");

                        foreach (var kvp in xmlMasterSnapshot)
                        {
                            if (!xmlChildSnapshot.ContainsKey(kvp.Key))
                                continue;

                            var children = xmlChildSnapshot[kvp.Key];

                            foreach (var child in children)
                            {
                                string[] split = child.Value.Split('|');

                                if (split.Length < 7)
                                    continue;

                                string childPath = split[0].Trim().Trim('"');
                                string childEngine = split[4].Trim();
                                string childSession = split[6].Trim().Replace("\r", "").Replace("\n", "");

                                if (string.Equals(childPath, currentFullPath, StringComparison.OrdinalIgnoreCase)
                                    && string.Equals(childEngine, sanitizedEngine, StringComparison.OrdinalIgnoreCase)
                                    && string.Equals(childSession, sanitizedSession, StringComparison.OrdinalIgnoreCase))
                                {
                                    parentKey = kvp.Key;
                                    targetCryptoMeta = split[5];
                                    break;
                                }
                            }

                            if (parentKey != null)
                                break;
                        }

                        // RE-ENFORCED UI INTERACTION PATH: Dynamic UI update and color trigger on lookup failure
                        if (parentKey == null)
                        {
                            CentralLog.LogEvent("DECRYPT", "SESSION NOT FOUND FOR PATH: " + filePath, nameof(FileDecrypt));
                            this.Invoke(new Action(() =>
                            {
                                labOperation.Text = "Decrypt: Session not found!";
                                labOperation.ForeColor = Color.Red;
                            }));
                            continue;
                        }

                        parentKeysToEvaluate.Add(parentKey);
                        string[] parts = xmlMasterSnapshot[parentKey].Split('|');

                        string hex = parts[1];
                        byte[] encryptedSaltBytes = new byte[hex.Length / 2];

                        for (int i = 0; i < hex.Length; i += 2)
                            encryptedSaltBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

                        string algoDec = parts[2];
                        string algohash = parts[3];

                        var decrypto = new CryptoAdapterByte();
                        byte[] DecSalt = decrypto.Decrypt(algoDec, encryptedSaltBytes, Filepass,
                                                   int.Parse(listSett.Items[3].SubItems[2].Text, System.Globalization.CultureInfo.InvariantCulture)
                        );

                        if (DecSalt == null || DecSalt.Length == 0)
                            continue;

                        byte[] combined = new byte[Filepass.Length + DecSalt.Length];
                        Buffer.BlockCopy(Filepass, 0, combined, 0, Filepass.Length);
                        Buffer.BlockCopy(DecSalt, 0, combined, Filepass.Length, DecSalt.Length);

                        DeriverRec dr = new DeriverRec();
                        dr.Derive(combined, DecSalt, algohash);

                        reconstructedHash = dr.Hashrec;

                        Array.Clear(combined, 0, combined.Length);

                        char[] password = HashToCharArray(reconstructedHash);

                        // =================================================================
                        // OUTPUT STREAM DECRYPT (BOUNDLESS BLOCK PACKING TO TEMP STAGING)
                        // =================================================================
                        string tempFile = Path.GetTempFileName();
                        string outputPath = filePath.Replace(".SPCR", "");

                        using (FileStream input = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        using (FileStream output = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            input.Position = headerEnd;

                            byte[] buffer = new byte[1024 * 1024];
                            long remaining = cipherLen;

                            while (remaining > 0)
                            {
                                int toRead = (int)Math.Min(buffer.Length, remaining);
                                int read = input.Read(buffer, 0, toRead);

                                if (read <= 0)
                                    break;

                                output.Write(buffer, 0, read);
                                remaining -= read;
                            }
                        }

                        // =================================================================
                        // PROGRAMMATIC ENGINE ROUTING (PGP VS STANDARD HIGH-DENSITY BLOCK)
                        // =================================================================
                        if (engine != null && engine.Contains("PGP"))
                        {
                            string tempCipherFile = Path.GetTempFileName();
                            File.Copy(tempFile, tempCipherFile, true);

                            try
                            {
                                PgpDecryptor.DecryptFile(tempCipherFile, outputPath, Path.Combine(parts[0], "PGPPrivateKeyRSA.asc"), password);
                            }
                            finally
                            {
                                if (File.Exists(tempCipherFile)) File.Delete(tempCipherFile);
                            }
                        }
                        else
                        {
                            string cryptoMetaString = FileListMap.GetCryptoMeta(fileItem);
                            var match = Regex.Match(cryptoMetaString ?? string.Empty, @"\d+");
                            int keySize = match.Success ? int.Parse(match.Value, System.Globalization.CultureInfo.InvariantCulture) : 256;

                            EncryptionManager.DecryptFile(tempFile, outputPath, reconstructedHash, keySize, engine);
                        }

                        if (IsFileDecrypted(filePath, outputPath))
                        {
                            bool itemWasRemoved = UiListMutationManager.SafeRemoveItem(this, listFiles, fileItem, labRemainingFiles);
                            if (itemWasRemoved)
                            {
                                processedPaths.Add(currentFullPath);
                                success = true;
                            }
                        }

                        if (File.Exists(tempFile)) File.Delete(tempFile);

                        if (!success)
                        {
                            CryptoRollbackManager.RollbackDecryption(filePath.Replace(".SPCR", ""));
                            continue;
                        }

                        if (AutomaticDel == true)
                        {
                            // DIRECT LIVE PURGE LAYER: Safely remove the child record from the real live XML mapping now that execution is isolated from reads.
                            var activeChildren = AppConfigHelper.XmlConfig.GetChildNodes(parentKey);
                            foreach (var child in activeChildren.ToList())
                            {
                                string[] split = child.Value.Split('|');
                                if (split.Length < 1)
                                    continue;

                                string storedPath;
                                try
                                {
                                    storedPath = Path.GetFullPath(split[0]).Trim().Trim('"');
                                }
                                catch
                                {
                                    continue;
                                }

                                if (string.Equals(currentFullPath, storedPath, StringComparison.OrdinalIgnoreCase))
                                {
                                    AppConfigHelper.XmlConfig.RemoveChild(parentKey, child.Key);
                                }
                            }
                        }

                        if (File.Exists(filePath)) File.Delete(filePath);
                    }

                    if (AutomaticDel == true && processedPaths.Count > 0)
                    {
                        foreach (string evaluatedParentKey in parentKeysToEvaluate)
                        {
                            string[] headerLineParts = AppConfigHelper.XmlConfig.GetValue(evaluatedParentKey)?.Split('|');
                            if (headerLineParts == null || headerLineParts.Length <= 4)
                                continue;

                            string activeEngine = headerLineParts[4];

                            if (activeEngine != null && !activeEngine.Contains("PGP"))
                            {
                                bool hasRemainingChildren = AppConfigHelper.XmlConfig.GetChildNodes(evaluatedParentKey).Any();
                                if (!hasRemainingChildren)
                                {
                                    RemoveNode remover = new RemoveNode(AppConfigHelper.XmlConfig);
                                    remover.Execute(evaluatedParentKey);

                                    string prefix = activeEngine + "EencryptedSalt-";
                                    bool existsAnyGroup = AppConfigHelper.XmlConfig.GetAllKeyValuePairs().Keys.Any(k => k.StartsWith(prefix));

                                    if (!existsAnyGroup)
                                    {
                                        counters.Reset(activeEngine);
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    CentralLog.LogException(ex, "MAIN", "Error during the Decryption Process!");
                    this.Invoke(new Action(() =>
                    {
                        labOperation.Text = "Decrypt: Error during the Decryption Process!";
                        labOperation.ForeColor = Color.Red;
                    }));
                    Eraseall();
                    _hmacCount = 0;
                }
                finally
                {
                    AppConfigHelper.Save();

                    Arrayclear();
                    if (reconstructedHash != null) Array.Clear(reconstructedHash, 0, reconstructedHash.Length);

                    if (_upd == 0)
                    {
                        _upd = 1;
                        _activeList = false;
                        _hmacCount = 0;
                    }

                    GC.Collect();
                }
            });
        }

        /// <summary>
        /// Provides high-density static lookup mappings to safely isolate contextual file paths 
        /// and cryptographic configuration attributes from standard list sub-item matrices.
        /// </summary>
        private static class FileListMap
        {
            public static string GetPath(ListViewItem item)
            {
                return item.SubItems[2].Text;
            }
            public static string GetCryptoMeta(ListViewItem item)
            {
                return item.SubItems[7].Text;
            }
        }

        /// <summary>
        /// Evaluates systemic target file-system properties to assert successful data restoration states, 
        /// validating path boundary conditions, structural file extensions, existence vectors, and payload metrics.
        /// </summary>
        private bool IsFileDecrypted(string inputFilePath, string outputFilePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(inputFilePath) || string.IsNullOrWhiteSpace(outputFilePath))
                    return false;

                if (!inputFilePath.EndsWith(".SPCR", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (outputFilePath.EndsWith(".SPCR", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!File.Exists(inputFilePath))
                    return false;

                if (!File.Exists(outputFilePath))
                    return false;

                FileInfo fi = new FileInfo(outputFilePath);

                if (fi.Length == 0)
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }       

        /// <summary>
        /// Evaluates systemic target file-system properties to assert successful cipher processing execution states, 
        /// validating path boundary conditions, structural file extensions, existence vectors, and payload metrics.
        /// </summary>
        private bool IsFileEncrypted(string inputFilePath, string outputFilePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(inputFilePath) || string.IsNullOrWhiteSpace(outputFilePath))
                    return false;

                if (inputFilePath.EndsWith(".SPCR", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!outputFilePath.EndsWith(".SPCR", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!File.Exists(inputFilePath))
                    return false;

                if (!File.Exists(outputFilePath))
                    return false;

                FileInfo fi = new FileInfo(outputFilePath);

                if (fi.Length == 0)
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Transmutes raw cryptographic hash byte sequences into a standardized hex-encoded character array, 
        /// executing high-speed low-level bitwise operations to completely eliminate managed heap string allocation layers.
        /// </summary>
        private char[] HashToCharArray(byte[] hash)
        {
            // Convert each byte to 2 hex chars without creating a full string
            char[] chars = new char[hash.Length * 2];
            int index = 0;

            for (int i = 0; i < hash.Length; i++)
            {
                byte b = hash[i];
                chars[index++] = GetHexChar(b >> 4);
                chars[index++] = GetHexChar(b & 0x0F);
            }

            return chars;
        }

        /// <summary>
        /// Converts a specific 4-bit nibble value into its localized lowercase hexadecimal character equivalent 
        /// executing high-speed localized integer arithmetic operations.
        /// </summary>
        private char GetHexChar(int value)
        {
            return (char)(value < 10 ? ('0' + value) : ('a' + (value - 10)));
        }

        /// <summary>
        /// Synchronizes high-level graphical interface elements to reflect an active decryption preparation state, 
        /// binding context menus, toolbar icons, tooltips, and enforcing conditional availability metrics 
        /// based on structural credential scoring results.
        /// </summary>
        public void DecryptSettings()
        {
            _encDec = true;
            encryptionListMenu.Text = "Decr&ypt list";
            encryptionListMenu.Image = ForAllUnits.Decrypted22;
            tStripBtnEncryption.Image = encryptionListMenu.Image;
            tStripBtnEncryption.ToolTipText = "Decrypt List";
            encryptListStripMenu.Text = "Decrypt List";
            encryptListStripMenu.Image = encryptionListMenu.Image;
            picOperation.Image = ForAllUnits.Decrypted22;
            labOperation.Text = "Ready for processing";
            labOperation.ForeColor = Color.Black;

            if (secMasKey.Text != string.Empty && _rescor > 2)
            {
                encryptionListMenu.Enabled = true;
                tStripBtnEncryption.Enabled = true;
                encryptListStripMenu.Enabled = true;
            }
        }

        #endregion Decrypt

        #region Status Bar

        /// <summary>
        /// Forces structural scroll visibility to target the terminal item within the diagnostic test grid, 
        /// updates systemic directional state trackers, and toggles hardware input boundaries.
        /// </summary>
        private void BtnDown_Click(object sender, EventArgs e)
        {
            listTest.Items[listTest.Items.Count - 1].EnsureVisible();
            btnDown.Enabled = false;
            btnUp.Enabled = true;
            _updown = 0;
        }

        /// <summary>
        /// Forces structural scroll visibility to target the initial baseline item within the diagnostic test grid, 
        /// updates systemic directional state trackers, and toggles hardware input boundaries.
        /// </summary>
        private void BtnUp_Click(object sender, EventArgs e)
        {
            listTest.Items[0].EnsureVisible();
            btnUp.Enabled = false;
            btnDown.Enabled = true;
            _updown = 1;
        }

        #endregion Status Bar

        #region Capture Screen

        /// <summary>
        /// Intercepts screen capture command operations, dispatching execution synchronously 
        /// to the localized static capture subsystem handler to process desktop bitmap acquisition routines.
        /// </summary>
        private void BtnCapture_Click(object sender, EventArgs e)
        {
            Capturescreen.TriggerCapture();
        }

        #endregion Capture Screen

        #region Others

        /// <summary>
        /// Evaluates visual obfuscation configuration parameters, toggles security anti-screen-capture subroutines,
        /// and synchronizes global system indicator components dynamically based on credential protection matrices.
        /// </summary>
        public void ActivateGhost()
        {
            picScreen.Image = ForAllUnits.Ledred16;
            SpeedcryptGhost.Disable(this);

            if (Obfs == true)
            {
                SpeedcryptGhost.Enable(this);
                picScreen.Image = ForAllUnits.Ledgreen16;
            }
        }

        /// <summary>
        /// Scans low-level operating system thread execution tables to isolate and aggressively terminate 
        /// concurrent auxiliary utility instances, preventing transactional cross-process runtime boundary leaks.
        /// </summary>
        void KillSpcUtility()
        {
            //Close SpcUtility if you open other form
            Process[] wreg = Process.GetProcessesByName("SpcUtility");

            if (wreg.Length > 0) wreg[0].Kill();
        }

        /// <summary>
        /// Serializes dynamic selection attributes extracted from specific selection container components 
        /// into the persistent centralized xml metadata configuration schema.
        /// </summary>
        void SaveComboBoxSetting(string key, ComboBox comboBox)
        {
            if (comboBox.SelectedItem != null)
            {
                AppConfigHelper.XmlConfig.SetValue(key, comboBox.SelectedItem.ToString());
            }
        }

        /// <summary>
        /// Serializes structural checked state boolean conditions verified from user interaction checkbox controls 
        /// into the persistent centralized xml metadata configuration schema.
        /// </summary>
        void SaveCheckboxSetting(string key, CheckBox checkbox)
        {
            AppConfigHelper.XmlConfig.SetValue(key, checkbox.Checked.ToString());
        }

        #endregion Others

        #region Override        

        /// <summary>
        /// Intercepts systemic window closing lifecycles, immediately nullifying visual interface layers,
        /// disabling low-level anti-screen-capture wrappers, and dispatching synchronous serialization routines 
        /// to store runtime preference matrices and environmental settings configuration states onto persistent memory structures.
        /// </summary>
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Terminates any active background host utility processing instances before initiating window destruction
            KillSpcUtility();

            // Immediately make the form invisible
            // Obstructs the user interface layer instantaneously by purging window opacity and layout visibility states
            this.Opacity = 0;
            this.Visible = false;
            this.Hide();

            // Disable redraw for main window
            // Intercepts the native OS window manager handle to suppress layout redraw events during cleanup execution loops
            SendMessage(this.Handle, WM_SETREDRAW, false, IntPtr.Zero);

            // Freeze controls
            // Suspends visual update rendering loops across data tracking list grids to optimize process de-allocation performance
            listSett.BeginUpdate();
            listTest.BeginUpdate();
            listFiles.BeginUpdate();
            listFileEnc.BeginUpdate();

            // Suspends UI drawing hierarchies for the cryptographic engine structural tree interface view
            treeEngines.BeginUpdate();

            // Disable SpeedcryptGhost protections
            // Iterates the entire open application form registry matrix to strip context-sensitive screen capture protection hooks
            foreach (Form openForm in Application.OpenForms)
            {
                SpeedcryptGhost.Disable(openForm);
            }

            // Save configuration
            // Dispatches a serialization request to copy the last known-good active configuration state into the emergency fallback replica local storage store
            BckConfigFile.CreateBackup();

            // Commits specific user environmental selection state checkboxes parameters into localized cache records
            SaveCheckboxSetting("Result.OverwriteAppend", chkOverwrite);
            SaveCheckboxSetting("Result.AlternateRow", chkAlternate);
            SaveCheckboxSetting("Result.AutomaticDeletionLog", chkAutomatic);
            SaveCheckboxSetting("Result.DisplayRSAKeys", chkDisplayRSA);
            SaveCheckboxSetting("Result.OpenFolderPGPKeys", chkOpenFolder);

            // Commits operational log truncation metrics from dropdown menu selection states into localized storage
            SaveComboBoxSetting("Result.DeletionErrorLog", cmbDeletion);

            // Flushes all cached system modifications and commits permanent configuration updates onto disk structures
            AppConfigHelper.Save();

            // Invokes the base implementation to ensure standard operating system window lifecycle termination events are fully processed executionally
            base.OnFormClosing(e);
        }

        #endregion Override
    }
}