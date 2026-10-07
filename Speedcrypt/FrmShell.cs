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
using Speedcrypt.XMLConfig;
using Speedcrypt.Interfaces;
using Speedcrypt.WindowsShell;

namespace Speedcrypt
{
    public partial class FrmShell : Form
    {
        #region Fields

        // Reference to the main user interface window container acting as the principal application controller
        private FrmMain mainForm;

        // Infrastructure component managing dynamic tooltip displays and context-sensitive user help notifications
        private ToolTipManager _tt;

        // Component driving localized XML system configuration file persistence and node mapping
        private PrivateXmlConfig _xmlConfig;

        // Operating system shell integration manager driving the registration of Speedcrypt inside the Windows 'Send To' native context menu
        private SendToSpeedcrypt _sendTo = new SendToSpeedcrypt("Speedcrypt", Application.ExecutablePath);

        #endregion Fields

        #region Constructor
        /// <summary>
        /// Initializes a new instance of the FrmShell class, establishing a synchronized inter-form link with the core controller thread.
        /// </summary>
        /// <param name="callingForm">The invoking form instance interface containing base application runtime pointers.</param>
        public FrmShell(Form callingForm)
        {
            InitializeComponent(); // Initializes all UI components and controls
                                   // Safely casts and binds the parent container reference to establish runtime communication with the core window thread
            mainForm = callingForm as FrmMain; // Cast and store reference to the main application form
                                               // Dispatches sequential procedural triggers to evaluate environments, load telemetry counters, and initialize form states
            LoadAll();// Loads application configuration and initializes runtime state
        }

        #endregion Constructor

        #region Form Routines
        void LoadAll()
        {
            #region Instances

            // Instantiates the localized user interface documentation overlay layer for context help messages
            _tt = new ToolTipManager(); // Tooltip
                                        // Binds the localized field pointer to the production enterprise application settings caching infrastructure
            _xmlConfig = AppConfigHelper.XmlConfig; // Configuration File
                                                    // Explicitly decouples active screen-capture prevention mechanisms for specific interface initialization scopes
            SpeedcryptGhost.Disable(this); // Obfuscate print Screen

            #endregion Instances

            #region Form Interface

            // Configure main form appearance and behavior
            // Extracts and assigns the application executable icon layout with a fallback to the default system application template
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;
            // Disables the window maximization button to lock control geometry bounds
            MaximizeBox = false;
            // Disables the window minimization button to block standard user taskbar interface minimization
            MinimizeBox = false;
            // Establishes a fixed, non-resizable window dialog border to prevent user layout disruption
            FormBorderStyle = FormBorderStyle.FixedDialog;
            // Aligns the initial window spawning location to the precise geometric center of the display screen
            StartPosition = FormStartPosition.CenterScreen;
            // Sets the standardized window title string header for identification
            Text = "Speedcrypt Windows Shell...";

            // Header images configuration
            // Attaches the system global gradient layout template to the header background image container
            picGrad.Image = ForAllUnits.Gradientform;
            // Configures background layout properties to stretch fluidly across the visual interface boundary
            picGrad.BackgroundImageLayout = ImageLayout.Stretch;

            // Binds the designated operating system shell integration asset to the icon picture box control
            picSimb.Image = ForAllUnits.Shell32;
            // Parents the icon control container to the gradient panel to build accurate layer layout hierarchies
            picSimb.Parent = picGrad;
            // Enforces alpha transparency on control background layers to guarantee accurate composite color blending
            picSimb.BackColor = Color.Transparent;

            // Header labels styling
            // Applies high-visibility background coloring parameters to the yellow indicator highlight control
            labYel.BackColor = Color.Yellow;

            // Syncs the primary window header label text layout directly with the main form text title property
            labFir.Text = Text;
            // Parents the primary title text object container directly to the background gradient layout surface
            labFir.Parent = picGrad;
            // Eliminates solid control backgrounds to allow seamless background text alpha rendering pass
            labFir.BackColor = Color.Transparent;
            // Configures high-visibility solid white for primary label visual foreground styling strings
            labFir.ForeColor = Color.White;
            // Instantiates a new text styling object utilizing the native control font family set to a bold 10-point configuration
            labFir.Font = new Font(labFir.Font.FontFamily, 10, FontStyle.Bold);

            // Establishes the sub-descriptive text explaining the specific scope of the operating system integration panel
            labSec.Text = "Basic Windows Shell settings for Speedcrypt";
            // Coordinates parental interface attachments linking the subtitle layout block onto the gradient panel structure
            labSec.Parent = picGrad;
            // Clears solid background layer color values to permit fluid transparency text rendering
            labSec.BackColor = Color.Transparent;
            // Applies clean high-visibility white text formatting for the sub-header presentation layer
            labSec.ForeColor = Color.White;
            // Instantiates a standard regular 10-point text presentation font wrapper for reading accessibility 
            labSec.Font = new Font(labSec.Font.FontFamily, 10);

            #endregion Form Interface

            #region Form Components

            // Group Box
            // Localizes container panels managing the layout separation for Windows 'Send To' options and native shell registry context menus
            grbSendTo.Text = "Send To Speedcrypt...";
            grbSendTo.ForeColor = Color.Brown;
            // Descriptive user documentation clarifying the real-time operational benefits of the Send-To environment hook
            labSendTo.Text = "You can enable this option if you want to send\r\n " +
                             "files to Speedcrypt for encryption or decryption \r\n" +
                             "by selecting them directly from the Windows Shell. \r\n" +
                             "A quick way to send files that you can disable at any time.\r\n";

            grbShell.Text = "Windows Shell Extension...";
            grbShell.ForeColor = Color.Brown;
            // Descriptive user guidance detailing the direct right-click context menu integration behaviors within File Explorer
            labShell.Text = "Shell extensions add 'Encrypt with SpeedCrypt'\r\n " +
                            "and 'Decrypt with SpeedCrypt' to the Windows \r\n" +
                            "context menu for quick file transfer into the program.\r\n" +
                            "You can remove these options at any time\r\n";

            // Comprehensive multiline feature registry listing system layout benefits to optimize operator workflows
            labShellNote.Text = "●  Quick access to core functions directly from your desktop\r\n\r\n" +
                                "●  Immediate encryption of files and folders with a single click\r\n\r\n" +
                                "●  Fast decryption without opening the application first\r\n\r\n" +
                                "●  Seamless integration with the native Windows interface\r\n\r\n" +
                                "●  Time-saving management of your daily sensitive data\r\n\r\n" +
                                "●  Optimized workflow thanks to multi-file selection\r\n\r\n" +
                                "●  Completely safe activation with zero risk to your system\r\n\r\n" +
                                "●  No slowdowns or impact on Windows performance\r\n\r\n" +
                                "●  Direct management of protected files within File Explorer\r\n\r\n" +
                                "●  Immediate operations via the right-click context menu\r\n\r\n" +
                                "●  Clean layout that does not clutter your system menus\r\n\r\n" +
                                "●  Maximum convenience for quickly sending encrypted attachments\r\n\r\n" +
                                "●  Disable or remove the menu options at any time\r\n\r\n" +
                                "●  Quick and straightforward setup with a simple checkbox\r\n\r\n" +
                                "●  High-speed Shell extension via dedicated buttons\r\n";

            // Buttons
            // Instantiates a strongly-typed tuple array tracking physical UI parameters for actionable integration commands
            var otherbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                (btnAddShell, "&Add Shell", "Add Shell extension", ForAllUnits.Shell32, true),
                (btnRemoveShell, "&Remove", "Remove Shell extension", ForAllUnits.Cancelitem32, true),
                (btnOk, "&Ok", "Close Speedcrypt Windows Shell", ForAllUnits.Apply16, true),
            };

            int verticalSpacing = 5;
            // Iterates across the button layout collection to assign text, centralized glyph assets, and pointer actions
            foreach (var othernbut in otherbutton)
            {
                othernbut.Button.Text = othernbut.Text;
                _tt.Set(othernbut.Button, othernbut.Tip); // Registers user reference guides screen tooltips
                othernbut.Button.Cursor = Cursors.Hand; // Standardizes input pointer profile upon interface boundaries collision
                othernbut.Button.Image = othernbut.Icon;
                othernbut.Button.ImageAlign = ContentAlignment.MiddleCenter;
                othernbut.Button.TextAlign = ContentAlignment.BottomCenter;
                othernbut.Button.Enabled = othernbut.Enabled;
                othernbut.Button.Padding = new Padding(0, 0, 0, verticalSpacing); // Applies absolute vertical structural spacing padding
            }

            // Other Buttons
            // Configures specific presentation behaviors for the contextual documentation access reference link
            btnHelp.Text = "&Help";
            btnHelp.Image = ForAllUnits.Help16;
            btnHelp.ImageAlign = ContentAlignment.MiddleLeft;
            btnHelp.Cursor = btnOk.Cursor;
            _tt.Set(btnHelp, "View Help Guide");

            // ChekBox
            // Tuple configuration matrix driving operational setup parameter toggles for the shell workspace
            var allChkBox = new (CheckBox Chk, string Text, string Tip, bool Checked, bool Enabled)[]
            {
                (chkSendto, "Send to Speedcrypt", "Enable / Disable sending files from Windows Shell via “Send to”", false, true),
            };

            // Mass-initializes interactive properties and tooltips across the environment checkboxes
            foreach (var boxOption in allChkBox)
            {
                boxOption.Chk.Enabled = boxOption.Enabled;
                boxOption.Chk.Checked = boxOption.Checked;
                boxOption.Chk.Text = boxOption.Text;
                _tt.Set(boxOption.Chk, boxOption.Tip);
                boxOption.Chk.Cursor = Cursors.Hand;
            }

            // ListView for send To 
            // Configures layout parameters, styles, and data structural columns for the native 'Send To' shortcut list
            listSendTo.View = View.Details;
            listSendTo.SmallImageList = imageList1;
            listSendTo.BeginUpdate(); // Inhibits GUI redraw thread loops while appending layout grid metadata columns
            listSendTo.Columns.Add("ID", 27, HorizontalAlignment.Center);
            listSendTo.Columns.Add("PROGRAMS", 395, HorizontalAlignment.Left);
            listSendTo.EndUpdate(); // Resumes standard UI painting threads after schema configuration injection
            listSendTo.FullRowSelect = false; // Disables mass selection highlighting across row indexes boundaries
            listSendTo.HeaderStyle = ColumnHeaderStyle.None; // Suppresses visual column descriptors for a flat minimalistic design
            listSendTo.MultiSelect = false; // Enforces absolute singular row selection constraints inside the tracking table
            listSendTo.TabStop = false; // Excludes the component from sequential tab keyboard navigation loops

            // ListView for Shell Extension 
            // Configures layout parameters, status monitoring indicators, and column metadata schemas for shell extensions
            listShellExt.View = View.Details;
            listShellExt.SmallImageList = imageList2;
            listShellExt.BeginUpdate(); // Prevents interface flickering during column populationpasses
            listShellExt.Columns.Add("ID", 27, HorizontalAlignment.Center);
            listShellExt.Columns.Add("EXTENSION", 220, HorizontalAlignment.Left);
            listShellExt.Columns.Add("STATUS", 80, HorizontalAlignment.Left);
            listShellExt.EndUpdate(); // Resumes visual painting threads
            listShellExt.FullRowSelect = false;
            listShellExt.HeaderStyle = ColumnHeaderStyle.None; // Suppresses headers to harmonize the visual styling across both panels
            listShellExt.MultiSelect = false;
            listShellExt.TabStop = false;

            #endregion Form Components

            #region Event handlers

            // Hooks interactive selection change events driving real-time activation or removal of the 'Send To' filesystem shortcut
            chkSendto.CheckedChanged += ChkSendto_CheckedChanged;

            // Binds the action trigger tasked with generating and registering the custom context menu extensions into the Windows Registry
            btnAddShell.Click += BtnAddShell_Click;

            // Binds the operational command tasked with purging and unregistering the context menu entries from the system environment
            btnRemoveShell.Click += BtnRemoveShell_Click;

            // Subscribes the reference guide button action link to initialize the administrative compilation help framework
            btnHelp.Click += BtnHelp_Click;

            #endregion Event handlers

            #region Initialization

            /// <summary>
            /// Initializes the state of the 'SendTo' checkbox based on application settings.
            /// If the configuration key is missing or undefined, the system performs a fallback 
            /// hardware-level directory probe within the Windows 'SendTo' special folder 
            /// to verify the physical existence of the Speedcrypt executable or shortcut link.
            /// </summary>
            // Evaluates persistent configuration properties storage maps to assess setup key visibility constraints
            if (!string.IsNullOrEmpty(_xmlConfig.GetValue("Result.SendToSpeedcrypt")))
            {
                // Apply configuration state directly if the settings key resides in the XML
                // Synchronizes the user interface switch directly with parameters loaded from the database records
                chkSendto.Checked = _xmlConfig.GetValue("Result.SendToSpeedcrypt") == "True";
            }
            else
            {
                // Fallback routine: Evaluate checkbox state via physical file system inspection
                // Dispatches a hard filesystem inquiry routine to dynamically assess shortcut presence inside unmanaged system targets
                chkSendto.Checked = IsSpeedcryptInSendToFolder();
            }

            // Intercepts global main controller environmental states to enforce screenshot protection on local initialization bounds
            if (mainForm.Obfs == true)
                SpeedcryptGhost.Enable(this);

            // Call our new management class to execute the logic and bind everything
            // Allocates an infrastructure manager proxy module tasking it to populate current runtime links data inside the send-to grb container list
            SendToManager.PopulateSendToMenu(this.listSendTo, this.imageList1);

            // Allocates a low-level shell extension coordinator component to map context menu entries registrations into the target table grid view
            ShellExtManager.PopulateShellExtensionMenu(this.listShellExt, this.imageList2, this.Icon);

            // Evaluates environment data matrices to conditionally calibrate the administrative command action buttons availability profile
            Enablebut();

            // Block space key interference
            // Attaches an input interception listener to suppress keyboard spacing actions inside specific controls
            SpaceKeyBlocker.Enable(this);

            #endregion Initialization
        }

        #endregion Form Routines

        #region Event handlers
        private void ChkSendto_CheckedChanged(object sender, EventArgs e)
        {
            if (chkSendto.Checked)
            {
                _sendTo.Enable();

            }
            else
            {
                _sendTo.Disable();

            }
            SendToManager.PopulateSendToMenu(this.listSendTo, this.imageList1);
        }
        private void BtnAddShell_Click(object sender, EventArgs e)
        {
            try
            {
                DialogResult result = MessageBox.Show("You have chosen to update the Windows context menu with the items related to Speedcrypt. Continue?",
                                                      ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (result == DialogResult.No)
                    return;

                Cursor = Cursors.WaitCursor; // Change cursor to loading state
                ShellExtensionManager.Activate();
                Cursor = Cursors.Default;
                ShellExtManager.PopulateShellExtensionMenu(this.listShellExt, this.imageList2, this.Icon);
                Enablebut();
                MessageBox.Show("DLL registered successfully! Windows Explorer has been restarted.", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);                
            }
            catch (Exception ex)
            {
                Cursor = Cursors.Default;
                MessageBox.Show(ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        private void BtnRemoveShell_Click(object sender, EventArgs e)
        {
            try
            {
                DialogResult result = MessageBox.Show("You have chosen to remove the Windows context menu with the items related to Speedcrypt. Continue?",
                                                      ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (result == DialogResult.No)
                    return;

                Cursor = Cursors.WaitCursor;
                ShellExtensionManager.Remove();
                ShellExtManager.PopulateShellExtensionMenu(this.listShellExt, this.imageList2, this.Icon);
                Cursor = Cursors.Default;
                Enablebut();
                MessageBox.Show("DLL removed successfully! Windows Explorer has been restarted.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);                
            }
            catch (Exception ex)
            {
                Cursor = Cursors.Default;
                MessageBox.Show(ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        private void BtnHelp_Click(object sender, EventArgs e)
        {
            // Verifies deployment directory records and attaches external compiled help file system windows to current form context
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.ShellExt);
        }

        // Enabled / Disabled Buttons
        /// <summary>
        /// Evaluates the active registration status of the shell extension inside the tracking grid to dynamically calibrate command button states.
        /// </summary>
        void Enablebut()
        {
            // Toggles the registration action trigger visibility based on the text status value of the primary array entry row
            btnAddShell.Enabled = listShellExt.Items[0].SubItems[2].Text == "Inactive";

            // Toggles the unregistration action trigger visibility ensuring mutual exclusion between installation paths
            btnRemoveShell.Enabled = listShellExt.Items[0].SubItems[2].Text == "Active";
        }

        /// <summary>
        /// Checks if the Speedcrypt application shortcut or executable exists in the current Windows user's SendTo folder.
        /// </summary>
        /// <returns>True if the file or shortcut exists; otherwise, false.</returns>
        private bool IsSpeedcryptInSendToFolder()
        {
            try
            {
                // Dynamically retrieve the absolute path of the SendTo special folder for the current Windows user
                // Requests unmanaged platform environment handles to extract the active profile special folder location
                string sendToPath = Environment.GetFolderPath(Environment.SpecialFolder.SendTo);

                // Guard clause ensuring processing parameters are initialized before executing layout path string processing
                if (string.IsNullOrEmpty(sendToPath))
                    return false;

                // Define paths for both the raw executable and the Windows shortcut file
                string targetExePath = Path.Combine(sendToPath, "Speedcrypt.exe");
                string targetLnkPath = Path.Combine(sendToPath, "Speedcrypt.lnk");

                // Perform a safe file system check to verify physical existence of either file type
                // Executes multi-format validation boundaries searching for explicit execution binaries or linked redirection artifacts
                return File.Exists(targetExePath) || File.Exists(targetLnkPath);
            }
            catch (Exception)
            {
                // Fallback guard: Return false if any unexpected security or I/O exception occurs
                return false;
            }
        }

        #endregion Event handlers

        #region override
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Invokes the base implementation to ensure standard operating system window closure events are processed executionally
            base.OnFormClosing(e);

            // Dispatches layout state persistence requests to commit the user-selected Send To integration setting into local cache structures
            UiConfigSaver.SaveCheckBoxSetting("Result.SendToSpeedcrypt", chkSendto);

            // Commit all changes to configuration
            // Flushes all cached system modifications and commits permanent configuration updates onto disk structures
            AppConfigHelper.Save();
        }

        #endregion Override

    }
}
