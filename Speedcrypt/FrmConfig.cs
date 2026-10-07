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
using System.Xml;
using Speedcrypt.UI;
using System.Drawing;
using System.Diagnostics;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// Speedcrypt
using Speedcrypt.Protect;
using Speedcrypt.XMLConfig;
using Speedcrypt.Interfaces;
using Speedcrypt.Exceptionlog;

namespace Speedcrypt
{
    public partial class FrmConfig : Form
    {
        #region Fields

        // Reference to the main user interface window container
        private FrmMain mainForm;

        // Infrastructure component managing dynamic tooltip displays and contextual help
        private ToolTipManager _tt;

        // Component managing XML configuration file persistence
        private PrivateXmlConfig _xmlConfig;

        // Default localized text string displayed for key deletion and counter reset actions
        private string commonTip = "Select to reset the counter or delete associated keys";

        /// <summary>
        /// Native Windows API function to retrieve an icon handle from an executable or DLL file.
        /// </summary>
        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr ExtractIcon(IntPtr hInst, string lpszExeFileName, int nIconIndex);

        /// <summary>
        /// Native Windows API function to release memory resources allocated to an icon handle.
        /// </summary>
        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr hIcon);

        #endregion Fields

        #region Constructor
        public FrmConfig(Form callingForm)
        {
            InitializeComponent(); // Initializes all UI components and controls
            mainForm = callingForm as FrmMain; // Cast and store reference to the main application form
            LoadAll();// Loads application configuration and initializes runtime state
        }

        #endregion Constructor

        #region Form Routines
        void LoadAll()
        {
            #region Instances

            _tt = new ToolTipManager(); // Tooltip
            _xmlConfig = AppConfigHelper.XmlConfig; // Configuration File
            SpeedcryptGhost.Disable(this); // Obfuscate print Screen

            #endregion Instances

            #region Form Interface

            // Configure main form appearance and behavior
            // Extracts and assigns the application icon with a fallback to the default system application icon
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;

            // Disables the window maximization button to enforce a fixed-size user interface
            MaximizeBox = false;

            // Disables the window minimization button to prevent standard taskbar minimization behaviors
            MinimizeBox = false;

            // Sets the window border style to a non-resizable dialog box to protect layout integrity
            FormBorderStyle = FormBorderStyle.FixedDialog;

            // Sets the initial form layout position to the geometric center of the display monitor
            StartPosition = FormStartPosition.CenterScreen;

            // Sets the title bar text string for form identification
            Text = "Speedcrypt Configuration File...";

            // Header images configuration
            // Assigns the global gradient resource asset to the primary header image control
            picGrad.Image = ForAllUnits.Gradientform;

            // Configures the gradient background image layout to dynamically scale across the container
            picGrad.BackgroundImageLayout = ImageLayout.Stretch;

            // Assigns the standard ASCII indicator icon resource to the symbol picture control
            picSimb.Image = ForAllUnits.Ascii32;

            // Parents the symbol control to the gradient container to establish hierarchical layout rendering
            picSimb.Parent = picGrad;

            // Configures the symbol control background to transparent for seamless alpha blending
            picSimb.BackColor = Color.Transparent;

            // Header labels styling
            // Applies high-visibility background coloring to the yellow label indicator
            labYel.BackColor = Color.Yellow;

            // Mirrors the main form window text title onto the primary header label control
            labFir.Text = Text;

            // Parents the primary label to the gradient container for accurate absolute positioning
            labFir.Parent = picGrad;

            // Ensures the primary label text renders cleanly with a transparent background wrapper
            labFir.BackColor = Color.Transparent;

            // Sets the primary header text color to high-contrast white
            labFir.ForeColor = Color.White;

            // instantiates a new bold font configuration utilizing the native control font family at 10 points
            labFir.Font = new Font(labFir.Font.FontFamily, 10, FontStyle.Bold);

            // Defines the descriptive subtitle text outlining the purpose of the configuration panel
            labSec.Text = "Basic Settings for Managing the Speedcrypt Configuration File";

            // Parents the subtitle label to the gradient container to maintain layout structure
            labSec.Parent = picGrad;

            // Configures the subtitle control background to transparent for optimal visual blending
            labSec.BackColor = Color.Transparent;

            // Sets the subtitle text color to high-contrast white
            labSec.ForeColor = Color.White;

            // Instantiates a standard regular font layout configuration at 10 points for readability
            labSec.Font = new Font(labSec.Font.FontFamily, 10);

            #endregion Form Interface

            #region Form Components

            // Visual container localization and grouping styles
            grbEngine.Text = "Engine selection:";
            grbEngine.ForeColor = Color.Brown;
            grbManagement.Text = "Configuration file management:";
            grbManagement.ForeColor = Color.Brown;
            grbAutomaticdel.Text = "Automatic deletion:";
            grbAutomaticdel.ForeColor = Color.Brown;

            // Status label conveying system integrity verification baseline
            labReport.Text = "Integrity verified – Ready";

            // ImageList
            // Collection array initializing embedded graphic assets for list item processing
            Image[] images1 = { ForAllUnits.Round22, 
                                ForAllUnits.Apply22,
                                ForAllUnits.Ascii22 };

            // Iterates and flushes the standard icons into the system image registry pipeline
            foreach (var img in images1)
                imageList1.Images.Add(img);

            // ListView
            // Configures layout parameters and layout definitions for the data logging interface
            listTamper.View = View.Details;
            listTamper.SmallImageList = imageList1;
            listTamper.BeginUpdate(); // Prevents UI flickering during column schema population
            listTamper.Columns.Add("ID", 25, HorizontalAlignment.Center);
            listTamper.Columns.Add("FILE", 350, HorizontalAlignment.Left);
            listTamper.Columns.Add("STATUS", 60, HorizontalAlignment.Left);
            listTamper.Columns.Add("DETAILS", 120, HorizontalAlignment.Left);
            listTamper.EndUpdate(); // Resumes standard UI painting threads after column loading
            listTamper.OwnerDraw = true; // Enables low-level UI rendering interception overrides
            listTamper.TabStop = false; // Excludes the component from sequential user keyboard navigation loops

            // Images
            // Initializes status indicator with default non-active operational state color
            picTest.Image = ForAllUnits.Ledorange16;

            // Other Buttons
            // Strongly-typed tuple array storing programmatic metadata for core window operations
            var otherbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                (btnStart, "&Start", "Start operation", ForAllUnits.Reload32, false),
                (btnIntegrity, "&Integrity", "Check the integrity of the Configuration file", ForAllUnits.Connect32, true),
                (btnExport, "&Export File", "Export the Configuration file", ForAllUnits.Filesaveas32, true),
                (btnImport, "I&mport File", "Import the Configuration file", ForAllUnits.Importfile32, true),
                (btnEdit, "&View File", "View the configuration file with Microsoft Edge", ForAllUnits.Viewconf32, true),
                (btnOk, "&Ok", "Close Speedcrypt Configuration file", ForAllUnits.Apply16, true),
                (btnDel, "&Delete File", "Warning: delete the configuration file", ForAllUnits.Cancelitem32, true),
            };

            // Defines bottom padding spacing between image and text
            int verticalSpacing = 5;

            // Applies standardized configuration to all buttons
            // Executes structural UI loop formatting for operational actionable triggers
            foreach (var othernbut in otherbutton)
            {
                othernbut.Button.Text = othernbut.Text;
                _tt.Set(othernbut.Button, othernbut.Tip); // Hooks system context-sensitive screen tooltips
                othernbut.Button.Cursor = Cursors.Hand; // Switches pointer profile upon layout boundary entry
                othernbut.Button.Image = othernbut.Icon;
                othernbut.Button.ImageAlign = ContentAlignment.MiddleCenter;
                othernbut.Button.TextAlign = ContentAlignment.BottomCenter;
                othernbut.Button.Enabled = othernbut.Enabled;
                othernbut.Button.Padding = new Padding(0, 0, 0, verticalSpacing); // Applies physical text offsets
            }

            // Buttons
            // Configures specific parameters for context-sensitive reference system help access
            btnHelp.Text = "&Help";
            btnHelp.Image = ForAllUnits.Help16;
            btnHelp.ImageAlign = ContentAlignment.MiddleLeft;
            btnHelp.Cursor = btnOk.Cursor;
            _tt.Set(btnHelp, "View Help Guide");

            // Labels
            // Registration container identifying metrics counters for standard cryptographic ciphers
            var allLabels = new Label[]
            {
                labAES,
                labPGP,
                labIDEA,
                labGOST,
                labAESGCM,
                labSERPENT,
                labTWOFISH,
                labCAMELLIA,
                labTHREEFISH,
                labKUZNYECHIK,
                labXCHACHA20POLY1305
            };

            // Initializes cryptographic metrics telemetry trackers to initial state values
            foreach (Label lbl in allLabels)
            {
                lbl.Text = "0";
                lbl.ForeColor = Color.Red;
                lbl.TextAlign = ContentAlignment.MiddleCenter;
            }

            // ChekBox
            // Tuple configuration matrix for layout environment configuration switches
            var allChkBox = new (CheckBox Chk, string Text, string Tip, bool Checked, bool Enabled)[]
            {
                (chkAll, "Select all engines", "Select / Deselect all encryption engines", false, true),
                (chkAutomaticdel, "Enable automatic deletion", "Use with extreme caution!", false, true),
                (chkZip, "Export the file in Zip format", "Allows storing the configuration file in compressed format", false, true),
                (chkDisplay, "Display after each modification", "Display the configuration file after each modification", false, true),
            };

            // Mass initializes visual interface environment toggle structures
            foreach (var boxOption in allChkBox)
            {
                boxOption.Chk.Enabled = boxOption.Enabled;
                boxOption.Chk.Checked = boxOption.Checked;
                boxOption.Chk.Text = boxOption.Text;
                _tt.Set(boxOption.Chk, boxOption.Tip);
                boxOption.Chk.Cursor = Cursors.Hand;
            }

            // // Engines ChekBox
            // Registry containing programmatic data targets mapping individual cryptographic suites
            var engineChkBox = new (CheckBox Chk, string Text, bool Checked, bool Enabled)[]
            {
                (chkAES, "AES", false, true),
                (chkPGP, "PGP", false, true),
                (chkIDEA, "IDEA", false, true),
                (chkGOST, "GOST", false, true),
                (chkAESGCM, "AES-GCM", false, true),
                (chkSERPENT, "SERPENT", false, true),
                (chkTWOFISH, "TWOFISH", false, true),
                (chkCAMELLIA, "CAMELLIA", false, true),
                (chkTHREEFISH, "THREEFISH", false, true),
                (chkKUZNYECHIK, "KUZNYECHIK", false, true),
                (chkXCHACHA20POLY1305, "XCHACHA20-POLY1305", false, true)
            };

            // Applies localized descriptions and defaults to cipher toggle states
            foreach (var boxOption in engineChkBox)
            {
                boxOption.Chk.Enabled = boxOption.Enabled;
                boxOption.Chk.Checked = boxOption.Checked;
                boxOption.Chk.Text = boxOption.Text;
                _tt.Set(boxOption.Chk, commonTip);
                boxOption.Chk.Cursor = Cursors.Hand;
            }

            // Radiobuttons
            // Mutual exclusion switches driving counter resets or secure context asset deletions
            var allradiobut = new (RadioButton Button, string Text, string Tip, bool Cheched, bool Enabled)[]
            {
                (rdbCounters, "Key Counters", "Reset counters for the selected engines", true, true),
                (rdbKeys, "Associated keys", "Delete the associated keys of the selected engines", false, true),
            };
            // Mounts configurations across selection state switches
            foreach (var radoption in allradiobut)
            {
                radoption.Button.Enabled = radoption.Enabled;
                radoption.Button.Checked = radoption.Cheched;
                radoption.Button.Text = radoption.Text;
                _tt.Set(radoption.Button, radoption.Tip);
                radoption.Button.Cursor = Cursors.Hand;
            }

            #endregion Form Components

            #region Event handlers

            // ChekBox
            // Binds the master toggle event handler to manage group state changes across all cryptographic engines
            chkAll.CheckedChanged += ChkAll_CheckedChanged;

            // Binds the event handler controlling the state of the secure automated deletion routine
            chkAutomaticdel.CheckedChanged += ChkAutomaticdel_CheckedChanged;

            // Binds individual cryptographic suite selection triggers to their core processing logic routines
            chkAES.CheckedChanged += ChkAES_CheckedChanged;
            chkPGP.CheckedChanged += ChkAES_CheckedChanged;
            chkIDEA.CheckedChanged += ChkAES_CheckedChanged;
            chkGOST.CheckedChanged += ChkAES_CheckedChanged;
            chkAESGCM.CheckedChanged += ChkAES_CheckedChanged;
            chkSERPENT.CheckedChanged += ChkAES_CheckedChanged;
            chkTWOFISH.CheckedChanged += ChkAES_CheckedChanged;
            chkCAMELLIA.CheckedChanged += ChkAES_CheckedChanged;
            chkTHREEFISH.CheckedChanged += ChkAES_CheckedChanged;
            chkKUZNYECHIK.CheckedChanged += ChkAES_CheckedChanged;
            chkXCHACHA20POLY1305.CheckedChanged += ChkAES_CheckedChanged;

            // Buttons
            // Maps user interaction triggers to their respective operational execution paths
            btnStart.Click += BtnStart_Click;
            btnIntegrity.Click += BtnIntegrity_Click;
            btnExport.Click += BtnExport_Click;
            btnImport.Click += BtnImport_Click;
            btnEdit.Click += BtnEdit_Click;
            btnDel.Click += BtnDel_Click;

            // ListView
            // Registers low-level rendering handlers for custom structural interface drawing
            listTamper.DrawColumnHeader += ListTamper_DrawColumnHeader;
            listTamper.DrawSubItem += ListTamper_DrawSubItem;

            // Help
            // Subscribes the user documentation and reference guide trigger to the help system interface
            btnHelp.Click += BtnHelp_Click;

            #endregion Event handlers

            #region Initialization

            // Invokes the data retrieval routine to populate and synchronize internal operational metrics counters
            LoadCounters();

            if (mainForm.Obfs == true) // Enable / Disable Obfuscate print Screen
                SpeedcryptGhost.Enable(this); // Enforces secure environment policy to obstruct external screen capture and display sniffing tools

            // Configuration File
            // Synchronizes visual interface toggle states with values fetched from the persistent XML storage engine
            chkAutomaticdel.Checked = _xmlConfig.GetValue("Result.AutomaticDeletion") == "True";
            chkZip.Checked = _xmlConfig.GetValue("Result.ExportZipFormat") == "True";
            chkDisplay.Checked = _xmlConfig.GetValue("Result.DisplayConfigurationFile") == "True";
            rdbCounters.Checked = _xmlConfig.GetValue("Result.KeysCounterFile") == "True";
            rdbKeys.Checked = _xmlConfig.GetValue("Result.AssociatedKeysFile") == "True";

            // Executes validation procedures to confirm the availability and structural integrity of key containers
            KeyExists();

            // Block space key interference
            // Attaches an input interception listener to suppress keyboard spacing actions inside specific controls
            SpaceKeyBlocker.Enable(this);

            #endregion Inizialization
        }

        #endregion Form Routines

        #region Event handlers

        // ChekBox
        private void ChkAES_CheckedChanged(object sender, System.EventArgs e)
        {
            // Triggers a visual state refresh to re-evaluate and update the operational availability of the main processing action button
            UpdateStartButton();
        }
        private void ChkAutomaticdel_CheckedChanged(object sender, System.EventArgs e)
        {
            // Reverts the structural warning label to its non-alert text representation color
            labNote.ForeColor = Color.Black;
            if (chkAutomaticdel.Checked)
            {
                // Elevates visibility status to critical warning level to alert user of imminent structural deletions
                labNote.ForeColor = Color.Red;

                // Commits the policy selection into the principal runtime environment configuration matrix
                mainForm.AutomaticDel = true;
            }
            // Synchronizes and disengages the principal runtime flag immediately if the policy selection is revoked
            else mainForm.AutomaticDel = false;
        }
        private void ChkAll_CheckedChanged(object sender, System.EventArgs e)
        {
            // Captures the updated logical selection state of the main grouping interface controller
            bool checkedState = chkAll.Checked;

            // Instantiates a tracking reference registry map containing all active individual cryptographic cipher suite toggles
            CheckBox[] engineCheckBoxes =
            {
                                         chkAES,
                                         chkPGP,
                                         chkIDEA,
                                         chkGOST,
                                         chkAESGCM,
                                         chkSERPENT,
                                         chkTWOFISH,
                                         chkCAMELLIA,
                                         chkTHREEFISH,
                                         chkKUZNYECHIK,
                                         chkXCHACHA20POLY1305
            };

            // Iterates across the collection array to execute mass logical synchronization matching the master control interface state
            foreach (CheckBox chk in engineCheckBoxes)
            {
                chk.Checked = checkedState;
            }
        }

        // Buttons
        private void BtnStart_Click(object sender, EventArgs e)
        {
            // Displays a security confirmation interception box to protect against unintended state manipulation or key deletions
            DialogResult result = MessageBox.Show("Are you sure you want to perform this operation?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            // Intercepts and aborts execution workflow immediately if operational consent is denied by the user
            if (result == DialogResult.No)
                return;

            // Queries the active user interface matrix to extract the targeted cryptographic engine collection
            List<string> selectedEngines = GetSelectedEngines();

            // Safety validation boundary preventing runtime processing execution on empty parameters or null reference containers
            if (selectedEngines == null || selectedEngines.Count == 0)
                return;

            // Selects the appropriate administrative infrastructure pathway based on chosen mutation parameters
            if (rdbCounters.Checked)
            {
                // Allocates a dedicated subsystem manager task to flush and recalibrate numeric engine transaction telemetry logs
                CounterResetManager mgr = new CounterResetManager();
                mgr.ResetCounters(selectedEngines);
            }
            else
            {
                // Instantiates an encryption context manager instance to enforce structural erasure of secure key material structures
                new EncryptionKeyResetManager().DeleteKeys(selectedEngines);

                // Dispatches an invalidation signal to flush outdated visualization structures across the master execution hierarchy
                mainForm.UpdateNodes();
            }
            // Automatically launches external administrative inspection rendering if verification review properties are enabled
            if (chkDisplay.Checked) EditFile();

            // Forces a full refresh cycle across internal dashboard telemetry models to publish up-to-date execution results
            LoadCounters();
        }
        private void BtnIntegrity_Click(object sender, EventArgs e)
        {
            // Initializes the validation subsystem component parsing target schema integrity against administrative UI logs
            var validator = new ConfigValidator(ForAllUnits.ConfigPath, listTamper, imageList1);

            // Triggers structural and cryptographic signature validation processes across the configuration file surface
            bool result = validator.Validate();

            // Invokes UI synchronization routines to re-populate local file health indicators and lists metadata
            PopulateFileStatus();

            // Updates dashboard warning systems and visual diagnostic indicators depending on integrity evaluation outcome
            UpdateTestResult(result);
        }
        private void BtnExport_Click(object sender, EventArgs e)
        {
            // Instantiates a local system file allocation dialogue interface mapping output storage layout destinations
            SaveFileDialog dlg = new SaveFileDialog();

            // Sets a descriptive window title to clearly identify the secure configuration export context
            dlg.Title = "Speedcrypt Export Configuration File";

            // Automatically enforces the correct extension binding according to the compression checkbox state to prevent unwritten layout payloads
            dlg.FileName = chkZip.Checked ? "Speedcrypt.config.zip" : "Speedcrypt.config.xml";

            // Conditionally configures file extension format criteria maps matching target compression parameters state
            dlg.Filter = chkZip.Checked
                ? "ZIP Archive (*.zip)|*.zip"
                : "XML File (*.xml)|*.xml";

            // Intercepts and terminates processing threads gracefully if the file dialog interaction is cancelled by user
            if (dlg.ShowDialog() != DialogResult.OK)
                return;

            try
            {
                // Allocates the architectural export coordinator component handling output stream packing logic
                ConfigExportManager exporter = new ConfigExportManager();

                // Serializes data matrix and transfers compiled config bytes to persistent storage target path
                exporter.Export(dlg.FileName, chkZip.Checked);

                // Displays a visual modal to confirm the configuration export completed successfully
                MessageBox.Show("Configuration exported successfully.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                // Handles operational serialization failures by warning user with standard system error display contexts
                // Displays a modal error dialog utilizing centralized localization tokens to notify the operator of export failures
                MessageBox.Show(ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);

                // Commits a persistent diagnostic trace record into the centralized auditing log infrastructure for post-mortem debugging analysis
                CentralLog.LogException(ex, "CONFIG_MANAGEMENT", "Failed to serialize and export configuration payload archive or file data.");
            }
        }
        private void BtnImport_Click(object sender, EventArgs e)
        {
            // Instantiates a native system navigation container to point down external backup storage source items
            OpenFileDialog dlg = new OpenFileDialog();

            // Sets a descriptive window title to clearly identify the secure configuration import context
            dlg.Title = "Speedcrypt Import Configuration File";

            // Enables multi-format parsing boundary options accepting regular raw text profiles or zipped package bundles
            dlg.Filter = "Config Files (*.xml;*.zip)|*.xml;*.zip";

            // Evaluates interactive workflow consent parameters and stops execution sequence if window closes unexpectedly
            if (dlg.ShowDialog() != DialogResult.OK)
                return;

            try
            {
                // Extracts the plain filename from the target path to enforce strict corporate naming conventions
                string fileNameOnly = Path.GetFileName(dlg.FileName);

                // Structural invariant check: enforces strict filename conformity to mitigate user-induced configuration drift
                if (fileNameOnly != "Speedcrypt.config.xml" && fileNameOnly != "Speedcrypt.config.zip")
                {
                    // Displays a warning dialog utilizing centralized localization tokens to notify the operator of layout naming non-compliance
                    MessageBox.Show("Warning: The selected file name is non-compliant!\nTo be imported successfully, the file must be named exactly 'Speedcrypt.config.xml' or 'Speedcrypt.config.zip'.\nPlease rename the file and try again.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Allocates configuration ingestion framework pipelines to unwrap and overwrite existing system data targets
                ConfigImportManager importer = new ConfigImportManager();

                // Executes structural ingestion parsing routines and registers mutations into current system domain context
                importer.ImportAndApply(dlg.FileName);

                // Warns system operator that operational state mutation boundaries enforce an application reboot sequence
                MessageBox.Show("Configuration imported successfully. The application will restart to apply changes.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);

                // Invokes the centralized atomic execution framework to trigger an immediate hardware-level software reboot
                LifecycleManager.ForceAtomicApplicationRestart();
            }
            catch (Exception ex)
            {
                // Safety container capture catch fallback routing system execution raw crash dumps into interface warning layers
                // Displays an immediate modal error dialog utilizing centralized localization tokens to notify the operator of ingestion failures
                MessageBox.Show("Failed to import configuration! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);

                // Commits a persistent diagnostic trace record into the centralized auditing log infrastructure for post-mortem debugging analysis
                CentralLog.LogException(ex, "CONFIG_MANAGEMENT", "Failed to import and apply configuration archive or file data.");
            }
        }
        private void BtnEdit_Click(object sender, EventArgs e)
        {
            // Invokes the local file subsystem process launcher mapping external inspection rendering handlers
            EditFile();
        }
        private void BtnDel_Click(object sender, EventArgs e)
        {
            // Displays a destructive action confirmation prompt utilizing centralized warning localization assets
            DialogResult result = MessageBox.Show("Warning: Are you absolutely sure I should delete the configuration file?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            // Aborts execution sequence immediately if user revokes erasure confirmation
            if (result == DialogResult.No)
                return;

            // Evaluates storage environment and permanently purges the primary active cryptographic configuration file resource
            if (File.Exists(ForAllUnits.ConfigurationFile)) File.Delete(ForAllUnits.ConfigurationFile);

            // Evaluates storage environment and permanently purges the secondary backup/redundant configuration container
            if (File.Exists(ForAllUnits.BckConfigurationFile)) File.Delete(ForAllUnits.BckConfigurationFile);

            // Invokes the centralized atomic execution framework to trigger an immediate hardware-level software reboot
            LifecycleManager.ForceAtomicApplicationRestart();
        }

        // ListView
        private void ListTamper_DrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            e.DrawDefault = true; // Draw header normally
        }
        private void ListTamper_DrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            // Check if it's the STATUS column (index 2)
            // Intercepts rendering pipeline specifically at index boundary matching the status result data fields
            if (e.ColumnIndex == 2)
            {
                // Forces rendering engine to paint item background layer respecting current selection and focus states
                e.DrawBackground();

                // Dynamically switches display brushes to reflect the evaluation state of security records
                Color foreColor = e.SubItem.Text == "OK" ? Color.Green :
                                  e.SubItem.Text == "FAIL" ? Color.Red :
                                  e.SubItem.ForeColor;

                // Manually paints the custom-colored tracking text status within the precise visual item bounds
                e.Graphics.DrawString(e.SubItem.Text, listTamper.Font, new SolidBrush(foreColor), e.Bounds);
            }
            else
            {
                e.DrawDefault = true; // Draw other subitems normally
            }
        }

        // Help
        private void BtnHelp_Click(object sender, EventArgs e)
        {
            // Verifies deployment directory records and attaches external compiled help file system windows to current form context
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.Configfile);
        }

        // The procedures        
        void UpdateTestResult(bool result)
        {
            // Updates human-readable layout feedback controls based on integrity evaluation outputs
            labReport.Text = result
                ? "Integrity verified: Test Passed"
                : "Integrity verified:Test Failed";

            // Safely flushes and unbinds current image structures from memory canvas pipelines before switching states
            if (picTest.Image != null)
            {
                picTest.Image = null;
            }

            // Assigns corresponding real-time operational status hardware LED simulation assets
            picTest.Image = result
                ? ForAllUnits.Ledgreen16
                : ForAllUnits.Ledred16;
        }
        void PopulateFileStatus()
         {
             // Allocates a new structural container row for interface logging data insertion
             ListViewItem item = new ListViewItem();
             item.Text = string.Empty; // Enforces empty placeholder for primary key mapping index
                                       // Appends isolated file system name metadata into the secondary dataset layer column

             item.SubItems.Add(Path.GetFileName(ForAllUnits.ConfigPath));

             // Validates real-time presence of file resource on storage medium and maps failure bounds
             if (!File.Exists(ForAllUnits.ConfigPath))
             {
                 item.SubItems.Add("FAIL"); // Updates operational verification status field
                 item.SubItems.Add("Config file not found"); // Assigns descriptive context warning string
                 listTamper.Items.Add(item); // Commits the metadata record row into visual control list
                 
                return; // Aborts subsequent document analysis paths immediately
             }

             try
             {
                 // Instantiates native structured DOM infrastructure handling schema deserialization tasks
                 XmlDocument doc = new XmlDocument();
                 doc.Load(ForAllUnits.ConfigPath); // Streams structural layout contents from physical target path

                 // Resolves parent layout object element encapsulating local configuration blocks
                 XmlElement root = doc.DocumentElement;

                 // Validates structural conformity parameters checking standard naming definitions schema
                 if (root == null || root.Name != "Configuration")
                 {
                     item.SubItems.Add("FAIL");
                     item.SubItems.Add("Invalid root node");
                     listTamper.Items.Add(item);

                     return;
                 }

                 // Executes deep relational path matching querying all configuration records collections
                 XmlNodeList keys = root.SelectNodes("Key");

                 // Assesses structural data density bounds preventing loading blank or invalid arrays structures
                 if (keys == null || keys.Count == 0)
                 {
                     item.SubItems.Add("FAIL");
                     item.SubItems.Add("No configuration entries found");
                     listTamper.Items.Add(item);

                     return;
                 }

                 // Optional: sanity check on loadability via your parser
                 // Instantiates defensive custom serialization component to run low-level ingestion trial
                 PrivateXmlConfig config = new PrivateXmlConfig();

                 // Evaluates framework ingestion capabilities against configuration target bytes stream
                 uint result = config.LoadFromFile(ForAllUnits.ConfigPath);

                 // Intercepts functional custom errors returned during lower structural translation passes
                 if (result != 0)
                 {
                     item.SubItems.Add("FAIL");
                     item.SubItems.Add("Parser rejected configuration");
                 }
                 else
                 {
                     item.SubItems.Add("OK"); // Marks entry record execution trace block validation success
                     item.SubItems.Add("Configuration valid"); // Publishes integrity verification baseline string
                 }
             }
             catch (Exception ex)
             {
                 // Captures serialization crashes or low-level operational failures to route traces onto UI rows
                 item.SubItems.Add("FAIL");
                 item.SubItems.Add(ex.Message);
             }

             // Pushes completely aggregated validation telemetry matrix row into structural data logging pane
             listTamper.Items.Add(item);            
         }
        private Icon GetFileIcon(string filePath)
        {
            // Invokes native Windows API to extract the primary icon resource handle from the target file execution path
            IntPtr hIcon = ExtractIcon(IntPtr.Zero, filePath, 0);

            // Evaluates extraction outcome and routes to system default warning indicator if native call fails
            if (hIcon == IntPtr.Zero)
                return SystemIcons.Warning;

            // Instantiates a managed Icon wrapper from the unmanaged handle and duplicates it to ensure safe ownership allocation
            Icon icon = (Icon)Icon.FromHandle(hIcon).Clone();

            // Disposes of the unmanaged native OS operating system handle resource immediately to eliminate memory leaks
            DestroyIcon(hIcon);

            return icon;
        }
        void KeyExists()
        {
            // Identifies the core configuration property string to validate inside system local settings records
            string keyName = "Result.KeysCounterFile";

            bool exists = false;

            // Queries the underlying initialization storage layer to populate all active configuration dictionary targets
            var allKeys = AppConfigHelper.XmlConfig.GetAllKeyValuePairs();

            // Performs case-insensitive linear tracking traversal across persistent properties maps to discover key token availability
            foreach (var kv in allKeys)
            {
                if (kv.Key.Equals(keyName, StringComparison.OrdinalIgnoreCase))
                {
                    exists = true;
                    break;
                }
            }

            // Applies a secure default layout state fallback initializing selection nodes if target parameters record missing
            if (!exists)
            {
                rdbCounters.Checked = true;
            }
        }
        void EditFile()
        {
            try
            {
                // Defensively tests storage systems presence parameters before invoking browser host execution systems
                if (!File.Exists(ForAllUnits.ConfigPath))
                {
                    // Triggers modal warning interface utilizing localized failure headers if data file tracking record lost
                    MessageBox.Show("Configuration file not found.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);

                    return;
                }

                // Populates operating system pipeline process information routing the targeted text schema straight onto Microsoft Edge host
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "msedge.exe",
                    Arguments = "\"" + ForAllUnits.ConfigPath + "\"",
                    UseShellExecute = true
                };

                // Dispatches processing operational threads tasking the system shell execution path to display targeted metrics configurations
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                // Routes underlying stack trace data drops safely inside persistent logging storage units filtering module flags
                CentralLog.LogException(ex, "UI", "Error opening configuration file with Edge");
            }
        }
        void UpdateStartButton()
        {
            // Evaluates logical OR operations across all cryptographic suite selection toggles to dynamically update control availability state
            btnStart.Enabled = chkAES.Checked ||
                               chkPGP.Checked ||
                               chkIDEA.Checked ||
                               chkGOST.Checked ||
                               chkAESGCM.Checked ||
                               chkSERPENT.Checked ||
                               chkTWOFISH.Checked ||
                               chkCAMELLIA.Checked ||
                               chkTHREEFISH.Checked ||
                               chkKUZNYECHIK.Checked ||
                               chkXCHACHA20POLY1305.Checked;
        }
        List<string> GetSelectedEngines()
        {
            // Allocates a temporary heap-bound collection string container to track active encryption targets
            List<string> list = new List<string>();

            // Sequential validation conditional mapping blocks collecting selected cipher suite tokens for processing pipelines
            if (chkAES.Checked) list.Add("AES");
            if (chkPGP.Checked) list.Add("PGP");
            if (chkIDEA.Checked) list.Add("IDEA");
            if (chkGOST.Checked) list.Add("GOST");
            if (chkAESGCM.Checked) list.Add("AES-GCM");
            if (chkSERPENT.Checked) list.Add("SERPENT");
            if (chkTWOFISH.Checked) list.Add("TWOFISH");
            if (chkCAMELLIA.Checked) list.Add("CAMELLIA");
            if (chkTHREEFISH.Checked) list.Add("THREEFISH");
            if (chkKUZNYECHIK.Checked) list.Add("KUZNYECHIK");
            if (chkXCHACHA20POLY1305.Checked) list.Add("XCHACHA20-POLY1305");

            return list;
        }
        void LoadCounters()
        {
            try
            {
                // Instantiates native XML DOM document memory infrastructure handling schema parsing tasks
                var doc = new XmlDocument();
                doc.Load(ForAllUnits.ConfigPath); // Streams file stream layout contents from the persistent destination path

                // Defines a fixed relational map binding database element token string keys to their corresponding dashboard UI counters
                var map = new (string Key, Label Label)[]
                {
                    ("COUNT-AES", labAES),
                    ("COUNT-PGP", labPGP),
                    ("COUNT-IDEA", labIDEA),
                    ("COUNT-GOST", labGOST),
                    ("COUNT-AES-GCM", labAESGCM),
                    ("COUNT-SERPENT", labSERPENT),
                    ("COUNT-TWOFISH", labTWOFISH),
                    ("COUNT-CAMELLIA", labCAMELLIA),
                    ("COUNT-THREEFISH", labTHREEFISH),
                    ("COUNT-KUZNYECHIK", labKUZNYECHIK),
                    ("COUNT-XCHACHA20-POLY1305", labXCHACHA20POLY1305)
                };

                // Traverses across the structural map executing targeted XPath data extractions to retrieve cipher transaction metrics
                foreach (var item in map)
                {
                    // Executes a selective relational query searching matching administrative attribute keys inside the XML nodes hierarchy
                    var node = doc.SelectSingleNode($"/Configuration/Key[@Name='{item.Key}']");

                    // Defensively extracts the attribute text wrapper falling back to safe zero metrics tracking string on empty references
                    string value = node?.Attributes["Value"]?.Value ?? "0";

                    // Publishes extracted numeric telemetry targets directly onto interface panel labels formatting text states
                    item.Label.Text = value;
                    item.Label.ForeColor = Color.Red;
                }
            }
            catch (Exception ex)
            {
                // Intercepts structural I/O or serialization failures and registers the stack dump into the centralized tracking logs
                CentralLog.LogException(ex, "UI", "Active configuration file corrupted or locked. Initiating automated disaster recovery procedure.");

                try
                {
                    // Automated Disaster Recovery: Attempts an instant silent rollback from the offline backup replica container
                    BckConfigFile.RestoreFromBackup();

                    // Re-evaluates document parsing logic post-recovery by standard execution path re-entry
                    var docRetry = new XmlDocument();
                    docRetry.Load(ForAllUnits.ConfigPath);

                    var mapRetry = new (string Key, Label Label)[]
                    {
                        ("COUNT-AES", labAES),
                        ("COUNT-PGP", labPGP),
                        ("COUNT-IDEA", labIDEA),
                        ("COUNT-GOST", labGOST),
                        ("COUNT-AES-GCM", labAESGCM),
                        ("COUNT-SERPENT", labSERPENT),
                        ("COUNT-TWOFISH", labTWOFISH),
                        ("COUNT-CAMELLIA", labCAMELLIA),
                        ("COUNT-THREEFISH", labTHREEFISH),
                        ("COUNT-KUZNYECHIK", labKUZNYECHIK),
                        ("COUNT-XCHACHA20-POLY1305", labXCHACHA20POLY1305)
                    };

                    foreach (var item in mapRetry)
                    {
                        var node = docRetry.SelectSingleNode($"/Configuration/Key[@Name='{item.Key}']");
                        string value = node?.Attributes["Value"]?.Value ?? "0";
                        item.Label.Text = value;
                        item.Label.ForeColor = Color.Green; // Visual indicator signifying the screen is successfully using recovered backup data
                    }
                }
                catch (Exception recoveryEx)
                {
                    // Total system failure boundary: triggered if both active data files and system backup replicas are permanently destroyed
                    CentralLog.LogException(recoveryEx, "UI", "Critical: Automated recovery failed. Both configuration file and backup file are unreadable.");
                }
            }
        }

        #endregion Event handlers

        #region override
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Invokes the base implementation to ensure standard operating system window closure events are processed executionally
            base.OnFormClosing(e);

            // Dispatches layout state persistence requests to commit user-selected checkboxes settings into local cache structures
            UiConfigSaver.SaveCheckBoxSetting("Result.ExportZipFormat", chkZip);
            UiConfigSaver.SaveCheckBoxSetting("Result.DisplayConfigurationFile", chkDisplay);
            UiConfigSaver.SaveCheckBoxSetting("Result.AutomaticDeletion", chkAutomaticdel);

            // Dispatches layout state persistence requests to commit mutual exclusion radio elements parameters
            UiConfigSaver.SaveRadioButtonSetting("Result.KeysCounterFile", rdbCounters);
            UiConfigSaver.SaveRadioButtonSetting("Result.AssociatedKeysFile", rdbKeys);

            // Routes down specific erasure pipelines depending on current security authorization configuration toggles
            if (chkAutomaticdel.Checked) mainForm.DelConfigFile();
            else mainForm.DelNoConfigFile();

            // Commit all changes to configuration
            // Flushes all cached system modifications and commits permanent configuration updates onto disk structures
            AppConfigHelper.Save();
        }

        #endregion override
    }
}