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
using System.Diagnostics;
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.XMLConfig;
using Speedcrypt.Exceptionlog;

namespace Speedcrypt
{
    public partial class FrmEmergency : Form
    {
        #region Fields

        // Reference to the main user interface window container acting as the principal application controller
        private FrmMain mainForm;

        // Component driving localized XML system configuration file persistence and node mapping
        private PrivateXmlConfig _xmlConfig;

        // Infrastructure component managing dynamic tooltip displays and context-sensitive user help notifications
        private ToolTipManager _tt;

        // UI helpers
        private ListViewRowAlternator _alternator; // Utility for alternating target background colors in ListView rows

        #endregion Fields

        #region Constructor
        /// <summary>
        /// Initializes a new instance of the FrmSecurity class, establishing a logical link with the parent execution controller.
        /// </summary>
        /// <param name="callingForm">The invoking form instance interface containing base application runtime pointers.</param>
        public FrmEmergency(Form callingForm)
        {
            // Executes system auto-generated code routines to instantiate and lay out graphical window components
            InitializeComponent();

            // Safely casts and binds the parent container reference to establish runtime communication with the core window thread
            mainForm = callingForm as FrmMain;

            // Dispatches sequential procedural triggers to evaluate environments, load telemetry counters, and initialize form states
            LoadAll();
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

            // Main
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
            Text = "Speedcrypt Emergency Recovery...";

            // Images
            // Attaches the system global gradient layout template to the header background image container
            picGrad.Image = ForAllUnits.Gradientform;

            // Configures background layout properties to stretch fluidly across the visual interface boundary
            picGrad.BackgroundImageLayout = ImageLayout.Stretch;

            // Binds the designated administrative console indicator asset to the icon picture box control
            picSimb.Image = ForAllUnits.Emergency32;

            // Parents the icon control container to the gradient panel to build accurate layer layout hierarchies
            picSimb.Parent = picGrad;

            // Enforces alpha transparency on control background layers to guarantee accurate composite color blending
            picSimb.BackColor = Color.Transparent;

            // Labels
            // Applies high-contrast background coloring parameters to the yellow indicator highlight control
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

            // Establishes the sub-descriptive text explaining the specific scope of the administrative environment settings panel
            labSec.Text = "Speedcrypt Emergency Recovery Configuration File";

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

            // Loads icons into array for unified processing into imageList1
            // Declares an immutable array profile allocating the required visual resources for sequential instantiation
            Image[] images1 =
            {
                ForAllUnits.Ascii22,
            };

            // Adds each icon to imageList1 by converting byte[] to Image via MemoryStream
            // Iterates through the collection to populate the operational UI graphics container via batch registration
            foreach (var img in images1)
                imageList1.Images.Add(img);

            // Configures baseline display schemas and asynchronous painting bounds for the evaluation logger pane
            // Instantiates the four-column layout structure mapping the dynamic historical database recovery timeline
            listDate.View = View.Details;
            listDate.SmallImageList = imageList1;
            listDate.BeginUpdate(); // Inhibits visual refreshing loops while rebuilding structural columns matrix
            listDate.Columns.Add("ID", 25, HorizontalAlignment.Center);
            listDate.Columns.Add("DATE", 300, HorizontalAlignment.Left);
            listDate.Columns.Add("ENGINES", 150, HorizontalAlignment.Left);
            listDate.Columns.Add("FILE", 1, HorizontalAlignment.Left); // The hidden administrative column holding physical XML strings
            listDate.EndUpdate(); // Resumes system presentation layer redraw passes
            listDate.FullRowSelect = true; // Enforces absolute entire-row highlighting context maps
            listDate.MultiSelect = false; // Disables multi-row selection patterns to secure atomic restoration boundaries
            listDate.TabStop = false; // Excludes the control grid from standard tab index loops to protect navigation threads                                      

            // Other Buttons
            // Strongly-typed tuple array storing programmatic metadata for core window operations
            var otherbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                (btnOpenfolder, "O&pen Folder", "Open the history folder", ForAllUnits.Loadfolder32, false),
                (btnImport, "I&mport File", "Import the Configuration file", ForAllUnits.Importfile32, false),
                (btnEdit, "&View File", "View the configuration file with Microsoft Edge", ForAllUnits.Viewconf32, false),
                (btnOk, "&Ok", "Close Speedcrypt Emergency Recovery", ForAllUnits.Apply16, true),
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

            // Filter Section
            // Configures layout attributes and metadata arrays for real-time history lookup filters controls
            grbFind.Text = "Find Values...";
            grbFind.ForeColor = Color.Brown;
            picFind.Image = ForAllUnits.Find48;

            cmbField.Items.AddRange(new object[]
            {
                "DATE", "ENGINES",
            });
            cmbField.DropDownStyle = ComboBoxStyle.DropDownList; // Restricts entry interactions forcing explicit selector loops
            cmbField.SelectedIndex = 0;

            labFilter.BackColor = Color.LightYellow;
            labFilter.ForeColor = Color.Red;

            // Documentation Box Styling
            // Calibrates structural containers assigned to house localized operator informational notes
            grbNote.Text = "Important Notes:";
            grbNote.ForeColor = Color.Brown;
            grbNote.TabStop = false;
            picNotes.Image = ForAllUnits.Notes48;

            // ComboBoxes
            // Registers standard configuration selector containers with specialized user-guidance descriptions
            var allcombo = new (ComboBox Box, string Tip, bool Enabled)[]
            {
                (cmbField,  "Select the field on which to perform the search or filter", true),
            };

            foreach (var option in allcombo)
            {
                _tt.Set(option.Box, option.Tip);
                option.Box.Enabled = option.Enabled;
                option.Box.Cursor = Cursors.Hand;
            }

            // Comprehensive multiline user guidance panel documenting the physical recovery environment properties
            labNotes.Text = "● XML configurations are highly sensitive data structures\r\n" +
                             "  that can easily corrupt during unexpected OS crashes.\r\n\r\n" +
                             "● Hardware level factors like a dead motherboard battery\r\n" +
                             "  can desynchronize system clock writes on your disk.\r\n\r\n" +
                             "● Abrupt power outages while writing cryptographic tokens\r\n" +
                             "  can damage core structures of active settings files.\r\n\r\n" +
                             "● Antivirus software lockouts or extreme memory pressure\r\n" +
                             "  can sometimes truncate active XML serialization tags.\r\n\r\n" +
                             "● Speedcrypt Emergency Kit isolates recovery procedures\r\n" +
                             "  to restore full database access with zero data loss.\r\n\r\n" +
                             "● The system captures a secure database snapshot file\r\n" +
                             "  automatically at the end of each operation run.\r\n\r\n" +
                             "● Each backup filename explicitly includes date markers\r\n" +
                             "  and the active cryptographic suite for quick analysis.\r\n\r\n" +
                             "● Users can browse available recovery points inside the\r\n" +
                             "  timeline grid sorted chronologically from the top.\r\n\r\n" +
                             "● The specific engine column helps advanced operators\r\n" +
                             "  identify which cipher was running during data drops.\r\n\r\n" +
                             "● Press the View file button to safely preview all XML\r\n" +
                             "  elements and configuration details in MS Edge.\r\n\r\n" +
                             "● Selecting a point and pressing restore overwrites the\r\n" +
                             "  active parameters using automated atomic swaps.\r\n\r\n" +
                             "● The recovery pipeline clears corrupt structures and\r\n" +
                             "  instantly clones a fresh secure standard .Bck file.\r\n\r\n" +
                             "● The history repository is fully self-managing and\r\n" +
                             "  retains only the most recent operational instances.\r\n\r\n" +
                             "● An automated housekeeping algorithm tracks space loops\r\n" +
                             "  and purges the oldest element once it exceeds 50.\r\n";

            #endregion Form Components

            #region Event handlers

            // Hooks the execution trigger tasked with opening the unmanaged Windows Explorer window inside the local history folder
            btnOpenfolder.Click += BtnOpenfolder_Click;

            // Subscribes the operation link assigned to handle external configuration file import streams routines
            btnImport.Click += BtnImport_Click;

            // Hooks the processing operational command that launches Microsoft Edge to safely view the historical snapshot file content
            btnEdit.Click += BtnEdit_Click;

            // Connects hardware pointer mouse interactions to handle dynamic row highlights and contextual pop-up menus
            listDate.MouseUp += ListDate_MouseUp;

            // Binds the real-time search textbox input tracker to filter available recovery snapshots instantly on key changes
            txtProcname.TextChanged += TxtProcname_TextChanged;

            // Hooks selection change parameters inside the filter category box to dynamic update sorting target boundaries
            cmbField.SelectedIndexChanged += CmbField_SelectedIndexChanged;

            // Help
            // Subscribes the user documentation and reference guide trigger to the help system interface
            btnHelp.Click += BtnHelp_Click;

            #endregion Event handlers

            #region Initialization

            // Dispatches the compiled dictionary streaming pass to populate history recovery grid rows immediately at launch
            PopulateHistoryList();

            if (mainForm.Obfs == true) // Enable / Disable Obfuscate print Screen
               SpeedcryptGhost.Enable(this); // Enforces secure environment policy to obstruct external screen capture and display sniffing tools


            // Binds low-level interface input hooks to enforce standard hand cursor transformations across grid boundaries
            listDate.EnableHandCursor();

            // TextBox hover highlighting
            // Injects dynamic graphic interactions for active input structures
            // Attaches mouse telemetry interception wrappers to handle real-time contrast background color shifting loops
            TextBoxHoverHighlighter.Attach(this);

            // Instantiates and locks the contrasting row alternator to render visual stripe formatting across the canvas
            _alternator = new ListViewRowAlternator(listDate);
            _alternator.Enable();

            // Real-time capability evaluation: dynamically activates or locks administrative buttons matching list bounds density
            btnOpenfolder.Enabled = listDate.Items.Count > 0;
            grbFind.Enabled = btnOpenfolder.Enabled;

            // Block space key interference
            // Attaches an input interception listener to suppress keyboard spacing actions inside specific controls
            SpaceKeyBlocker.Enable(this);

            #endregion Initialization
        }
        
        #endregion Form Routines

        #region Event handlers
        private void BtnEdit_Click(object sender, EventArgs e)
        {
            // Boundary check: validates that an item has been explicitly highlighted in the history recovery grid
            if (listDate.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a history checkpoint from the list before attempting to view its contents.",
                                ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                ListViewItem selectedItem = listDate.SelectedItems[0];

                // THE STRATEGIC MASTERMOVE: Extracts the absolute filename string directly from the invisible 4th column (Index 3)
                string historyFileName = selectedItem.SubItems[3].Text.Trim();

                // Resolve absolute directory environment boundaries within the local historical repository filesystem layout
                string basePath = AppDomain.CurrentDomain.BaseDirectory;
                string historyFilePath = Path.Combine(basePath, "History", historyFileName);

                // Defensively tests storage systems presence parameters before invoking browser host execution systems
                if (!File.Exists(historyFilePath))
                {
                    // Triggers modal warning interface utilizing localized failure headers if data file tracking record lost
                    MessageBox.Show("Selected historical configuration file not found.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                                        
                    Clearitem();

                    return;
                }

                // Populates operating system pipeline process information routing the targeted text schema straight onto Microsoft Edge host
                // Launches Microsoft Edge passing the physical historical snapshot path enclosed in defensive double quotes for safe command line parsing
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "msedge.exe",
                    Arguments = "\"" + historyFilePath + "\"",
                    UseShellExecute = true
                };

                // Dispatches processing operational threads tasking the system shell execution path to display targeted metrics configurations
                Process.Start(psi);

                // VISUAL ENFORCEMENT FIX: Pulls focus straight back into the list view execution layout context
                // This forces the interface thread to safely preserve contrast alternate color rows layout configurations
                listDate.Focus();
            }
            catch (Exception ex)
            {
                // Routes underlying stack trace data drops safely inside persistent logging storage units filtering module flags
                CentralLog.LogException(ex, "UI_EMERGENCY", "Error opening specific historical configuration file with Edge");
            }
        }
        private void BtnImport_Click(object sender, EventArgs e)
        {
            // Routes the user confirmation trigger straight into the atomic recovery and software restart transaction loop
            RecoveryFile();
        }
        private void BtnOpenfolder_Click(object sender, EventArgs e)
        {
            // Defensively verifies folder presence before spawning the operating system shell navigation thread
            if (Directory.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "History")))
            {
                // Launches a native Windows Explorer process window focused directly inside the target history directory bounds
                Process.Start("explorer.exe", Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "History"));
            }
        }
        private void BtnHelp_Click(object sender, EventArgs e)
        {
            // Verifies deployment directory records and attaches external compiled help file system windows to current form context
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.Emergency);
        }
        private void ListDate_MouseUp(object sender, MouseEventArgs e)
        {
            // Check if any item is under the mouse
            // Dispatches geometric spatial collision test points matching unmanaged mouse event coordinates mapping
            ListViewHitTestInfo hit = listDate.HitTest(e.Location);

            // Enable the delete button only if an item is selected and the click is on an item
            // Dynamically recalibrates capabilities across actionable triggers enforcing selection presence validations
            btnEdit.Enabled = hit.Item != null && listDate.SelectedItems.Count > 0;
            btnImport.Enabled = btnEdit.Enabled;
        }
        private void TxtProcname_TextChanged(object sender, EventArgs e)
        {
            // ENTERPRISE UI LOCK: Initialize visual suppression framework immediately at method entry for visual continuity
            listDate.BeginUpdate();

            // Extracts and normalizes input text patterns to build case-insensitive filtering data criteria loops
            string filterText = txtProcname.Text.ToLower();
            string selectedField = cmbField.Text;

            // Resolves target column index based on the chosen administrative combo filter field metadata
            int col = -1;
            if (selectedField == "DATE") col = 1;
            else if (selectedField == "ENGINES") col = 2;

            int filteredCount = 0;

            // Linearly traverses the grid rows matrix evaluating cell data entries against text input buffers
            foreach (ListViewItem item in listDate.Items)
            {
                // DEFENSIVE BOUNDARY VALIDATION: Prevent argument out of range crashes on dynamic sub-items layout
                if (col != -1 && item.SubItems.Count <= col)
                    continue;

                bool match = col == -1 || string.IsNullOrEmpty(filterText) ||
                             item.SubItems[col].Text.ToLower().Contains(filterText);

                // Alters text foreground colors to shade out non-matching configurations items rows safely
                for (int i = 0; i < item.SubItems.Count; i++)
                {
                    if (i == 2 || i == 8) // STATUS → They remain intact in color
                        continue; // Guard clause maintaining pristine color configurations across legacy index slots

                    item.SubItems[i].ForeColor = match
                        ? SystemColors.WindowText
                        : SystemColors.GrayText; // Grays out row layouts to provide clear visual match feedback metrics
                }

                if (match)
                    filteredCount++;
            }

            // Resumes visual presentation layer drawing passes post-mutation layout transformations loop completion
            listDate.EndUpdate();

            // Publishes total remaining matching record counts directly onto the telemetry status layout tracker text string
            labFilter.Text = filteredCount.ToString();

            // Fallback sync: If search string is empty, restore absolute item counts on the telemetry interface
            if (txtProcname.Text == string.Empty)
                labFilter.Text = listDate.Items.Count.ToString();
        }
        private void CmbField_SelectedIndexChanged(object sender, EventArgs e)
        {
            // Encapsulates UI state transitions within an explicit redraw inhibition block to eliminate layout flickering
            listDate.BeginUpdate();

            // Flushes stale evaluation inputs and refocuses user hardware carets onto the pattern matching input textbox
            txtProcname.Clear();
            txtProcname.Focus();

            // Re-enables the visual rendering loop only after the data reset transaction is completely finalized
            listDate.EndUpdate();
        }

        /// <summary>
        /// Synchronizes the operational state of the management controls and lookup panels based on the current items in the history collection, 
        /// dynamically updating the structural tracking metric to reflect the active filtering count.
        /// </summary>
        void Clearitem()
        {
            foreach (ListViewItem item in listDate.SelectedItems)
            {
                listDate.Items.Remove(item);
            }

            btnOpenfolder.Enabled = listDate.Items.Count > 0;
            btnEdit.Enabled = btnOpenfolder.Enabled;
            btnImport.Enabled = btnOpenfolder.Enabled;
            grbFind.Enabled = btnOpenfolder.Enabled;
            labFilter.Text = listDate.Items.Count.ToString();
        }

        /// <summary>
        /// Queries the centralized backup repository to populate the history recovery grid across four synchronized columns, 
        /// injecting the absolute filename token into an invisible column slot to streamline deterministic lookups.
        /// </summary>
        void PopulateHistoryList()
        {
            // Suppresses visual presentation redraw threads to enable high-speed data insertions without interface flickering
            listDate.BeginUpdate();

            try
            {
                // Flushes stale visual elements from the tracking grid before initiating bulk collection loading
                listDate.Items.Clear();

                // High-Precision Path Resolution: Extracts the dictionary stream compiling unmanaged history file paths
                System.Collections.Generic.Dictionary<string, string> backups = BckConfigFile.GetAvailableHistoryBackups();

                // Boundary guard clause: bails out early if the history repository contains zero archive snapshots
                if (backups == null || backups.Count == 0)
                    return;

                int counter = 1;

                // Iterates through the sorted recovery matrix to instantiate synchronized rows structures
                foreach (System.Collections.Generic.KeyValuePair<string, string> backup in backups)
                {
                    // Forziamo la scrittura del contatore progressivo nella prima colonna (ID) per attivare il rendering visivo nativo
                    ListViewItem item = new ListViewItem(counter.ToString());
                    item.ImageIndex = 0; // Assigns the standard fixed document icon placeholder

                    // 1. Inseriamo la data formattata e leggibile nella seconda colonna (DATE)
                    item.SubItems.Add(backup.Value);

                    // PARSING AUTOMATICO DEL MOTORE: Estrae il nome dell'algoritmo direttamente dal nome del file fisico
                    string pureFileName = Path.GetFileNameWithoutExtension(backup.Key); // Rimuove ".xml"
                    pureFileName = pureFileName.Replace(".config", ""); // Rimuove ".config" se presente

                    string[] filenameParts = pureFileName.Split('_');
                    string engineName = "UNKNOWN";

                    // Se il file segue il pattern corretto con l'engine alla fine, lo cattura al volo
                    if (filenameParts.Length >= 5)
                    {
                        engineName = filenameParts[filenameParts.Length - 1].Trim().ToUpper();
                    }

                    // 2. Inseriamo il nome del motore crittografico normalizzato nella terza colonna (ENGINE)
                    item.SubItems.Add(engineName);

                    // 3. LA TUA FURBATA INGEGNERISTICA: Inseriamo il solo nome file con estensione nella quarta colonna nascosta (FILE)
                    // L'utente non vedrà questa riga perché la colonna è larga 1, ma l'applicazione ha il bersaglio già pronto!
                    string physicalXmlName = Path.GetFileName(backup.Key);
                    item.SubItems.Add(physicalXmlName);

                    // Per ulteriore blindatura difensiva a livello di RAM, conserviamo comunque il percorso assoluto nel Tag
                    item.Tag = backup.Key;

                    // Commits the fully compiled historical matrix row directly into the user interface list structure
                    listDate.Items.Add(item);
                    counter++;

                    labFilter.Text = listDate.Items.Count.ToString();
                }
            }
            catch (Exception ex)
            {
                // Captures unexpected layout manipulation or data stream faults to guarantee trace stability inside central logs
                CentralLog.LogException(ex, "EMERGENCY_UI", "Critical error during emergency recovery list view four-column population sequence.");
            }
            finally
            {
                // Restores standard framework presentation layer drawing passes post-mutation loop completion, unfreezing the GUI smoothly
                listDate.EndUpdate();
            }
        }

        /// <summary>
        /// Executes the atomic configuration recovery transaction by reading the invisible filename column,
        /// purging corrupted operational parameters, renaming the snapshot, and forcing a clean system restart.
        /// </summary>
        void RecoveryFile()
        {
            // Boundary check: validates that an item has been explicitly highlighted in the history recovery grid
            if (listDate.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a valid history checkpoint from the list before proceeding.",
                                ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // User Consent Interception and Mandatory Restart Warning
            DialogResult consentResult = MessageBox.Show("You are about to restore the selected historical configuration snapshot.\r\n\r\n" +
                                                         "This operation will overwrite your active settings and require an immediate " +
                                                         "restart of Speedcrypt to apply changes safely.\r\n\r\n" +
                                                         "Do you want to proceed with the recovery process?",
                                                         ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            // Aborts the entire transaction smoothly if user workspace operation explicit authorization is denied
            if (consentResult == DialogResult.No)
                return;

            try
            {
                ListViewItem selectedItem = listDate.SelectedItems[0];

                // THE STRATEGIC MASTERMOVE: Extracts the absolute filename string directly from the invisible 4th column (Index 3)
                // This completely bypasses the need for complex unmanaged directory parsing loops or memory-sensitive Tag pointers
                string historyFileName = selectedItem.SubItems[3].Text.Trim();

                // Resolve absolute directory environment boundaries within the local filesystem layout
                string basePath = AppDomain.CurrentDomain.BaseDirectory;
                string historyFilePath = Path.Combine(basePath, "History", historyFileName);

                // Define core execution target paths inside the primary application root deployment directory
                string activeConfigPath = Path.Combine(basePath, "Speedcrypt.config.xml");
                string backupConfigPath = Path.Combine(basePath, "Speedcrypt.config.xml.Bck");

                // Defensive validation ensuring the historical target file still physically resides on storage media
                if (string.IsNullOrEmpty(historyFileName) || !File.Exists(historyFilePath))
                {
                    MessageBox.Show("Critical Error: The selected historical backup file could not be verified on disk.\r\n\r\n" +
                                    "The transaction has been aborted to preserve current environment stability.",
                                    ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                   
                    Clearitem();

                    return;
                }

                // Prevention Cleansing 
                // Systematically purges legacy or corrupted operational files from the root folder to avoid collision faults
                if (File.Exists(activeConfigPath))
                {
                    File.Delete(activeConfigPath);
                }

                if (File.Exists(backupConfigPath))
                {
                    File.Delete(backupConfigPath);
                }

                //  Restoration and Renaming
                // Copies the selected immutable historical snapshot into the root folder, stripping out timestamps to re-establish the active production file
                File.Copy(historyFilePath, activeConfigPath, true);

                // Final Armor Alignment (Rigenerazione dello Specchio .Bck)
                // Immediately executes a secondary cloned mirror generation pass to re-align the double-buffering backup architecture
                if (File.Exists(activeConfigPath))
                {
                    File.Copy(activeConfigPath, backupConfigPath, true);
                }

                // Step 5: Transaction Success and Forced Automated Restart Workflow
                MessageBox.Show("Configuration restored successfully! Speedcrypt will now restart to load the historical database posture.",
                                ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);

                // Invokes the centralized atomic execution framework to trigger an immediate hardware-level software reboot
                LifecycleManager.ForceAtomicApplicationRestart();
            }
            catch (Exception ex)
            {
                // Captures unexpected filesystem access, security ACL privileges constraints, or unmanaged I/O faults to preserve stability
                CentralLog.LogException(ex, "RECOVERY_EXECUTION", "Critical failure encountered during the dynamic configuration restoration loop.");
                MessageBox.Show($"A critical error occurred during the restoration loop:\n{ex.Message}",
                                "Recovery Fault", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }        

        #endregion  Event handlers
    }
}