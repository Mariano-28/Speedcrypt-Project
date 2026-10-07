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
using System.Drawing;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.Protect;
using Speedcrypt.XMLConfig;

namespace Speedcrypt
{
    public partial class FrmSecurity : Form
    {
        #region Fields

        // Reference to the main user interface window container acting as the principal application controller
        private FrmMain mainForm;

        // Infrastructure component managing dynamic tooltip displays and context-sensitive user help notifications
        private ToolTipManager _tt;

        // Component driving localized XML system configuration file persistence and node mapping
        private PrivateXmlConfig _xmlConfig;

        // Core software security wrapper enforcing runtime validation and anti-tamper mechanisms
        private SpeedcryptProtection _protection;

        /// <summary>
        /// Native Windows API function to retrieve an unmanaged icon handle from an executable or dynamic-link library (DLL).
        /// </summary>
        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr ExtractIcon(IntPtr hInst, string lpszExeFileName, int nIconIndex);

        /// <summary>
        /// Native Windows API function to release operating system resources allocated to an unmanaged icon handle.
        /// </summary>
        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr hIcon);

        // Cryptographic system hardware input constant signifying a low-level keyboard key release event trigger
        private const uint KEYEVENTF_KEYUP = 0x0002;

        #endregion Fields

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the FrmSecurity class, establishing a logical link with the parent execution controller.
        /// </summary>
        /// <param name="callingForm">The invoking form instance interface containing base application runtime pointers.</param>
        public FrmSecurity(Form callingForm)
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
            Text = "Speedcrypt Security...";

            // Images
            // Attaches the system global gradient layout template to the header background image container
            picGrad.Image = ForAllUnits.Gradientform;

            // Configures background layout properties to stretch fluidly across the visual interface boundary
            picGrad.BackgroundImageLayout = ImageLayout.Stretch;

            // Binds the designated administrative console indicator asset to the icon picture box control
            picSimb.Image = ForAllUnits.Konsole32;

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
            labSec.Text = "Basic Settings to Control Speedcrypt Security";

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
            // Localizes container panels driving layout separation for testing procedures and runtime options
            grbTamper.Text = "Security Test:";
            grbTamper.ForeColor = Color.Brown;
            grbOptions.Text = "Other Options:";
            grbOptions.ForeColor = grbTamper.ForeColor;

            // Buttons
            // Defines vertical padding offset metric used during iterative button layout initialization
            int verticalSpacing = 5;
            // Instantiates a strongly-typed tuple array tracking structural parameters for core functional action items
            var allbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                (btnTest, "Start &Test", "Start the Selected Test", ForAllUnits.Connect32, true),
                (btnCapture, "Capture", "Capture screen", ForAllUnits.Cut32, true),
                (btnOk, "&Ok", "Close Speedcrypt Security", ForAllUnits.Apply16, true),

            };
            // Iterates the action buttons matrix to apply global UI styles and hook context tooltips
            foreach (var optionbut in allbutton)
            {
                optionbut.Button.Text = optionbut.Text;
                _tt.Set(optionbut.Button, optionbut.Tip); // Binds localized context-sensitive help strings
                optionbut.Button.Cursor = Cursors.Hand; // Standardizes mouse pointer response profile upon boundary entry
                optionbut.Button.Image = optionbut.Icon;
                optionbut.Button.ImageAlign = ContentAlignment.MiddleCenter;
                optionbut.Button.TextAlign = ContentAlignment.BottomCenter;
                optionbut.Button.Enabled = optionbut.Enabled;
                optionbut.Button.Padding = new Padding(0, 0, 0, verticalSpacing); // Enforces absolute bottom spacing constraints
            }
            // other Buttons
            // Configures specific layout properties for the contextual reference guide button link
            btnHelp.Text = "&Help";
            btnHelp.Image = ForAllUnits.Help16;
            btnHelp.ImageAlign = ContentAlignment.MiddleLeft;
            btnHelp.Cursor = btnOk.Cursor;
            _tt.Set(btnHelp, "View Help Guide");

            // CechkcBoxs
            // Instantiates configuration array tracking logical environment toggle switches properties
            var allChkBox = new (CheckBox Chk, string Text, string Tip, bool Checked, bool Enabled)[]
            {
                (chkObfuscate, "Obfuscate Print Screen", "Prevents Windows Print Screen from capturing Speedcrypt screenshots", false, true),
            };
            // Iterates and mas-initializes runtime behavioral parameter switches across target checkbox wrappers
            foreach (var boxOption in allChkBox)
            {
                boxOption.Chk.Enabled = boxOption.Enabled;
                boxOption.Chk.Checked = boxOption.Checked;
                boxOption.Chk.Text = boxOption.Text;
                _tt.Set(boxOption.Chk, boxOption.Tip);
                boxOption.Chk.Cursor = Cursors.Hand;
            }

            // RadioButons
            // Mutual exclusion setup driving user validation choice targets across diagnostic systems
            var allradiobut = new (RadioButton Button, string Text, string Tip, bool Cheched)[]
            {
                 (rdbTamper,    "Anti-Tamper Test",    "Perform targeted Anti-Tamper Test", true),
                 (rdbConfig,    "Configuration File Test",    "Perform targeted Configuration File Test", false),
            };
            // Initializes selection parameters and mouse reaction profiles across radio options structures
            foreach (var radoption in allradiobut)
            {
                radoption.Button.Checked = radoption.Cheched;
                radoption.Button.Text = radoption.Text;
                _tt.Set(radoption.Button, radoption.Tip);
                radoption.Button.Cursor = Cursors.Hand; // set hand cursor
            }

            // ImageList
            // Compiles embedded graphical icon assets used for list row state evaluation feedback
            Image[] images1 = { ForAllUnits.Round22,
                    ForAllUnits.Apply22,
                    ForAllUnits.Ascii22};
            // Caches system assets directly into the localized grid image index pipeline registry
            foreach (var img in images1)
                imageList1.Images.Add(img);

            // ListView
            // Configures baseline display schemas and asynchronous painting bounds for the evaluation logger pane
            listTamper.View = View.Details;
            listTamper.SmallImageList = imageList1;
            listTamper.BeginUpdate(); // Inhibits visual refreshing loops while rebuilding structural columns matrix
            listTamper.Columns.Add("ID", 25, HorizontalAlignment.Center);
            listTamper.Columns.Add("FILE", 350, HorizontalAlignment.Left);
            listTamper.Columns.Add("STATUS", 60, HorizontalAlignment.Left);
            listTamper.Columns.Add("DETAILS", 120, HorizontalAlignment.Left);
            listTamper.EndUpdate(); // Resumes system presentation layer redraw passes
            listTamper.OwnerDraw = true; // Enables low-level interface interception overrides for custom element painting

            // Images
            // Allocates default visual assets reflecting core informational panel icons properties
            picNote.Image = ForAllUnits.Notes22;
            picObusc.Image = ForAllUnits.Display22;
            picTest.Image = ForAllUnits.Ledorange16; // Sets baseline pending operational alert color

            // Labels
            // Configures default instructional text styles and alert hierarchies across data display blocks
            labReport.Text = "Security test validation: Ready:";
            labNotes.Font = new Font(labNotes.Font.FontFamily, 10, FontStyle.Regular);
            labNotes.ForeColor = Color.Red;
            labNotes.Text = "Notes...";

            // Rich informational multiline documentation strings driving user advisory notices layouts
            labTest.Text = "● For your safety and that of Speedcrypt, \r\n" +
                           "perform these tests periodically.\r\n\r\n " +
                           "● Remember to backup sensitive data if the \r\n" +
                           "test results are positive. \r\n\r\n" +
                           "● The backup keeps you safe in case the project\r\n " +
                           "is attacked and its files are tampered with. \r\n\r\n" +
                           "● You will be able to restore the sensitive files and \r\n" +
                           "the full operational functionality of Speedcrypt.\r\n\r\n" +
                           "● To perform the backup of sensitive data, you must \r\n" +
                           "call the module named Utility. After running the tests \r\n" +
                           "and obtaining positive results, display the module using\r\n " +
                           "the dedicated Menu.";

            // Explanatory guidance string block clarifying the operational scope of screen captures capture boundaries
            labScreen.Text = "● Enable this option if you want to prevent anyone\r\n " +
                             "through Windows screenshots. \r\n\r\n" +
                             "● When the protection is active, all images related \r\n" +
                             "to Speedcrypt windows will be obscured.";

            #endregion Form Components

            #region Event handlers

            // Maps the diagnostic execution path trigger to the primary validation workflow action button
            btnTest.Click += BtnTest_Click;

            // Binds the operational testing action button to intercept and evaluate current screen capture contexts
            btnCapture.Click += BtnCapture_Click;

            // Hooks status change updates on the anti-tamper targeted evaluation selection switch
            rdbTamper.CheckedChanged += RdbTamper_CheckedChanged;

            // Hooks status change updates on the system configuration validation pathway selection switch
            rdbConfig.CheckedChanged += RdbConfig_CheckedChanged;

            // Monitors interactive state mutations driving real-time print screen interception policies updates
            chkObfuscate.CheckedChanged += ChkObfuscate_CheckedChanged;

            // Registers low-level infrastructure drawing interception routines for custom column schemas rendering
            listTamper.DrawColumnHeader += ListTamper_DrawColumnHeader;

            // Registers low-level framework layout drawing interception routines for custom item values painting
            listTamper.DrawSubItem += ListTamper_DrawSubItem;

            // Subscribes the contextual documentation navigation trigger to the administrative help system panel
            btnHelp.Click += BtnHelp_Click;

            #endregion Event handlers

            #region Initialization

            // Synchronizes the user interface toggle selection state with variables fetched from the persistent XML storage engine
            chkObfuscate.Checked = _xmlConfig.GetValue("Result.ObfuscatePrintScreen") == "True";
            if (chkObfuscate.Checked) SpeedcryptGhost.Enable(this); // Enforces secure runtime execution policy to obstruct snapshot sniffing if set to true
                                                                    // Instantiates the structural anti-tamper subsystem module configuring safe diagnostic auditing without data erasure
            
            _protection = new SpeedcryptProtection(wipeOnViolation: false);

            // Block space key interference
            // Attaches an input interception listener to suppress keyboard spacing actions inside specific controls
            SpaceKeyBlocker.Enable(this);

            #endregion Initialization
        }

        #endregion Form Routines

        #region Event handlers
        private void BtnTest_Click(object sender, EventArgs e)
        {
            listTamper.Items.Clear();

            if (rdbTamper.Checked)
            {
                bool result = _protection.Validate();
                PopulateFileStatus();
                UpdateTestResult(result);
            }
            else if (rdbConfig.Checked)
            {
                var validator = new ConfigValidator(ForAllUnits.ConfigPath, listTamper, imageList1);
                bool result = validator.Validate();
                UpdateTestResult(result);
            }
        }
        private void BtnCapture_Click(object sender, EventArgs e)
        {
            Capturescreen.TriggerCapture();
        }
        private void RdbTamper_CheckedChanged(object sender, EventArgs e)
        {
            // Rename column KEY -> FILE on the fly
            foreach (ColumnHeader col in listTamper.Columns)
            {
                if (col.Text == "KEY")
                {
                    col.Text = "FILE";
                    break;
                }
            }

            cleartest();
        }
        private void RdbConfig_CheckedChanged(object sender, EventArgs e)
        {
            // Rename column FILE -> KEY on the fly
            foreach (ColumnHeader col in listTamper.Columns)
            {
                if (col.Text == "FILE")
                {
                    col.Text = "KEY";
                    break;
                }
            }

            cleartest();
        }
        private void ChkObfuscate_CheckedChanged(object sender, EventArgs e)
        {
            if (chkObfuscate.Checked)
            {
                SpeedcryptGhost.Enable(this);
                mainForm.Obfs = true;
                mainForm.ActivateGhost();
            }
            else
            {
                SpeedcryptGhost.Disable(this);
                mainForm.Obfs = false;
            }
        }
        private void ListTamper_DrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            e.DrawDefault = true; // Draw header normally
        }
        private void ListTamper_DrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            // Check if it's the STATUS column (index 2)
            // Intercepts the graphics rendering pipeline specifically at index boundary matching the status result data fields
            if (e.ColumnIndex == 2)
            {
                // Forces the rendering engine to paint the item background layer respecting current selection and focus states
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
        private void BtnHelp_Click(object sender, EventArgs e)
        {
            // Verifies deployment directory records and attaches external compiled help file system windows to current form context
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.Security);
        }

        #endregion Event handlers

        #region Procedures
        void cleartest()
        {
            // Resets the real-time operational status hardware LED simulation asset and updates human-readable layout feedback controls
            picTest.Image = ForAllUnits.Ledorange16; labReport.Text = "Security test validation: Ready:";

            // Flushes and clears any previous diagnostic or verification validation rows from the visualization grid layout
            listTamper.Items.Clear();
        }
        void UpdateTestResult(bool result)
        {
            // Updates the core dashboard warning labels to publish the comprehensive environment posture evaluation outcome
            labReport.Text = result
                ? "Speedcrypt Integrity verified: Test Passed"
                : "Speedcrypt Integrity verified:Test Failed";

            // Safely flushes and unbinds current image structures from memory canvas pipelines before switching states
            if (picTest.Image != null)
            {
                picTest.Image = null;
            }

            // Assigns the corresponding real-time operational status visual indicator mapping the verification output metrics
            picTest.Image = result
                ? ForAllUnits.Ledgreen16
                : ForAllUnits.Ledred16;
        }
        void PopulateFileStatus()
        {
            // Instantiates an auxiliary protection subsystem reference to query static cryptographic security records
            SpeedcryptProtection protection = new SpeedcryptProtection();

            // Extracts the strongly-typed array matrices mapping internal critical software files and their respective baseline hash signatures
            string[] criticalFiles = protection.GetCriticalFiles();
            byte[][] criticalHashes = protection.GetCriticalHashes();

            // Safety validation boundary preventing runtime iteration processing on empty parameters or null reference containers
            if (criticalFiles == null || criticalHashes == null)
                return;

            // Detects structural data divergence where the file registry counts do not align with the signatures collection counts
            if (criticalFiles.Length != criticalHashes.Length)
            {
                // Critical mismatch: protection data corrupted
                // Allocates a critical mismatch alert container row to notify the operator that protection schemas are corrupted
                ListViewItem errorItem = new ListViewItem();
                errorItem.Text = string.Empty;
                errorItem.SubItems.Add("PROTECTION DATA");
                errorItem.SubItems.Add("FAIL");
                errorItem.SubItems.Add("Critical mismatch in protection definitions");
                listTamper.Items.Add(errorItem);

                return; // Aborts subsequent individual file analysis workflows immediately
            }

            // Loops through the synchronized files collection to execute deep structural hash verification scans item by item
            for (int i = 0; i < criticalFiles.Length; i++)
            {
                // Dispatches localized individual checking tasks to populate target validation metrics inside the visualization grid
                AddFileStatusItem(criticalFiles[i], criticalHashes[i]);
            }
        }
        void AddFileStatusItem(string file, byte[] expectedHash)
        {
            // Normalizes the filename to a lower-case invariant string token to establish a consistent image registry look-up key
            string key = file.ToLowerInvariant();

            // Enforces icon buffer availability by checking or dynamically extracting and caching the target file visual asset
            EnsureImageKey(file, key);

            // Allocates a new structural row item container for data entry logging within the visualization panel
            ListViewItem item = new ListViewItem();

            item.ImageKey = key; // Assigns the registered dynamic icon look-up key token to the list row
            item.Text = string.Empty; // Enforces an empty placeholder for the primary indexing column
            
            // Extracts and appends the isolated filesystem filename into the secondary description layer column
            item.SubItems.Add(Path.GetFileName(file));

            // Defensively validates the real-time presence of the physical resource on disk before initializing cryptographic streaming
            if (!File.Exists(file))
            {
                item.SubItems.Add("FAIL"); // Updates the diagnostic execution state field to failed status
                item.SubItems.Add("File not found"); // Attaches a descriptive missing resource context warning string
                listTamper.Items.Add(item); // Commits the completed failure record row directly into the user interface list
                return; // Aborts subsequent cryptographic hashing evaluation pipelines immediately
            }

            try
            {
                // Streams the file contents from disk to calculate its current real-time mathematical digest signature
                byte[] actualHash = ComputeSha256(file);

                // Executes a byte-by-byte verification check comparing the newly computed signature against the embedded baseline
                if (IsHashValid(actualHash, expectedHash))
                {
                    item.SubItems.Add("OK"); // Marks entry record execution trace block verification success
                    item.SubItems.Add("Integrity verified"); // Publishes a positive cryptographic signature match baseline string
                }
                else
                {
                    item.SubItems.Add("FAIL"); // Marks structural mismatch verification failure
                    item.SubItems.Add("Hash mismatch"); // Attaches an explicit tampered signature modification alert string
                }
            }
            catch (Exception ex)
            {
                // Captures operational I/O crashes or file locking block failures to route stack dumps safely onto the UI row fields
                item.SubItems.Add("FAIL");
                item.SubItems.Add(ex.Message);
            }

            // Pushes the fully compiled validation telemetry matrix row into the structural logging pane
            listTamper.Items.Add(item);
        }
        byte[] ComputeSha256(string file)
        {
            // Instantiates a secure read-only shared input stream to process file bytes without locking out other operational processes
            using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))

            // Initializes the native cryptographic managed provider pipeline to execute SHA-256 data digestion passes
            using (SHA256 sha = SHA256.Create())
            {
                // Computes and returns the fixed 256-bit binary hash array signature representing the streamed resource surface
                return sha.ComputeHash(fs);
            }
        }
        bool IsHashValid(byte[] actual, byte[] expected)
        {
            // Safety validation boundary preventing comparison passes on unallocated or null reference memory parameters
            if (actual == null || expected == null)
                return false;

            // Evaluates structural byte density size metrics to fail early if array sizes diverge from standard specifications
            if (actual.Length != expected.Length)
                return false;

            // Executes a linear sequential byte-level equality validation to confirm absolute cryptographic conformity across both hashes
            return actual.SequenceEqual(expected);
        }
        void EnsureImageKey(string file, string key)
        {
            // Evaluates cache presence parameters within the system visual registry index pipeline to prevent duplicate asset allocation
            if (imageList1.Images.ContainsKey(key))
                return;

            Image img;

            // Checks specifically if the targeted execution signature matches the primary system operational binary name
            if (Path.GetFileName(file).Equals("Speedcrypt.exe", StringComparison.OrdinalIgnoreCase))
            {
                // Extracts the unmanaged native icon layout profile from the physical assembly with a safe system error fallback interface
                Icon ico = File.Exists(file) ? GetFileIcon(file) : SystemIcons.Error;

                // Transmutes the unmanaged icon structure metadata into a managed bitmap rendering engine pixel canvas surface
                img = ico.ToBitmap();
            }
            else
            {
                // Fallback default assignment loading the primary baseline standard placeholder icon index asset from the cached registry
                img = imageList1.Images[0];
            }

            // Commits the finalized graphical asset mapping it to its normalized lowercase invariant key registry look-up string
            imageList1.Images.Add(key, img);
        }
        Icon GetFileIcon(string filePath)
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
        void SaveCheckboxSetting(string key, CheckBox checkbox)
        {
            // Transmutes the visual interface selection state parameter into a text string representation and caches it into the persistent configuration matrix
            AppConfigHelper.XmlConfig.SetValue(key, checkbox.Checked.ToString());
        }

        #endregion Procedures

        #region Override
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Dispatches layout state persistence requests to commit the user-selected print screen obfuscation preference into the settings file cache
            SaveCheckboxSetting("Result.ObfuscatePrintScreen", chkObfuscate);

            // Flushes all cached environment modifications and commits permanent configuration updates onto the disk surface
            AppConfigHelper.Save();

            // Broadcasts real-time interception listener update signals to dynamically re-evaluate the screen-capture protection posture on the core window thread
            mainForm.ActivateGhost();

            // Invokes the base implementation to ensure standard operating system window lifecycle termination events are fully processed executionally
            base.OnFormClosing(e);
        }

        #endregion Override
    }
}