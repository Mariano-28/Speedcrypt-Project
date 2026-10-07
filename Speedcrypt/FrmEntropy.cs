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
using System.Security.Cryptography;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.XMLConfig;
using Speedcrypt.Passwordgen;
using Speedcrypt.Exceptionlog;

namespace Speedcrypt
{  
    public partial class FrmEntropy : Form
    {
        #region Cryptographic Fields

        // Manages localized, context-aware UI/UX help overlays for secure parameter inputs
        private ToolTipManager _tt; // Tooltip Manager

        // Buffers high-entropy data utilizing multi-source noise for cryptographic seeding
        private EntropyPool _pool; // Entropy Pool

        // Handles the encrypted local configuration subsystem for restricted metadata persistence
        private PrivateXmlConfig _xmlConfig; // XML Config

        // Exposes the immutable volatile raw cryptographic seed data array to the application
        public byte[] CollectedEntropy { get; private set; } // Entropy Seed

        // Drives the thread-safe entropy harvesting state machine loop execution status
        private bool _isCollecting; // Collection State

        #endregion Cryptographic Fields

        #region Constructor
        public FrmEntropy(Form callingForm)
        {
            InitializeComponent(); // Initializes all UI components and controls
            loadall();// Loads application configuration and initializes runtime state
        }

        #endregion Constructor

        #region Form Routines
        void loadall()
        {
            #region Form Components

            // Initializes the tooltip manager used to provide contextual help for UI controls
            _tt = new ToolTipManager(); // Tooltip

            // Retrieves the global XML configuration handler used across the application
            _xmlConfig = AppConfigHelper.XmlConfig; // For all

            // Initializes the entropy pool used to collect additional randomness from user input
            _pool = new EntropyPool();

            // Creates the OpenFileDialog instance used throughout the application
            ForAllUnits.openFileDialog1 = new OpenFileDialog();

            // Assigns the application icon extracted from the executable file
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;

            // Disables the maximize button to enforce fixed dialog behavior
            MaximizeBox = false;

            // Disables the minimize button to keep the dialog modal and focused
            MinimizeBox = false;

            // Sets a fixed dialog border to prevent resizing
            FormBorderStyle = FormBorderStyle.FixedDialog;

            // Centers the form on screen when it is displayed
            StartPosition = FormStartPosition.CenterScreen;

            // Sets the window title for the entropy generation dialog
            Text = "Extra Entropy...";

            // Images

            // Loads the gradient background image used in the form header
            picGrad.Image = ForAllUnits.Gradientform;

            // Ensures the gradient background stretches to fill the container
            picGrad.BackgroundImageLayout = ImageLayout.Stretch;

            // Sets the entropy icon representing randomness generation
            picSimb.Image = ForAllUnits.Entropy32;

            // Attaches the icon control to the gradient header container
            picSimb.Parent = picGrad;

            // Enables transparent rendering over the gradient background
            picSimb.BackColor = Color.Transparent;

            // Labels

            // Decorative yellow strip used in the UI layout
            labYel.BackColor = Color.Yellow;

            // Main header text describing the dialog purpose
            labFir.Text = "Additional Entropy...";

            // Places the label inside the gradient header container
            labFir.Parent = picGrad;

            // Enables transparent background for proper overlay rendering
            labFir.BackColor = Color.Transparent;

            // Sets header text color
            labFir.ForeColor = Color.White;

            // Applies bold styling to emphasize the header
            labFir.Font = new Font(labFir.Font.FontFamily, 10, FontStyle.Bold);

            // Secondary description explaining the dialog purpose
            labSec.Text = "Create additional entropy for your password";

            // Places the secondary label on the gradient header
            labSec.Parent = picGrad;

            // Enables transparent rendering over the background
            labSec.BackColor = Color.Transparent;

            // Sets text color for readability over gradient
            labSec.ForeColor = Color.White;

            // Applies standard font styling
            labSec.Font = new Font(labSec.Font.FontFamily, 10);

            // Removes border for a clean input display area
            labKeyboardInput.BorderStyle = BorderStyle.None;

            // Sets the background color for the keyboard input display field
            labKeyboardInput.BackColor = Color.White;

            // Mouse Random input Image

            // Assigns the image representing mouse-based entropy collection
            picPsw.Image = ForAllUnits.Entropy;

            #endregion Form Components

            #region Miscellaneous

            // Buttons
            // This array defines the main action buttons used by the entropy collector dialog.
            // Each tuple contains the Button control, its display text, tooltip text, icon and initial enabled state.
            var allbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                 (btnStart, "Start", "Start the entropy collector", ForAllUnits.Energy16, true),
                 (btnReset, "Reset", "Reset the entropy collector", ForAllUnits.Reload16, false),
                 (btnCanc, "Cancel", "Close the entropy collector", ForAllUnits.No16, true),
                 (btnOk, "&OK", "Accept the generated entropy", ForAllUnits.Apply16, true),
            };

            foreach (var optionbut in allbutton)
            {
                // Assigns the display text for the button
                optionbut.Button.Text = optionbut.Text;

                // Associates a tooltip with the button for user guidance
                _tt.Set(optionbut.Button, optionbut.Tip);

                // Changes the mouse cursor to a hand pointer to indicate a clickable control
                optionbut.Button.Cursor = Cursors.Hand;

                // Assigns the corresponding icon to the button
                optionbut.Button.Image = optionbut.Icon;

                // Sets the initial enabled/disabled state of the button
                optionbut.Button.Enabled = optionbut.Enabled;
            }

            // This block is intentionally structured for future ComboBox controls.
            // It is included in every UI section so that developers modifying the source code
            // will already find the ComboBox initialization structure prepared and consistent.
            var allcombo = new (ComboBox Box, string Tip, bool Enabled)[]
            {
                (cmbEntropyValue,  "Select the appropriate values based on your system", true),
                // Other Combo...
            };

            foreach (var option in allcombo)
            {
                // Assigns tooltip help text to the ComboBox
                _tt.Set(option.Box, option.Tip);

                // Sets the enabled/disabled state
                option.Box.Enabled = option.Enabled;

                // Uses a hand cursor to indicate that the control is interactive
                option.Box.Cursor = Cursors.Hand;
            }

            #endregion Miscellaneous

            #region Entropy Pool

            // GroupBox used for collecting random entropy from mouse and keyboard input
            grbMouse.Text = "Random Mouse Input:";
            grbKeyb.Text = "Random Keyboard Input:";

            // Visual style for entropy input sections
            grbMouse.ForeColor = Color.Brown;
            grbKeyb.ForeColor = grbMouse.ForeColor;

            // Labels configuration

            // Label describing the control buttons
            labStart.Text = "Start Pause Reset:";

            // Instruction label for user interaction
            labMouseKeyb.Text = "Move the mouse and type randomly on the keyboard";
            labMouseKeyb.ForeColor = Color.Brown;

            // Informational label describing that entropy collection can be customized
            labCustom.Text = "● Entropy collection is customizable based on your system";

            // Label associated with the entropy value ComboBox
            labValue.Text = "Select the appropriate values:";
            labValue.ForeColor = Color.Brown;

            // Detailed hint explaining how to properly generate entropy
            labHint.Text = "Adjust the values that best suit your system to obtain \r\n" +
                           "good additional entropy collection, and always alternate \r\n" +
                           "mouse movements with keyboard typing in the most \r\n" +
                           "random way possible. You can reset the collection and \r\n" +
                           "try again with new values!\r\n";

            // Predefined entropy target values available for the entropy pool
            cmbEntropyValue.Items.AddRange(new object[]
            {
                "256", "384", "512", "1024", "2048", "4096"
            });

            // Prevent manual editing: only predefined values can be selected
            cmbEntropyValue.DropDownStyle = ComboBoxStyle.DropDownList;

            // Default entropy target value (1024 bits)
            cmbEntropyValue.SelectedIndex = 3;

            #endregion Entropy Pool

            #region Configuratino File

            try
            {
                cmbEntropyValue.Text = _xmlConfig.GetValue("Result.PSWEntropyValueCollect");
                // Other Keys...
            }
            catch (Exception ex)
            {
                // Silent Exception
                CentralLog.LogException(ex, "Additional Entropy", "Handled exceptions during module loading! " + ex.Message);
            }

            #endregion Configuration File

            #region Events Handler

            // Buttons
            btnStart.Click += BtnStart_Click;
            btnReset.Click += BtnResetEntropy_Click;
            btnCanc.Click += BtnCanc_Click;
            this.FormClosing += FrmEntropy_FormClosing;

            // Entropy Values
            cmbEntropyValue.SelectedIndexChanged += CmbEntropyValue_SelectedIndexChanged;
            _pool.BitsCollectedChanged += Pool_BitsCollectedChanged;
            _pool.Completed += Pool_CompletedUpdate;

            #endregion Events Handler

            #region Initialization

            // Resets the progress tracking component bounds to zero percentage
            progressBar1.Minimum = 0; // Reset Min

            // Standardizes the maximum boundary completion metric for visual tracking
            progressBar1.Maximum = 100; // Set Max

            // Clears the ongoing execution status indicator within the control
            progressBar1.Value = 0; // Clear Value

            // Forces the dynamic entropy harvesting engine into an inactive state
            _isCollecting = false; // Reset State

            // Applies the corporate baseline foreground color to the user input label
            labKeyboardInput.ForeColor = Color.RoyalBlue; // Apply Color

            // Encapsulates the textual area within the structural container layout bounds
            labKeyboardInput.MaximumSize = new Size(panel1.Width, 0); // Label Bounds

            // Instructs the containing layout element to automatically handle content overflow
            panel1.AutoScroll = true; // Auto Scroll

            // Hard-locks the container against involuntary layout horizontal scrolling behavior
            panel1.HorizontalScroll.Enabled = false; // Disable Horizontal

            // Restricts the application rendering loop from drawing the horizontal scrollbar
            panel1.HorizontalScroll.Visible = false; // Hide Horizontal

            // Resets the baseline calculation offset for horizontal orientation containment
            panel1.HorizontalScroll.Maximum = 0; // Clear Offset

            // Requests automatic resizing behavior to adjust to fluid runtime string contents
            labKeyboardInput.AutoSize = true; // Fluid Label

            // Enforces strict horizontal restriction relative to parent component internal boundaries
            labKeyboardInput.MaximumSize = new Size(panel1.ClientSize.Width, 0); // Max Width

            // Pinions the typography presentation component firmly to the container top margin
            labKeyboardInput.Dock = DockStyle.Top; // Dock Top

            // Commences the registration sequence for standard system entropy collection mechanisms
            EntropyConnect(); // Seeding Connect

            // Configures the form window context to capture hardware strokes before controls
            this.KeyPreview = true; // Allows the form to intercept key presses

            // Activates the custom keyboard filtering driver to suppress illegal space sequences
            SpaceKeyBlocker.Enable(this); // Intercept Space

            // Initializes the environment by safely detaching any active anti-capture overlays
            SpeedcryptGhost.Disable(this); // Reset Ghost

            // Evaluates persistence records to determine active display privacy policy settings
            string valgh = _xmlConfig.GetValue("Result.ObfuscatePrintScreen"); // Get Policy

            // Conditionally enforces volatile memory display protection upon positive policy matching
            if (valgh == "True") SpeedcryptGhost.Enable(this); // Enforce Obfuscation

            #endregion Initialization
        }

        #endregion Form Routines

        #region Events Handler
        private void BtnStart_Click(object sender, EventArgs e)
        {
            
            if (!_isCollecting)
            {
                StartCollection();
                SpaceKeyBlocker.Disable(this);
            }
            else
            {
                StopCollection();
                SpaceKeyBlocker.Enable(this);

            }
        }
        private void BtnResetEntropy_Click(object sender, EventArgs e)
        {
            try
            {
                // Stop collecting if active
                if (_isCollecting)
                {
                    _isCollecting = false;
                    UnsubscribeInput();
                }

                // Clear pool and any previously stored final entropy
                _pool.Reset();
                WipeCollectedEntropy();

                // Reset UI
                progressBar1.Value = 0;
                labKeyboardInput.Text = string.Empty;

                // Button states: disable Reset, enable Start for a fresh collection
                btnReset.Enabled = false;
                
                btnStart.Enabled = true;
                btnStart.Text = "&Start...";
            }
            catch (Exception ex)
            {
                // keep silent, no crash in UI 
                CentralLog.LogException(ex, "ADDITIONAL ENTROPY", "Handled exceptions during Reset UI! " + ex.Message);
            }
        }
        private void BtnCanc_Click(object sender, EventArgs e)
        {
            WipeCollectedEntropy();
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }
        private void FrmEntropy_FormClosing(object sender, FormClosingEventArgs e)
        {
            try
            {
                // Stop collection if it's still active and unsubscribe input events
                if (_isCollecting)
                {
                    _isCollecting = false;
                    UnsubscribeInput();
                }

                // Ensure the final entropy is available if not already collected
                if (CollectedEntropy == null)
                {
                    try { CollectedEntropy = _pool.GetFinalEntropy(); }
                    catch { CollectedEntropy = null; }
                }
                SaveComboBoxSetting("Result.PSWEntropyValueCollect", cmbEntropyValue);
            }
            finally
            {
                // Save configuration
                AppConfigHelper.Save();

                // Dispose pool in a safe, idempotent way
                DisposePoolSafely();
            }
        }
        private void CmbEntropyValue_SelectedIndexChanged(object sender, EventArgs e)
        {
            EntropyConnect();
        }
        private void Pool_BitsCollectedChanged(int bits)
        {
            // Evaluates whether the current execution thread is distinct from the UI thread context
            if (this.InvokeRequired) // Thread Check
            {
                // Marshals the method execution asynchronously back onto the main user interface thread
                BeginInvoke(new Action<int>(Pool_BitsCollectedChanged), bits); // Marshal Thread

                // Terminates the current background execution path safely after dispatching the delegate
                return; // Exit Thread
            }

            // Normalizes the raw collected entropy bit count into a standard percentage boundary
            int pct = Math.Min(100, bits * 100 / _pool.MaxEntropyBits); // Compute Percentage

            // Encapsulates the progress update procedure within a safe fault-tolerant structural block
            try
            {
                // Synchronizes the calculated percentage metric directly to the visual tracking component
                progressBar1.Value = pct;
            }
            // Suppresses runtime control exceptions to prevent unhandled interface thread failure sequences
            catch { } // Suppress Exceptions
        }
        private void Pool_CompletedUpdate()
        {
            if (this.InvokeRequired)
            {
                BeginInvoke(new Action(Pool_CompletedUpdate));
                return;
            }

            try
            {
                // Disable Start (collection finished) and enable Reset for a fresh run
                btnStart.Enabled = false;
                btnReset.Enabled = true;
                cmbEntropyValue.Enabled = true;
                // Stop collection immediately
                _isCollecting = false;
                UnsubscribeInput(); // remove mouse and keyboard handlers
                picPsw.Cursor = Cursors.Default;
                SpaceKeyBlocker.Enable(this);
            }
            catch { }
        }
        void EntropyConnect()
        {
            // Enforce InvariantCulture to extract the maximum entropy threshold safely from the UI selection
            int newMax = int.Parse(cmbEntropyValue.SelectedItem.ToString(), System.Globalization.CultureInfo.InvariantCulture);

            if (_pool == null) return;

            //long scaledBits = (long)_pool.BitsCollected * newMax / _pool.MaxEntropyBits;
            long scaledBits = ((long)_pool.BitsCollected * (long)newMax) / _pool.MaxEntropyBits;

            _pool.MaxEntropyBits = newMax;
            _pool.SetBitsCollected((int)scaledBits);
        }
        private void StartCollection()
        {
            // Evaluates whether the entropy harvesting cycle is currently inactive
            if (!_isCollecting) // State Verification
            {
                // Checks if the tracking component sits at its baseline position
                if (progressBar1.Value == 0) // Check Baseline
                                             // Purges the existing entropy buffer to initialize a clean collection run
                    _pool.Reset(); // Clear Buffer

                // Toggles the atomic tracking flag to indicate an active harvesting process
                _isCollecting = true; // Lock State

                // Dynamically updates the control text to reflect the suspend capability
                btnStart.Text = "Pause"; // UI Text

                // Adjusts the tracking area pointer to guide user input interaction
                picPsw.Cursor = Cursors.Cross; // Update Cursor

                // Disables selection parameter alterations during active data ingestion
                cmbEntropyValue.Enabled = false; // Freeze Configuration

                // Binds the localized hardware pointer tracking handler to the surface
                picPsw.MouseMove += PicPsw_MouseMove; // Hook Mouse

                // Suspends standard filtering mechanisms to permit raw sequence monitoring
                SpaceKeyBlocker.Disable(this); // Release Blocker

                // Registers the hardware key interception handler to capture raw parameters
                labKeyboardInput.KeyDown += LabKeyboardInput_KeyDown; // Hook Keyboard

                // Attempts to divert operational focus to the targeted monitoring component
                try { labKeyboardInput.Focus(); } catch { } // Force Focus
            }
        }
        private void StopCollection()
        {
            // Default Cursor
            picPsw.Cursor = Cursors.Default; 

            // Halts operations immediately if the collection loop is already inactive
            if (!_isCollecting) return; // Guard Clause

            // Updates the central operational flag to signify a stopped state machine
            _isCollecting = false; // Unlock State

            // Detaches active input hardware interceptors to cease data collection
            UnsubscribeInput(); // Clear Hooks

            // Restores the primary execution trigger label to its baseline designation
            btnStart.Text = "Start"; // Reset UI

            // Unlocks configuration selection components for operational parameter tuning
            cmbEntropyValue.Enabled = true; // Unfreeze Configuration

            // Encapsulates the sensitive extraction sequence in a fault-tolerant block
            try
            {
                // Extracts the final normalized cryptographic hash array from the pool
                CollectedEntropy = _pool.GetFinalEntropy(); // Extract Seed
            }
            // Handles runtime extraction failures gracefully to ensure stability
            catch
            {
                // Enforces a deterministic safe null assignment upon extraction failure
                CollectedEntropy = null; // Fault Assignment
            }
        }
        private void UnsubscribeInput()
        {
            // Attempts to safely detach the pointing device motion event tracking handler
            try { picPsw.MouseMove -= PicPsw_MouseMove; } catch { } // Unhook Mouse

            // Attempts to safely detach the physical hardware keystroke event interceptor
            try { labKeyboardInput.KeyDown -= LabKeyboardInput_KeyDown; } catch { } // Unhook Keyboard
        }
        private void PicPsw_MouseMove(object sender, MouseEventArgs e)
        {
            // Aborts operational processing immediately if the harvesting sequence is inactive
            if (!_isCollecting) return; // Guard Clause

            // Feeds raw peripheral pointer spatial coordinates directly into the core buffer
            _pool.AddMouseMove(e.X, e.Y); // Ingest Coordinates
        }

        // TECHNICAL SPECIFICATION: Unified Entropy Symbol Space Mapping Matrix
        // Provides a deterministic, immutable char array containing specialized operational glyphs, 
        // advanced mathematical operators, scientific constants, and alphanumeric subsets.
        // This static lookup pool is designed to drive high-entropy visual obfuscation cycles 
        // and secure data character mapping loops within the SpeedCrypt interface subsystem.
        private readonly char[] _entropySymbols = new char[]
        {
            '*','·','•','∎','⌘','↵','⎋','⎀','⌫','ƒ','≈','≡','∞','≠','∑','√','∆','Ω','π','µ','§','@','#','$','%','&','+',
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9'
        };
        private void LabKeyboardInput_KeyDown(object sender, KeyEventArgs e)
        {
            // Aborts processing immediately if the entropy harvesting sequence is inactive
            if (!_isCollecting) return; // Guard Clause

            // Block the actual key from being inserted
            e.SuppressKeyPress = true; // Suppress Hardware Stroke

            // Add key press to entropy pool
            _pool.AddKeyPress((int)e.KeyCode, '\0'); // Ingest Key Parameters

            // Generate 1-3 symbols for key using a single secure RNG
            byte[] buf = new byte[4]; // Allocation Buffer

            // Instantiates the isolated cryptographically secure pseudo-random number generator context
            using (var rng = RandomNumberGenerator.Create()) // Secure RNG Scope
            {
                // populates the data buffer with cryptographically strong residual random bytes
                rng.GetBytes(buf); // Poll Random Bytes

                // Dynamically computes an unpredictable symbol multiplier bound between 1 and 3
                int symbolCount = 1 + (buf[0] % 3); // Calculate Count

                // Instantiates a mutable string builder for fast concatenations without memory churn
                var sb = new System.Text.StringBuilder(); // Init Builder

                // Caches the total capacity of the specialized cryptographic symbol mapping dictionary
                int len = _entropySymbols.Length; // Cache Matrix Length

                // Calculates the mathematical remainder to discard biased high-end distribution values
                int rem = 256 % len; // Compute Remainder

                // Commences the deterministic processing loop for the selected random symbol quota
                for (int i = 0; i < symbolCount; i++) // Injection Loop
                {
                    byte b; // Value Declaration

                    // Executes a rejection-sampling loop to enforce true mathematical uniform distribution
                    do // Uniform Sampling
                    {
                        // Overwrites the validation buffer with fresh high-entropy random sequence data
                        rng.GetBytes(buf); // Refresh Buffer

                        // Extracts the baseline comparison byte value from the primary array index
                        b = buf[0]; // Extract State
                    }
                    // Discards elements exceeding the maximum unbiased mathematical interval threshold
                    while (b >= 256 - rem); // Uniform distribution for visual symbols

                    // Pulls the unbiased indexed character directly out of the mapped glyph matrix
                    sb.Append(_entropySymbols[b % len]); // Append Obfuscated Symbol
                }

                // Append the newly generated visual sequence to the interface label
                labKeyboardInput.Text += sb.ToString(); // Commit Sequence UI
            }

            // Keep caret at end
            labKeyboardInput.Refresh(); // Direct Paint Refresh

            // Forces the vertical offset positioning mechanics to follow the latest text bounds
            panel1.VerticalScroll.Value = panel1.VerticalScroll.Maximum; // Bottom Alignment

            // Re-evaluates container layout constraints to adapt dynamically to the modified dimensions
            panel1.PerformLayout(); // Force UI Layout Update
        }
        void SaveComboBoxSetting(string key, ComboBox comboBox)
        {
            if (comboBox.SelectedItem != null)
            {
                AppConfigHelper.XmlConfig.SetValue(key, comboBox.SelectedItem.ToString());
            }
        }
        public void WipeCollectedEntropy()
        {
            // Aborts the operation immediately if the raw cryptographic seed reference is unallocated
            if (CollectedEntropy == null) return; // Guard Clause

            // Executes a deterministic overwrite loop across every allocated index of the byte buffer
            for (int i = 0; i < CollectedEntropy.Length; i++) CollectedEntropy[i] = 0; // Secure Overwrite

            // Enforces an immediate null reference redirection to clear memory pointers after destruction
            CollectedEntropy = null; // Clear Reference
        }
        void DisposePoolSafely()
        {
            try
            {
                if (_pool != null)
                {
                    // Unsubscribe events to avoid callbacks during/after dispose
                    try { _pool.BitsCollectedChanged -= Pool_BitsCollectedChanged; } catch { }
                    try { _pool.Completed -= Pool_CompletedUpdate; } catch { }

                    // Ensure input handlers are released
                    try { UnsubscribeInput(); } catch { }

                    // Dispose and nullify (idempotent)
                    try { _pool.Dispose(); } catch { }
                    _pool = null;
                }
            }
            catch (Exception ex)
            {
                // Silent catch - prevent UI crash
                CentralLog.LogException(ex, "ADDITIONAL ENTROPY", "Handled exceptions during prevent UI crash! " + ex.Message);
            }
        }
 
        #endregion Events Handler
    }
}