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
using System.Diagnostics;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.SALT;
using Speedcrypt.Crypto;
using Speedcrypt.Combload;
using Speedcrypt.XMLConfig;
using Speedcrypt.Crypto.PGP;
using Speedcrypt.Securerase;
using Speedcrypt.Interfaces;
using Speedcrypt.Exceptionlog;
using Speedcrypt.Digests.Blake;
using Speedcrypt.HASHLibraries;
using Speedcrypt.Digests.Bcrypt;
using Speedcrypt.Securerase.NSACSS9;
using Speedcrypt.Securerase.NSACSS12;
using Speedcrypt.Secureerase.Overwrite;
using Speedcrypt.Securerase.NIST800_88;
using Speedcrypt.Securerase.CustomPasses;
using Speedcrypt.Securerase.BritishHMGIS5;
using Speedcrypt.Securerase.RCMPTSSITOPSII;

using Org.BouncyCastle.Security;

namespace Speedcrypt
{
    public partial class FrmSettings : Form
    {
        #region Cryptographic Fields

        // Reference to the main application form (used for cross-form communication)
        private readonly FrmMain mainForm;

        // Manages all PGP-related folder operations and path handling
        readonly PGPFoldersManager foldersManager = new PGPFoldersManager();

        // Singleton-style instance of the settings form to prevent multiple instances
        public static FrmSettings Instance { get; private set; }

        // Centralized tooltip manager responsible for UI contextual hints
        private ToolTipManager _tt;

        // Handles alternating row colors for ListView controls to improve readability
        private ListViewRowAlternator _alternator;

        // Performs validation and evaluation of the Custom Erase Algorithm
        // (used for secure file wiping configuration checks)
        private CustomPassEvaluator evaluator;

        // Manages secure XML configuration storage with restricted access
        private PrivateXmlConfig _xmlConfig;

        // Controls the linear positioning logic of the key arrow indicator
        private KeyarrowManager _keyarrowManager;

        // Tracks configuration changes and enables/disables the Save button accordingly
        private DirtyTracker _dirtyTracker;

        // Temporary SALT value used exclusively for cryptographic testing operations
        private string _SALT_TEST = string.Empty,

                       // Resulting hash after combining SALT with the user key
                       // and processing it through the selected hash algorithm
                       _HASH_TEST = string.Empty,

                       // Current process mode: "Encrypt" or "Decrypt"
                       _ENC_DEC = "Encrypt",

                       // Formatted file size in megabytes (MB), used for benchmark reporting
                       _MB_SIZE = string.Empty;

        /// <summary>
        /// Execution safety latch flag. Prevents cascading UI synchronization messages 
        /// and unexpected focus validation loops during active list clearance routines.
        /// </summary>
        private bool _isClearingList = false;


        // Process state indicator:
        // 0 = Encrypt
        // 1 = Decrypt
        // 2 = Secure file deletion

        #endregion Cryptographic Fields

        #region Constructor
        public FrmSettings(Form callingForm)
        {
            InitializeComponent(); // Initializes all UI components and controls
            mainForm = callingForm as FrmMain; // Cast and store reference to the main application form
            Loadall();// Loads application configuration and initializes runtime state
        }

        #endregion Constructor

        #region Form Routines
        void Loadall()
        {
            #region Form Components

            // Initialize tooltip manager
            _tt = new ToolTipManager();

            // Shared OpenFileDialog instance used across application units
            ForAllUnits.openFileDialog1 = new OpenFileDialog();

            // Configure main form appearance and behavior
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application;
            MaximizeBox = false;
            MinimizeBox = false;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            Text = "Speedcrypt Settings...";

            // Header images configuration
            picGrad.Image = ForAllUnits.Gradientform;
            picGrad.BackgroundImageLayout = ImageLayout.Stretch;

            picSimb.Image = ForAllUnits.Settings32;
            picSimb.Parent = picGrad;
            picSimb.BackColor = Color.Transparent;

            // Header labels styling
            labYel.BackColor = Color.Yellow;

            labFir.Text = Text;
            labFir.Parent = picGrad;
            labFir.BackColor = Color.Transparent;
            labFir.ForeColor = Color.White;
            labFir.Font = new Font(labFir.Font.FontFamily, 10, FontStyle.Bold);

            labSec.Text = "Basic Speedcrypt Function Settings";
            labSec.Parent = picGrad;
            labSec.BackColor = Color.Transparent;
            labSec.ForeColor = Color.White;
            labSec.Font = new Font(labSec.Font.FontFamily, 10);

            // TabCopntrol
            tabControl1.ImageList = imageList2;

            // ImageList 2 (small status and action icons)
            Image[] images2 =
                            {
                               ForAllUnits.Encrypted22,
                               ForAllUnits.Decrypted22,
                               ForAllUnits.Timer22,
                               ForAllUnits.Trash22,
                               ForAllUnits.Math22,
                               ForAllUnits.Benck22,
                               ForAllUnits.List22,
                               ForAllUnits.Hdd22
                            };

            foreach (var img in images2)
                imageList2.Images.Add(img);

            #endregion Form Components

            #region Timer Panel

            // Timer icon and formatted time display (mm.ss.mmm)
            picTimer.Image = ForAllUnits.Timer22;
            labTime.Text = "00:00:00.000";
            picTimer.Visible = false;
            labTime.Visible = picTimer.Visible;

            #endregion Timer Panel

            #region Benchmark Proposal

            // Benchmark tab configuration
            tabBmk1.Text = "Benchmark Proposal...";
            tabBmk1.ImageIndex = 5;

            // Group: File size generation for benchmark tests
            grbFilesize.Text = "Generate your Files for Encryption and Deletion Benchmarking...";
            grbFilesize.ForeColor = Color.Brown;
            picTest.Image = ForAllUnits.Connectcreating16;
            picOpen.Image = ForAllUnits.Foldercyanopen16;

            // Defines custom file size (in MB) for benchmark file generation
            labVal.Text = "[1 > 2000]";
            labVal.ForeColor = Color.Red;
            labCustsize.Text = "●  Select the size of your files.\r\n\r\n" +
                               "●  You can customize the size of your files\r\n";
            numCustomSize.Cursor = Cursors.Hand;
            _tt.Set(numCustomSize, "Enter a value between 1 and 2000 MB for file generation");
            numCustomSize.Minimum = 1;
            numCustomSize.Maximum = 2000;

            // Group: Immediate benchmark test (enabled after valid configuration)
            grbTestnow.Text = "Immediate Test with...";
            grbTestnow.ForeColor = Color.Brown;
            grbTestnow.Enabled = false;
            picImmediate.Image = ForAllUnits.Connect48;

            // Benchmark action icons
            picEnc.Image = ForAllUnits.Encrypted16;
            picDel.Image = ForAllUnits.Trash16;

            // Informational notes section
            picNote.Image = ForAllUnits.Notes22;
            labNotes.Text = "Notes...";
            labNotes.Font = labSec.Font;
            labNotes.ForeColor = labVal.ForeColor;

            // Recommended algorithms section
            labSysdrive.Text = "In your System Speedcrypt recommends the following Algorithms:";
            labSysdrive.ForeColor = Color.Brown;

            // Displays recommended encryption and wiping algorithms based on system analysis
            listAdvise.View = View.Details;
            listAdvise.SmallImageList = imageList2;

            // Driver List
            listAdvise.BeginUpdate();
            listAdvise.Columns.Add("DR", 28, HorizontalAlignment.Center);
            listAdvise.Columns.Add("DRIVE ANALYSIS", 435, HorizontalAlignment.Left);
            listAdvise.EndUpdate();

            listAdvise.Font = new Font("Courier New", 9.25F, FontStyle.Bold);
            listAdvise.TabStop = false;

            labSet.Text = "●  Creation of Files for Encryption and File Deletion Benchmarking\r\n\r\n" +
                          "●  Analyzing drives and assigning encryption and wiping algorithms\r\n\r\n" +
                          "●  System-level configuration of Argon2 and Scrypt algorithm parameters.\r\n\r\n" +
                          "●  You can create a list of benchmarks and export it in txt format\r\n\r\n" +
                          "●  The password is not strengthened with a SALT; it is for demonstration only\r\n\r\n" +
                          "●  Fixed password derived with BLAKE-256 for file encryption and decryption\r\n";

            #endregion Benchmark Proposal

            #region Encrypt Engines

            // Configure Benchmark Tab 2 for Encryption Settings
            tabBmk2.Text = "Encryption Settings...";
            tabBmk2.BackColor = tabBmk1.BackColor;
            tabBmk2.ImageIndex = 0;

            // Encryption Engine Selection
            labEnc.Text = "Select Encryption Engine:";
            labEnc.ForeColor = Color.Brown;
            cmbCrypteng.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbCrypteng.Items.AddRange(new object[]
            {
                "AES", "PGP", "IDEA", "GOST", "AES-GCM",
                "SERPENT", "TWOFISH", "CAMELLIA", "THREEFISH",
                "KUZNYECHIK", "XCHACHA20-POLY1305"
            });
            cmbCrypteng.SelectedIndex = 0;
            labNumenc.Text = cmbCrypteng.Items.Count.ToString();
            labNumenc.ForeColor = Color.Red;

            // Encryption String Settings
            labStrcrp.Text = "Encryption String:";
            labStrcrp.ForeColor = Color.Brown;

            labPbkdf2round.Text = "PBKF2 Rounds:";
            labPbkdf2round.ForeColor = Color.Brown;

            cmbStringcrypto.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbStringcrypto.Items.AddRange(new object[]
            {
                "AES-GCM", "SERPENT", "TWOFISH",
                "THREEFISH", "XCHACHA20", "XCHACHA20POLY1305",
                "AES"
            });
            cmbStringcrypto.SelectedIndex = 3;
            labNumstrenc.Text = cmbStringcrypto.Items.Count.ToString();
            labNumstrenc.ForeColor = Color.Red;

            // PBKDF2 iteration rounds for key derivation
            txtPbkdf2round.Text = "100000";
            picRound.Image = ForAllUnits.Round22;

            // PGP Settings Group
            grbPgp.ForeColor = Color.Brown;
            grbPgp.Text = "PGP Settings...";
            grbPgp.Enabled = false;

            labUnit.Text = "Select Unit:";
            cmbDrives.DropDownStyle = ComboBoxStyle.DropDownList;
            chkHidden.Checked = false;

            labFoldpath.Text = "PGP Folder Path";
            picConf.Image = ForAllUnits.Power48;

            // Generated Files ListView
            labFoldgen.Text = "Generated Files [Double click to insert a File]:";
            labFoldgen.ForeColor = Color.Gray;

            listFileload.View = View.LargeIcon;
            listFileload.LargeImageList = imageList3;
            listFileload.BackColor = listAdvise.BackColor;
            listFileload.Enabled = false;

            // Key Size Settings for each encryption algorithm
            grbKeysize.ForeColor = Color.Brown;
            grbKeysize.Text = "Select Key Size...";

            labAeskey.Text = "AES [Advanced Encryption Standard] [128 Bit - Block Cipher]:";
            labRsakey.Text = "PGP [RSA DOUBLE KEYS] [RSA Key Size]:";
            labIdeakey.Text = "IDEA [64 Bit - Block Cipher]:";
            labIdea.Text = "K128";
            labGostkey.Text = "GOST [64 Bit - Block Cipher]:";
            labGost.Text = "K256";
            labAesgcmkey.Text = "AES-GCM [128 Bit - Block Cipher]:";
            labAesgcm.Text = "K256";
            labSerpentkey.Text = "SERPENT [128 Bit - Block Cipher]:";
            labTwofishkey.Text = "TWOFISH [128 Bit - Block Cipher]:";
            labCamelliakey.Text = "CAMELLIA [128 Bit - Block Cipher]:";
            labThreefishkey.Text = "THREEFISH [256-512-1024 Bit - Block Cipher]:";
            labKuznyechikkey.Text = "KUZNYECHIK [128 Bit - Block Cipher]:";
            labKuznyechik.Text = "K256";
            labXchacha20key.Text = "XCHACHA20POLY1305 [512 Bit - Block Cipher]:";
            labXchacha20.Text = "K256";

            picKeisize.Image = ForAllUnits.Buttonup16;

            // Load Key Size Enum Values into ComboBoxes
            cmbAeskeysize.DropDownStyle = ComboBoxStyle.DropDownList;
            Comboadd.LoadEnumValues(cmbAeskeysize, typeof(AESKeysize));

            cmbRsaKeysize.DropDownStyle = ComboBoxStyle.DropDownList;
            Comboadd.LoadEnumValues(cmbRsaKeysize, typeof(RSAKeysize));
            cmbRsaKeysize.SelectedIndex = 1;

            cmbSepentkeysize.DropDownStyle = ComboBoxStyle.DropDownList;
            Comboadd.LoadEnumValues(cmbSepentkeysize, typeof(Serpentkeysize));

            cmbTwofishkeysize.DropDownStyle = ComboBoxStyle.DropDownList;
            Comboadd.LoadEnumValues(cmbTwofishkeysize, typeof(Twofishkeysize));

            cmbCamelliakeysize.DropDownStyle = ComboBoxStyle.DropDownList;
            Comboadd.LoadEnumValues(cmbCamelliakeysize, typeof(Camelliakeysize));

            cmbThreefishkeysize.DropDownStyle = ComboBoxStyle.DropDownList;
            Comboadd.LoadEnumValues(cmbThreefishkeysize, typeof(Threefishkeysize));

            // Benchmark Profile Section
            grbprofile.Text = "Benchmark Profile...";
            grbprofile.ForeColor = Color.Brown;

            labFilepath.Text = "File Path:";
            grbPassw.Text = "Password:";
            grbPassw.ForeColor = Color.Brown;
            labMb.ForeColor = Color.Navy;
            labPassword.ForeColor = Color.Navy;

            txtFilepath.ContextMenuStrip = bContextMenuStrip1;

            #endregion Encrypt Engines

            #region HASH Engines

            // Configure Benchmark Tab 3 for HASH Settings
            tabBmk3.ImageIndex = 4;
            tabBmk3.BackColor = tabBmk1.BackColor;
            tabBmk3.Text = "HASH Settings...";

            labHash.Text = "Select HASH Engine:";
            labHash.ForeColor = Color.Brown;

            cmbHash.Items.AddRange(new object[]
            {
                "BCRYPT", "SCRYPT", "MD5", "ARGON2i", "ARGON2d",
                "ARGON2id", "SHA-224", "SHA-256", "SHA-384",
                "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512",
                "BLAKE-256", "BLAKE-512", "BLAKE2b", "BLAKE2s",
                "BLAKE3-256", "BLAKE3-384", "BLAKE3-512",
                "BLAKE3-1024", "RIPEMD-128", "RIPEMD-160",
                "RIPEMD-256", "RIPEMD-320", "WHIRLPOOL",
                "SHAKE-128", "SHAKE-256", "TIGER-128,3",
                "TIGER-160,3", "TIGER-192,3",
                "GOST R 34.11-94 Standard of Russian Federation",
                "STREEBOG-256 R 34.11-2012 Russian Federation",
                "STREEBOG-512 R 34.11-2012 Russian Federation",
                "KECCAK-224", "KECCAK-256", "KECCAK-384",
                "KECCAK-512", "SKEIN-256", "SKEIN-512",
                "SKEIN-1024", "HMACSHA1", "HMACMD5",
                "HMACSHA-256", "HMACSHA-384", "HMACSHA-512",
                "HMACRIPEMD-160", "PBKDF2-HASH",
                "SM3 Standard of China Republic"
            });
            cmbHash.SelectedIndex = 0;
            cmbHash.DropDownStyle = cmbCrypteng.DropDownStyle;
            labNumhash.Text = cmbHash.Items.Count.ToString();
            labNumhash.ForeColor = Color.Red;

            // HASH Output Configuration
            grbOutput.ForeColor = grbPgp.ForeColor;
            grbOutput.Text = "HASH Encoding...";

            // SALT Output Configuration
            grbOutputsalt.ForeColor = grbPgp.ForeColor;
            grbOutputsalt.Text = "SALT Encoding...";

            // SALT Generator Selection
            labSalt.Text = "Select SALT Generator:";
            labSalt.ForeColor = Color.Brown;

            cmbSalt.Items.AddRange(new object[]
            {
               "BCRYPT", "FORTUNA", "AES-CTR DRBG",
               "CRYPTO-RANDOM", "BLUM-BLUM-SHUB[BBS]"
            });
            cmbSalt.DropDownStyle = cmbHash.DropDownStyle;
            cmbSalt.SelectedIndex = 0;
            cmbSalt.Enabled = false;
            labNumsalt.Text = cmbSalt.Items.Count.ToString();
            labNumsalt.ForeColor = Color.Red;

            // Number / Bit Sequence Generation
            grbGen.ForeColor = grbPgp.ForeColor;
            grbGen.Text = "Generating...";
            grbGen.Enabled = false;

            // Internal Functions 
            labHashsalt.Text = "Internal Functions:";
            txtInternal.Text = "BLAKE-256";
            txtInternal.ReadOnly = true;

            // String Value Type Selection
            grbString.ForeColor = grbPgp.ForeColor;
            grbString.Text = "Select the String Value type...";

            // SALT Test Section
            txtSalt.ReadOnly = true;
            labInsert.Text = "Enter String Value:";
            labSaltest.Text = "Salt Test:";
            picHkdf.Image = ForAllUnits.Ledred22;

            // Test Image
            picHash.Image = ForAllUnits.Cpu48;

            // HASH Output Block Configuration
            grbHashout.ForeColor = grbPgp.ForeColor;
            grbHashout.Text = "HASH Output...";
            numIndent.Minimum = 8;
            numIndent.Maximum = 16;
            numIndent.Value = 8;
            numIndent.ReadOnly = true;

            numTextblock.Minimum = 1;
            numTextblock.Maximum = 12;
            numTextblock.Value = 5;
            numTextblock.ReadOnly = numIndent.ReadOnly;

            labTxtblock.Text = "Text Block Number:";
            LabBase.Text = "Select Characters Number:";

            // Argon2 Algorithm Settings
            grbArgon.ForeColor = grbPgp.ForeColor;
            grbArgon.Text = "Argon2 Settings...";
            labArgms.Text = "Memory Size:";
            labArgpr.Text = "Parallelism:";
            labArgit.Text = "Iterations:";
            labArghs.Text = "HASH Size:";

            txtArgMem.Text = "65536";
            txtArgParal.Text = "4";
            txtArgIter.Text = "3";

            cmbArgsize.DropDownStyle = cmbHash.DropDownStyle;
            Comboadd.LoadEnumValues(cmbArgsize, typeof(Argonsize));
            cmbArgsize.SelectedIndex = 3;

            // Scrypt Algorithm Settings
            grbScrypt.ForeColor = grbPgp.ForeColor;
            grbScrypt.Text = "Scrypt Settings...";

            labScms.Text = labArgms.Text;
            labScpr.Text = "Parallelization:";
            labScbs.Text = "Block Size:";
            labSchs.Text = labArghs.Text;

            txtScrMem.Text = "16384";
            txtScrParal.Text = "1";
            txtScrBksz.Text = "8";

            cmbScrypsize.DropDownStyle = cmbHash.DropDownStyle;
            Comboadd.LoadEnumValues(cmbScrypsize, typeof(Argonsize));
            cmbScrypsize.SelectedIndex = 3;

            // BCrypt / PBKDF2 Settings
            grbStrec.ForeColor = grbPgp.ForeColor;
            grbStrec.Text = "BCrypt / PBKF2...";
            picKey.Image = ForAllUnits.Keystretc32;
            picBic.Image = ForAllUnits.Ledred16;
            picPbk.Image = picBic.Image;

            labKey.Text = "Key \r\nStretching\r\n";
            labBcrd.Text = "BCrypt Rounds:";
            labPbk.Text = "PBKDF2 Rounds:";

            txtPbkIter.Text = "100000";

            cmbBcrRound.DropDownStyle = cmbHash.DropDownStyle;
            Comboadd.LoadEnumValues(cmbBcrRound, typeof(Bcryptround));
            cmbBcrRound.SelectedIndex = 2;

            // String Length Settings
            grbStringlength.ForeColor = grbPgp.ForeColor;
            grbStringlength.Text = "String Length:";
            grbStringlength.TabStop = false;

            picLength.Image = ForAllUnits.Pakageutil32;

            labKeylen.Text = "Key:";
            labSaltlen.Text = "SALT:";
            labKeysaltlen.Text = "Key + SALT:";
            labHashlen.Text = "HASH Result:";

            labKeystr.Text = "0";
            labKeystr.ForeColor = Color.Red;

            labSaltstr.Text = labKeystr.Text;
            labSaltstr.ForeColor = labKeystr.ForeColor;

            labKeysaltstr.Text = labKeystr.Text;
            labKeysaltstr.ForeColor = labKeystr.ForeColor;

            labHashstr.Text = labKeystr.Text;
            labHashstr.ForeColor = labKeystr.ForeColor;

            // KDF Based
            grbKdf.Text = "HKDF/HMAC";
            grbKdf.ForeColor = Color.Brown;
            grbKdf.Cursor = Cursors.Cross;
            labKdf.Text = "KDF Based";
            labKdf.ForeColor = Color.Navy;

            // HASH Result Display
            labResult.Text = "HASH Result:";
            labResult.ForeColor = Color.Brown;

            rchHashresult.BackColor = listAdvise.BackColor;
            rchHashresult.Font = new Font("Consolas", 9);
            rchHashresult.TabStop = false;

            #endregion HASH Engines

            #region Secure Deletion

            tabBmk4.Text = "Secure Deletion...";
            tabBmk4.BackColor = tabBmk1.BackColor;
            tabBmk4.ImageIndex = 3;

            // Deletion Algorithms ComboBox
            labAlgodel.Text = "Select Deletion Engine:";
            cmbAlgodel.Items.AddRange(new object[]
            {
                "Quick 1 Pass", "Random 1 Pass", "DoD 3 Passes",
                "DoD 7 Passes", "Schneier 7 Passes", "German VSITR 7 Passes",
                "Gutmann 35 Passes", "RCMP TSSIT OPS-II",
                "British HMG IS5 [Enhanced]", "Custom Erase by Mariano Ortu [User Defined]",
                "NSA/CSS Standard 9", "NSA/CSS Standard 12",
                "Secure Delete", "NIST 800-88 Rev.1 Secure Erase"
            });
            cmbAlgodel.SelectedIndex = 13;
            cmbAlgodel.DropDownStyle = cmbStringcrypto.DropDownStyle; // Drop-down style matches string crypto ComboBox
            labNumdel.Text = cmbAlgodel.Items.Count.ToString();
            labNumdel.ForeColor = Color.Red;

            // Custom Erase Settings GroupBox
            grbAlgdel.Text = "Create your Custom Erase Algorithm [Max 8 Values]...";
            grbAlgdel.ForeColor = Color.Brown;
            grbSet.Text = "Manage Items List:";
            grbSet.ForeColor = Color.Brown;

            // Custom ComboBox for erase values
            cmbCustom.Items.AddRange(new object[]
            {
               "Zero (0x00)", "One (0xFF)", "Random",
            });
            cmbCustom.SelectedIndex = 0;
            cmbCustom.DropDownStyle = ComboBoxStyle.DropDownList;

            // ListView for custom erase sequence
            listCustom.BackColor = listAdvise.BackColor;
            listCustom.Items.Clear();
            labValue.ForeColor = Color.Blue;
            labValue.Text = "Score";

            // Informational label about recommended engines
            labCustom.Text = "●  Easy to use\r\n\r\n" +
                             "●  Extremely fast\r\n\r\n" +
                             "●  Easy to configure\r\n\r\n" +
                             "recommended with...\r\n\r\n" +
                             "●  AES\r\n\r\n" +
                             "●  AES-GCM\r\n\r\n" +
                             "●  SERPENT\r\n\r\n" +
                             "●  TWOFISH\r\n\r\n" +
                             "●  KUZNYECHIK\r\n";

            labDelfile.Text = "Delete File with...";

            picTrash.Image = ForAllUnits.Pakage48;

            // Algorithms Description GroupBox
            grbDesc.ForeColor = grbAlgdel.ForeColor;
            grbDesc.TabStop = false;

            // HDD Icon
            picHd.Image = ForAllUnits.Hdd32;

            // Algorithms Score Labels
            labHdtype.Text = "HD Type: ";
            labApx.Text = "Speed [+ -]:";
            labMan.Text = "Type:";
            labPse.Text = "Passes:";
            labPass.Text = "1";
            labFilerec.Text = "File Recoverability:";

            labHd.BackColor = listAdvise.BackColor;
            labHd.ForeColor = Color.Blue;
            labSpeed.BackColor = listAdvise.BackColor;
            labSpeed.ForeColor = labHd.ForeColor;
            labManual.BackColor = listAdvise.BackColor;
            labManual.ForeColor = labHd.ForeColor;
            labPass.BackColor = listAdvise.BackColor;
            labPass.ForeColor = labHd.ForeColor;

            // Benchmark Profile for Deletion
            grbProfiledel.Text = grbprofile.Text;
            grbProfiledel.ForeColor = grbprofile.ForeColor;
            grbFileKb.Text = "File Size:";
            grbFileKb.ForeColor = grbprofile.ForeColor;
            grbFilesizedel.Text = "File Size:";
            grbFilesizedel.ForeColor = Color.Brown;
            labKb.ForeColor = Color.Navy;
            labSelec.Text = "Select mode:";
            rdbGendel.Text = rdbGen.Text;
            labFilepathdel.Text = labFilepath.Text;

            // Generated Files ListView for Deletion
            labFoldgendel.Text = labFoldgen.Text;
            labFoldgendel.ForeColor = labFoldgen.ForeColor;
            listFileloaddel.View = listFileload.View;
            listFileloaddel.LargeImageList = listFileload.LargeImageList;
            listFileloaddel.BackColor = listFileload.BackColor;
            listFileloaddel.TabStop = false;
            listFileloaddel.Enabled = false;

            Custombut(false); // This instruction must remain here!!!

            #endregion Secure Deletion

            #region Benchmark List

            tabBmk5.Text = "Benchmark List...";
            tabBmk5.ImageIndex = 6;
            tabBmk5.BackColor = tabBmk1.BackColor;

            // Disable panel until ready
            pnlList.Enabled = false;

            // Import GroupBox
            grbImport.Text = "Import List...";
            grbImport.ForeColor = Color.Brown;

            // Filter Section
            grbFind.Text = "Find Values...";
            grbFind.ForeColor = Color.Brown;
            picFind.Image = ForAllUnits.Find48;
            labFind.Text = "Find Test by...";
            cmbFind.Items.AddRange(new object[]
            {
                "ALGORITHM", "PROCESS", "FILE SIZE", "TIME", "DATE TEST"
            });
            cmbFind.SelectedIndex = 0;
            cmbFind.DropDownStyle = cmbCrypteng.DropDownStyle;
            labFilter.Text = "0";
            labFilter.BackColor = Color.LightYellow;
            labFilter.ForeColor = Color.Red;

            // Test ListView
            listBmk.View = View.Details;
            listBmk.SmallImageList = imageList2;
            listBmk.BackColor = listAdvise.BackColor;
            listBmk.BeginUpdate();
            listBmk.Columns.Add("ID", 28, HorizontalAlignment.Center);
            listBmk.Columns.Add("ALGORITHM", 400, HorizontalAlignment.Left);
            listBmk.Columns.Add("PROCESS", 120, HorizontalAlignment.Left);
            listBmk.Columns.Add("FILE SIZE", 120, HorizontalAlignment.Left);
            listBmk.Columns.Add("TIME", 110, HorizontalAlignment.Left);
            listBmk.Columns.Add("DATE TEST", 105, HorizontalAlignment.Left);
            listBmk.EndUpdate();
            listBmk.FullRowSelect = true;
            listBmk.TabStop = true;

            #endregion Benchmark List

            #region Miscellaneous

            // ============================================================
            // Centralized UI Initialization Block
            // Purpose:
            // Provides a unified and maintainable initialization layer for
            // all interactive UI controls including Buttons, TextBoxes,
            // RadioButtons, CheckBoxes, ComboBoxes, and NumericUpDown.
            //
            // Design Goals:
            // - Ensure visual and behavioral consistency across the UI.
            // - Reduce duplicated initialization code.
            // - Improve maintainability and scalability.
            // - Centralize tooltip assignment and cursor behavior.
            // - Enable structured configuration using strongly typed tuples.
            //
            // This approach ensures that all UI elements follow a predictable
            // initialization pattern and can be extended safely.
            // ============================================================

            // ============================================================
            // BUTTON INITIALIZATION
            // Configures functional buttons used across multiple modules:
            //
            // Modules covered:
            // - PGP Key Management
            // - Encryption / Decryption Tests
            // - HASH Testing
            // - Secure Deletion
            // - Benchmark List Management
            //
            // Properties configured:
            // - Text label
            // - Tooltip description
            // - Icon image
            // - Enabled state
            // - Cursor behavior
            // - Visual alignment and padding
            //
            // This ensures uniform appearance and interaction model.
            // ============================================================

            var otherbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
                // PGP Settings
                (btnGenfile, "Generate", "Generate your files", ForAllUnits.Kpager32, true),
                (btnFoldernew, "New Folder", "Create a new folder to manage PGP keys", ForAllUnits.Newfolder32, false),
                (btnFolderpath, "Load Folder", "Select an existing folder to manage PGP keys", ForAllUnits.Loadfolder32, true),
                (btnGen, "Generate", "Generate the Keys for the PGP Test", ForAllUnits.Generatepassw32, false),
        
                // Encryption / Decryption Test 
                (btnLoad, "Add File...", "Select files to Encrypt or decrypt", ForAllUnits.Addfile32, true),
                (btnEncrypt, "Encrypt File", "Encrypt the selected file", ForAllUnits.Encrypted32, false),
                (btnDecrypt, "Decrypt File", "Decrypt the selected file", ForAllUnits.Decrypted32, false),
                (btnCleartest, "Clear All", "Clear all test data",ForAllUnits.Empty32, false),

                // Hash Settings
               (btnSaltTest, "Salt Test", "Start the SALT Test", ForAllUnits.Salt32, true),
               (btnStringval, "String Value", "Generate a random string for the Test", ForAllUnits.Write32, true),
               (btnHashTest, " Start Test", "Start the HASH test", ForAllUnits.Hash32, false),
               (btnCanc, "Clear All", "Clear all test data", ForAllUnits.Empty32, false),

               // Secure Deletion
               (btnRepeatval, "Repeat Value", "Repeat the value just entered", ForAllUnits.Reload32, false),
               (btnClearval, "Delete Value", "Delete the selected value from the list", ForAllUnits.Cancelitem32, false),
               (btnAlgodel, "Suggest...", "Ask Speedcrypt to suggest the best sequence", ForAllUnits.Suggest32, true),
               (btnSaveval, "Save List", "Save the values ​​in the list", ForAllUnits.Filesaveas32, false),
               (btnLoadval, "Load List", "Loads a list of previously saved values", ForAllUnits.Importfile32, true),
               (btnClearlistval, "Clear List", "Clear List Value and all test data", ForAllUnits.Empty32, false),
               (btnLoaddel, "Add File...", "Select files from the system", ForAllUnits.Addfile32, true),
               (btnDelete, "Delete File", "Delete the selected file. Warning: It will not be recoverable.", ForAllUnits.Trash32, false),

               // Benchmark List
               (btnImpList, "Import List", "Loads a Benchmarck List", ForAllUnits.Importfile32, true),
               (btnClearlist, "Clear List", "Clear the Benchmark List", ForAllUnits.Empty32, true),
               (btnDelitem, "Delete Item", "Delete the selected Items", ForAllUnits.Cancelitem32, false),
               (btnSave, "Save", "Save changes in the list", ForAllUnits.Filesave32, false),
               (btnExplist, "Export List", "Export the Bencmarch List", ForAllUnits.Filesaveas32, true),
            };

            // Defines bottom padding spacing between image and text
            int verticalSpacing = 5;

            // Applies standardized configuration to all buttons
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

            // ============================================================
            // SECONDARY BUTTON INITIALIZATION
            // Used for system-level and dialog control buttons.
            // ============================================================

            var allbutton = new (Button Button, string Text, string Tip, Image Icon, bool Enabled)[]
            {
               (btnDelFolder, "", "Delete the selected folder", ForAllUnits.Critical22, false),
               (btnOk, "Ok", "Close Speedcrypt Settings", ForAllUnits.Apply16, true),
               (btnHelp, "Help", "View Help Guide", ForAllUnits.Help16, true),
            };

            foreach (var optionbut in allbutton)
            {
                optionbut.Button.Text = optionbut.Text;
                _tt.Set(optionbut.Button, optionbut.Tip);
                optionbut.Button.Cursor = Cursors.Hand;
                optionbut.Button.Image = optionbut.Icon;
                optionbut.Button.Enabled = optionbut.Enabled;
            }

            // ============================================================
            // TEXTBOX INITIALIZATION
            // Assigns tooltips to guide user input and clarify parameter usage.
            // Ensures correct understanding of cryptographic parameters.
            // ============================================================

            var alltext = new (TextBox Box, string Tip)[]
            {
                (txtPbkdf2round, "Insert the appropriate PBKDF2 Round [Anti Brute Force Attack]"),
                (txtFilepath, "Insert or Copy and Paste the appropriate File Path"),
                (txtSalt, "Here you can see the SALT"),
                (txtHashInput, "Enter a Value of your choice"),
                (txtArgMem, "Argon2id: Please enter an appropriate Value"),
                (txtArgIter, "Argon2id: Please enter an appropriate Value"),
                (txtArgParal, "Argon2id: Please enter an appropriate Value"),
                (txtScrMem, "SCrypt: Please enter an appropriate Value"),
                (txtScrParal, "SCrypt: Please enter an appropriate Value"),
                (txtScrBksz, "SCrypt: Please enter an appropriate Value"),
                (txtPbkIter, "Insert the appropriate PBKDF2 Round [Anti Brute Force Attack]"),
                (txtFilepathdel, "Insert or Copy and Paste the appropriate File Path"),
                (txtProcname, "Enter an appropriate value for the filter"),
            };

            foreach (var (box, tip) in alltext)
            {
                _tt.Set(box, tip);
                box.Refresh(); // Ensures immediate visual update
            }

            // ============================================================
            // RADIOBUTTON INITIALIZATION
            // Defines selectable configuration options across modules.
            // Ensures consistent tooltip, cursor, and selection state.
            // ============================================================

            var allradiobut = new (RadioButton Button, string Text, string Tip, bool Cheched)[]
            {
                 // Benchmark Proposal
                (rdb1MB,    "1 MB",    "Set file size limit to 1 MB", true),
                (rdb10MB,   "10 MB",   "Set file size limit to 10 MB", false),
                (rdb100MB,  "100 MB",  "Set file size limit to 100 MB", false),
                (rdb500MB,  "500 MB",  "Set file size limit to 500 MB", false),
                (rdbCustom, "Custom", "Set a custom file size", false),
                (rdbEnc, "Encrypt the generated File", "Test encryption immediately for the generated file", true),
                (rdbDel, "Delete the generated File", "Test deletion immediately for the generated file", false),

                // Encryption Settings
                (rdbGen, "Generated Files", "Select the folder of the generated files", false),
                (rdbLoad,"Add File","Select files from the system", true),

                // Hash Settings
                (rdbBase64, "Base64", "Select Base64 HASH Output", true),
                (rdbHexLower, "Hex [Lower]", "Select Hex [Lower] HASH Output", false),
                (rdbHexUpper, "Hex [Upper]", "Select Hex [Upper] HASH Output", false),
                (rdbBase64salt, "Base64", "Select Base64 SALT Output", true),
                (rdbHexLowersalt, "Hex [Lower]", "Select Hex [Lower] SALT Output", false),
                (rdbHexUppersalt, "Hex [Upper]", "Select Hex [Upper] SALT Output", false),
                (rdbNumb,  "Numbers", "Generation of Number Sequences", true),
                (rdbSeq,  "Bit Sequences", "Generation of Bit Sequences", false),
                (rdbAll,  "All Characters", "Generate string with all Characters", true),
                (rdbNumber,  "Only Numbers", "Generate string with Numbers only", false),
                (rdbChr,  "Only Letters", "Generate string with Letters only", false),

                // Secure Deletion
                (rdbGendel, "Generated Files", "Select the folder of the generated files", false),
                (rdbLoaddel,"Add File","Select files from the system", true),
                (rdbCust1,"Classic Methode","Cancellation with the Classic Method", true),
                (rdbCust2,"User Method","Cancellation with the custom method", false),
            };

            foreach (var radoption in allradiobut)
            {
                radoption.Button.Checked = radoption.Cheched;
                radoption.Button.Text = radoption.Text;
                _tt.Set(radoption.Button, radoption.Tip);
                radoption.Button.Cursor = Cursors.Hand;
            }


            // ============================================================
            // CHECKBOX INITIALIZATION
            // Used for enabling/disabling optional behaviors and automation.
            // ============================================================

            var allChkBox = new (CheckBox Chk, string Text, string Tip, bool Checked, bool Enabled)[]
            {
                // Benchmark Proposal
               (chkImmediate, "Immediate Test", "Run the test immediately after generation", false, true),
               (chkOpenfoldbmk, "Open Folder after File creation", "Automatically open the folder once the file is created", false, true),
               (chkAdvanced,  "Analysis of all units", "Perform a complete analysis of all units", false, true),
    
               // Encryption Settings
               (chkOpfldencdecbmk, "Open Folder after file Encryption/Decryption", "Opens the target folder when the process is completed", false, true),
               (chkLoadlistbmk, "Always load the Test into the Benchmark List", "Saves every test result into the Benchmark List automatically", false, true),
               (chkDisplaybmk, "Display the Benchmark List after each process", "Shows the Benchmark List immediately after each operation", false, true),
               (chkDeloriginalbmk, "Delete the original file after the encryption process", "Removes the unencrypted file to keep only the protected version", false, true),
               (chkDelencryptedbmk, "Delete the encrypted file after the decryption process", "Removes the encrypted file after successful decryption", false, true),
               (chkHidden, "Visible", "Makes the PGP keys folder invisible in the system", false, true),
               (chkOpenfoldkeys, "Open the Keys Folder", "View folder after key generation", false, true),
               (chkFoldercreate, "If the path is valid, update the folder list for PGP keys when the window closes\r\n", "Update folder list for PGP keys when the window closes", false, true),

            // HASH Settings
            (chkNosalt, "Without SALT", "Generates output without SALT", false, true),
                (chkElapsed, "Insert Elapsed Time in the List", "View the time taken for each output", false, true),
                (chkHighlight, "Highlight the HASH Function with the Elapsed Time", "Highlights the HASH algorithm and the time taken for each output", false, true),

                // Secure Deletion
                (chkOpenFoldel, "Open Folder after File is Deleted", "Opens the folder immediately after the process is finished", false, true),
                (chkLoadlistbmkdel, "Always load the Test into the Benchmark List","Immediately adds the process to the Benchmark list", false, true),
                (chkDisplaybmkdel, "Display the Benchmark List after each process", "View the Benchmark list immediately after the process is finished", false, true),

                // Bencmark list
                (chkOverwrite, "Overwrite / Append", "Overwrite or append the content in the List with the file to load", false, true),
                (chkAlternate, "Alternate Row Color", "Allows alternating row colors in the List", false, true),
            };

            foreach (var boxOption in allChkBox)
            {
                boxOption.Chk.Enabled = boxOption.Enabled;
                boxOption.Chk.Checked = boxOption.Checked;
                boxOption.Chk.Text = boxOption.Text;
                _tt.Set(boxOption.Chk, boxOption.Tip);
                boxOption.Chk.Cursor = Cursors.Hand;
            }
            chkFoldercreate.ForeColor = Color.Brown;

            // ============================================================
            // COMBOBOX INITIALIZATION
            // Provides selection interfaces for cryptographic engines,
            // parameters, and system configuration.
            // ============================================================

            var allcombo = new (ComboBox Box, string Tip, bool Enabled)[]
            {                
                // Encryption Settings
                (cmbCrypteng,  "Select the appropriate Encryption Engine", true),
                (cmbStringcrypto,  "Select the appropriate Encryption string Engine", true),
                (cmbDrives,  "Select the appropriate drive where you want to create the PGP key folder", true),
                (cmbFolderPath,  "Select the appropriate folder where you want to create the PGP key", true),
                (cmbAeskeysize,  "Select the appropriate AES Key Size", true),
                (cmbRsaKeysize,  "Select the appropriate RSA Key Size", true),
                (cmbSepentkeysize,  "Select the appropriate Serpent Key Size", true),
                (cmbTwofishkeysize,  "Select the appropriate Twofish Key Size", true),
                (cmbCamelliakeysize,  "Select the appropriate Camellia Key Size", true),
                (cmbThreefishkeysize,  "Select the appropriate Threefish Key Size", true),

                // HASH Settings 
                (cmbHash,  "Select the appropriate HASH Engine", true),
                (cmbSalt,  "Select the appropriate SALT Engine", true),
                (cmbArgsize, "Select the HASH Size for the Argon2 Algorithm", true),
                (cmbScrypsize, "Select the HASH Size for the SCrypt Algorithm", true),
                (cmbBcrRound, "Select the BCrypt Rounds", true),

                // Secure Deletion
                (cmbCustom, "Select a value for the custom sequence", true),

                // Benchmark List
                (cmbFind, "Select a value to search", true),
            };

            foreach (var option in allcombo)
            {
                _tt.Set(option.Box, option.Tip);
                option.Box.Enabled = option.Enabled;
                option.Box.Cursor = Cursors.Hand;
            }

            // ============================================================
            // NUMERIC CONTROL INITIALIZATION
            // Used for numeric cryptographic and formatting parameters.
            // ============================================================

            var numericUp = new (NumericUpDown Box, string Tip)[]
            {
                (numTextblock, "Select the appropriate Number text Block"),
                (numIndent, "Select the appropriate Number of text indent"),
            };

            foreach (var (box, tip) in numericUp)
            {
                _tt.Set(box, tip);
                box.Cursor = Cursors.Hand;
            }

            #endregion Miscellaneous

            #region Configuration File

            // Declare a fallback default boolean value used when parsing configuration values fails or returns null.
            bool defaultValue = false;

            // ============================================================
            // To be executed before reading the configuration file.
            // ============================================================

            // Initialize the folders manager component.
            // This prepares internal folder structures, paths, and state required by the application.
            foldersManager.Initialize();

            // Bind the folders manager to the ComboBox control.
            // This populates the ComboBox with available folder paths and enables user selection.
            foldersManager.BindToComboBox(cmbFolderPath);
            labNumkey.Text = foldersManager.GetFolders().Count.ToString();

            // Instantiate the KeyarrowManager responsible for displaying and managing the key size indicator UI.
            // picKeisize: PictureBox used to visually display the key size indicator.
            // grbPgp: GroupBox associated with PGP configuration.
            // cmbCrypteng.Items.Count: Number of crypto engine options, used to configure the indicator logic.
            _keyarrowManager = new KeyarrowManager(picKeisize, grbPgp, cmbCrypteng.Items.Count);

            // Assign the XML configuration helper instance.
            // This object provides access to configuration values stored in the XML file.
            // This assignment is mandatory for configuration loading.
            _xmlConfig = AppConfigHelper.XmlConfig;// Indispensable

            // Check if the configuration file exists and ensure the "Result.ImmediateTest" key is not null or empty.
            // This condition determines whether configuration values should be loaded and applied to the UI.
            if (File.Exists(ForAllUnits.DirPath + @"\Speedcrypt.config.xml") && !string.IsNullOrEmpty(_xmlConfig.GetValue("Result.ImmediateTest")))
            {
                // Benchmark Proposal

                // Restore benchmark file size selection options from configuration.
                rdb1MB.Checked = _xmlConfig.GetValue("Result.1MBFile") == "True";
                rdb10MB.Checked = _xmlConfig.GetValue("Result.10MBFile") == "True";
                rdb100MB.Checked = _xmlConfig.GetValue("Result.100MBFile") == "True";
                rdb500MB.Checked = _xmlConfig.GetValue("Result.500MBFile") == "True";
                rdbCustom.Checked = _xmlConfig.GetValue("Result.CustomFile") == "True";

                // Restore custom benchmark file size value using InvariantCulture for cross-region compatibility
                numCustomSize.Value = int.Parse(_xmlConfig.GetValue("Result.CustomSize"), System.Globalization.CultureInfo.InvariantCulture);


                // Restore benchmark behavior options.
                chkOpenfoldbmk.Checked = _xmlConfig.GetValue("Result.OpenFolderBmk") == "True";
                chkOpfldencdecbmk.Checked = _xmlConfig.GetValue("Result.OpenfldencdecBmk") == "True";
                chkDisplaybmk.Checked = _xmlConfig.GetValue("Result.DisolayBmk") == "True";
                chkLoadlistbmk.Checked = _xmlConfig.GetValue("Result.LoadListBmk") == "True";
                chkDeloriginalbmk.Checked = _xmlConfig.GetValue("Result.DeloriginalBmk") == "True";
                chkDelencryptedbmk.Checked = _xmlConfig.GetValue("Result.DelencryptedBmk") == "True";

                // Restore immediate benchmark execution option.
                chkImmediate.Checked = _xmlConfig.GetValue("Result.ImmediateTest") == "True";

                // Enable or disable the immediate test GroupBox based on the restored state.
                grbTestnow.Enabled = chkImmediate.Checked;

                // Restore immediate test operation mode (encrypt or delete).
                rdbEnc.Checked = _xmlConfig.GetValue("Result.Immediateenc") == "True";
                rdbDel.Checked = _xmlConfig.GetValue("Result.Immediatedel") == "True";

                // Encrypt Engines

                // Restore the selected cryptographic engine from configuration.
                cmbCrypteng.Text = _xmlConfig.GetValue("Result.CryptoEngine");

                // Enable or disable the PGP settings GroupBox depending on whether PGP is selected.
                grbPgp.Enabled = cmbCrypteng.Text == "PGP";

                // PGP Keys Folder Creation
                chkFoldercreate.Checked = _xmlConfig.GetValue("Result.PGPFoldercreate") == "True";

                //Key arrow();

                // Update the visual key size indicator according to the selected crypto engine index.
                _keyarrowManager.UpdateIndicator(cmbCrypteng.SelectedIndex);

                // Restore key size selections for each supported cryptographic algorithm.
                cmbSepentkeysize.Text = _xmlConfig.GetValue("Result.SerpentKeySize");
                cmbTwofishkeysize.Text = _xmlConfig.GetValue("Result.TwofishKeySize");
                cmbCamelliakeysize.Text = _xmlConfig.GetValue("Result.CamelliaKeySize");
                cmbThreefishkeysize.Text = _xmlConfig.GetValue("Result.ThreefishKeySize");
                cmbRsaKeysize.Text = _xmlConfig.GetValue("Result.RSAKeySize");
                cmbAeskeysize.Text = _xmlConfig.GetValue("Result.AESKeySize");

                // Restore the folder path used for storing or loading PGP keys.
                cmbFolderPath.Text = _xmlConfig.GetValue("Result.PGPKeyFolderPath");

                // Encryption String

                // Restore the selected string encryption algorithm.
                cmbStringcrypto.Text = _xmlConfig.GetValue("Result.StringCrypto");

                // File options

                // Restore the option to generate files automatically.
                rdbGen.Checked = _xmlConfig.GetValue("Result.GenerateFile") == "True";

                // Enable or disable the file list control depending on generation mode.
                listFileload.Enabled = rdbGen.Checked;

                // Change label color to indicate active file generation mode.
                if (listFileload.Enabled) labFoldgen.ForeColor = Color.Brown;

                // Restore the option to load files manually.
                rdbLoad.Checked = _xmlConfig.GetValue("Result.LoadFile") == "True";

                // Change label color to indicate file loading mode.
                if (rdbLoad.Checked) labFoldgen.ForeColor = Color.Gray;

                // Enable or disable the load button depending on load mode selection.
                btnLoad.Enabled = rdbLoad.Checked;

                // Hash Engines

                // Restore the selected hash algorithm.
                cmbHash.Text = _xmlConfig.GetValue("Result.HashEngine");

                // Enable or disable the "No Salt" option depending on whether BCRYPT is selected.
                // BCRYPT internally manages salt and does not allow external salt configuration.
                //grbOutput.Enabled = cmbHash.Text != "BCRYPT";
                chkNosalt.Enabled = cmbHash.Text != "BCRYPT";

                // Restore the selected salt generation algorithm.
                cmbSalt.Text = _xmlConfig.GetValue("Result.SaltEngine");

                if (cmbHash.Text == "BCRYPT")
                {

                    cmbSalt.Text = cmbHash.Text;
                    cmbSalt.Enabled = false;
                }

                // Enable or disable salt output options depending on salt engine selection.
                // grbOutputsalt.Enabled = cmbSalt.Text != "BCRYPT";

                // Enable salt generation GroupBox only for supported deterministic or cryptographic salt generators.
                grbGen.Enabled = cmbSalt.Text == "AES-CTR DRBG" || cmbSalt.Text == "CRYPTO-RANDOM" || cmbSalt.Text == "BLUM-BLUM-SHUB[BBS]";

                // Attempt to parse numeric/sequence mode configuration safely with fallback default value.
                bool isChecked = bool.TryParse(_xmlConfig.GetValue("Result.NumbSeq") ?? defaultValue.ToString(), out bool result) ? result : defaultValue;

                // Apply parsed value to numeric mode RadioButton.
                rdbNumb.Checked = isChecked;

                // If numeric mode is not selected, enable sequence mode as fallback.
                if (!rdbNumb.Checked) rdbSeq.Checked = true;

                // Argon2

                // Restore Argon2 memory size parameter.
                txtArgMem.Text = _xmlConfig.GetValue("Result.ArgonMemSize");

                // Restore Argon2 parallelism parameter.
                txtArgParal.Text = _xmlConfig.GetValue("Result.ArgonParallelism");

                // Restore Argon2 iteration count parameter.
                txtArgIter.Text = _xmlConfig.GetValue("Result.ArgonIterations");

                // Restore Argon2 hash output size.
                cmbArgsize.Text = _xmlConfig.GetValue("Result.ArgonHashSize");

                // Scrypt

                // Restore Scrypt memory size parameter.
                txtScrMem.Text = _xmlConfig.GetValue("Result.ScryptMemSize");

                // Restore Scrypt parallelization parameter.
                txtScrParal.Text = _xmlConfig.GetValue("Result.ScryptParallelization");

                // Restore Scrypt block size parameter.
                txtScrBksz.Text = _xmlConfig.GetValue("Result.ScryptBlockSize");

                // Restore Scrypt hash output size.
                cmbScrypsize.Text = _xmlConfig.GetValue("Result.ScryptHashSize");

                // PBKDF2

                // Restore BCrypt rounds parameter.
                cmbBcrRound.Text = _xmlConfig.GetValue("Result.BCryptRounds");

                // Restore PBKDF2 iteration count parameter.
                txtPbkIter.Text = _xmlConfig.GetValue("Result.PBKDF2Rounds");

                // Hash options

                // Restore output encoding format selections for hash values.
                rdbBase64.Checked = _xmlConfig.GetValue("Result.SaltBase64") == "True";
                rdbHexLower.Checked = _xmlConfig.GetValue("Result.SaltHexLower") == "True";
                rdbHexUpper.Checked = _xmlConfig.GetValue("Result.SaltHexUpper") == "True";

                // Restore option to disable salt usage.
                chkNosalt.Checked = _xmlConfig.GetValue("Result.WhitoutSalt") == "True";

                // Restore option to display elapsed hashing time.
                chkElapsed.Checked = _xmlConfig.GetValue("Result.ElapsedTime") == "True";

                // Restore option to highlight hash output visually.
                chkHighlight.Checked = _xmlConfig.GetValue("Result.HashHighlight") == "True";

                // Salt options

                // Restore output encoding format selections for salt values.
                rdbBase64salt.Checked = _xmlConfig.GetValue("Result.SaltBase64Salt") == "True";
                rdbHexLowersalt.Checked = _xmlConfig.GetValue("Result.SaltHexLowerSalt") == "True";
                rdbHexUppersalt.Checked = _xmlConfig.GetValue("Result.SaltHexUpperSalt") == "True";

                // String Values

                // Restore string content selection mode.
                rdbAll.Checked = _xmlConfig.GetValue("Result.StringValueAll") == "True";
                rdbNumber.Checked = _xmlConfig.GetValue("Result.StringValueNum") == "True";
                rdbChr.Checked = _xmlConfig.GetValue("Result.StringValueChr") == "True";

                // Numeric UpDown

                // Restore indentation level setting using InvariantCulture to prevent localization parsing failures
                numIndent.Value = int.Parse(_xmlConfig.GetValue("Result.NumIndent"), System.Globalization.CultureInfo.InvariantCulture);

                // Restore text block size setting using InvariantCulture to prevent localization parsing failures
                numTextblock.Value = int.Parse(_xmlConfig.GetValue("Result.NumTextBlock"), System.Globalization.CultureInfo.InvariantCulture);

                // Secure Deletion

                // Restore selected secure deletion algorithm.
                cmbAlgodel.Text = _xmlConfig.GetValue("Result.DeleteEngine");

                // Restore secure deletion method selection.
                rdbCust1.Checked = _xmlConfig.GetValue("Result.ClassicMethod") == "True";
                rdbCust2.Checked = _xmlConfig.GetValue("Result.UserMethod") == "True";

                // Restore option to open folder after deletion.
                chkOpenFoldel.Checked = _xmlConfig.GetValue("Result.OpenFoldafterdel") == "True";

                // Restore option to insert list after deletion.
                chkLoadlistbmkdel.Checked = _xmlConfig.GetValue("Result.Insertlistafterdel") == "True";

                // Restore option to display list after deletion.
                chkDisplaybmkdel.Checked = _xmlConfig.GetValue("Result.Displaylistafterdel") == "True";

                // Retrieve custom secure deletion value sequence.
                string customValue = _xmlConfig.GetValue("Result.CustomValue");

                // If custom value exists and user-defined deletion method is selected, restore and apply it.
                if (!string.IsNullOrEmpty(customValue) && rdbCust2.Checked)
                {
                    // Split the stored sequence and populate the custom list.
                    listCustom.Items.AddRange(customValue.Split('|'));

                    // Enable list management buttons.
                    btnClearlistval.Enabled = true;
                    btnSaveval.Enabled = true;

                    // Instantiate evaluator to analyze and display strength of the custom pass sequence.
                    var evaluator = new CustomPassEvaluator(listCustom, qualityProgressBar1, labValue);

                    // Update the visual strength indicator.
                    evaluator.UpdateStrength();
                }

                // Restore secure deletion file generation mode.
                rdbGendel.Checked = _xmlConfig.GetValue("Result.GenerateFileDel") == "True";

                // Enable or disable file list depending on generation mode.
                listFileloaddel.Enabled = rdbGendel.Checked;

                // Change label color to indicate generation mode.
                if (listFileloaddel.Enabled) labFoldgendel.ForeColor = Color.Brown;

                // Restore secure deletion file load mode.
                rdbLoaddel.Checked = _xmlConfig.GetValue("Result.LoadFileDel") == "True";

                // Enable or disable load button accordingly.
                btnLoaddel.Enabled = rdbLoaddel.Checked;

                // Update PBKDF2 indicator or state based on restored configuration.
                PBKDF2led();

                // Benckmarch List

                // Restore option to overwrite or append benchmark results.
                chkOverwrite.Checked = _xmlConfig.GetValue("Result.BmkOverwriteAppend") == "True";

                // Restore option to alternate row coloring in benchmark list.
                chkAlternate.Checked = _xmlConfig.GetValue("Result.BmkAlternateRow") == "True";
            }
            else cmbSalt.Enabled = false; // Indispensable for BCRYPT

            #endregion Configuration File

            #region Paste Menu

            // Set the image icon associated with the pasteFileName UI element.
            // This assigns a predefined 16x16 pager icon from the global ForAllUnits resource container,
            // ensuring consistent visual representation across the application interface.
            pasteFileName.Image = ForAllUnits.Kpager16;

            #endregion Paste Menu

            #region Event handlers

            // ============================================================
            // Benchmark Proposal
            // ============================================================

            // Assign click event handler for file generation button.
            btnGenfile.Click += BtnGenfile_Click;

            // Assign event handler to handle changes in custom size numeric input.
            numCustomSize.TextChanged += NumCustomSize_TextChanged;

            // Assign event handler for immediate test checkbox state changes.
            chkImmediate.CheckedChanged += ChkImmediate_CheckedChanged;

            // ============================================================
            // Encryption Engines
            // ============================================================

            // Handle selection changes in the crypto engine ComboBox.
            cmbCrypteng.SelectedIndexChanged += CmbCrypteng_SelectedIndexChanged;

            // Handle selection changes in the string encryption algorithm ComboBox.
            cmbStringcrypto.SelectedIndexChanged += CmbStringcrypto_SelectedIndexChanged;

            // Handle key press events for PBKDF2 rounds input field.
            txtPbkdf2round.KeyPress += TxtPbkdf2round_KeyPress;
            txtPbkdf2round.Leave += TxtPbkdf2round_Leave;

            // Handle selection changes for available drives ComboBox.
            cmbDrives.DropDownClosed += CmbDrives_DropDownClosed;

            // Assign click events for folder management buttons.
            btnFoldernew.Click += BtnFoldernew_Click;
            btnFolderpath.Click += BtnFolderpath_Click;

            // Assign click events for generate and delete folder buttons.
            btnGen.Click += BtnGen_Click;
            btnDelFolder.Click += BtnDelFolder_Click;

            // Handle selection changes and text updates for folder path ComboBox.
            cmbFolderPath.SelectedIndexChanged += CmbFolderPhat_SelectedIndexChanged;
            cmbFolderPath.TextChanged += CmbFolderPhat_TextChanged;

            // Handle hidden files checkbox changes.
            chkHidden.Click += ChkHidden_Click;

            // Handle double-click on file load list to open or select file.
            listFileload.DoubleClick += ListFileload_DoubleClick;

            // Handle radio button changes for file generation or load mode.
            rdbGen.CheckedChanged += RdbGen_CheckedChanged;
            rdbLoad.CheckedChanged += RdbLoad_CheckedChanged;

            // Assign click and mouse events for file load button.
            btnLoad.Click += Btnload_Click;

            // Assign click events for encryption and decryption buttons.
            btnEncrypt.Click += BtnEncrypt_Click;
            btnDecrypt.Click += BtnDecrypt_Click;

            // Assign click event for clearing test inputs.
            btnCleartest.Click += BtnCleartest_Click;

            // Handle text changes in file path input field.
            txtFilepath.TextChanged += TxtFilepath_TextChanged;

            // ============================================================
            // HASH Engines
            // ============================================================

            // Assign click and mouse events for salt test button.
            btnSaltTest.Click += BtnSaltTest_Click;
            btnSaltTest.MouseMove += BtnSaltTest_MouseMove;
            btnSaltTest.MouseLeave += BtnSaltTest_MouseLeave;

            // Assign click and mouse events for string value evaluation button.
            btnStringval.Click += BtnStringval_Click;
            btnStringval.MouseMove += BtnStringval_MouseMove;
            btnStringval.MouseLeave += BtnStringval_MouseLeave;

            // Handle text changes and mouse events for salt input field.
            txtSalt.TextChanged += TxtSalt_TextChanged;
            txtSalt.MouseDown += TxtSalt_MouseDown;

            // Assign click event for hash test button.
            btnHashTest.Click += BtnHashtest_Click;

            // Handle text changes and mouse events for hash input field.
            txtHashInput.TextChanged += TxtKey_TextChanged;
            txtHashInput.MouseDown += TxtKey_MouseDown;

            // Assign click event for cancel button in hash operations.
            btnCanc.Click += BtnCanc_Click;

            // Handle mouse down events for Argon2 input fields.
            txtArgMem.MouseDown += TxtArgMem_MouseDown;
            txtArgParal.MouseDown += TxtArgParal_MouseDown;
            txtArgIter.MouseDown += TxtArgIter_MouseDown;

            // Handle mouse down and key press events for Scrypt input fields.
            txtScrMem.MouseDown += TxtScrMem_MouseDown;
            txtScrMem.KeyPress += TxtPbkdf2round_KeyPress;
            txtScrParal.MouseDown += TxtScrParal_MouseDown;
            txtScrParal.KeyPress += TxtPbkdf2round_KeyPress;
            txtScrBksz.KeyPress += TxtPbkdf2round_KeyPress;

            // Handle key press and mouse down for PBKDF2 rounds input fields.
            txtPbkIter.KeyPress += TxtPbkdf2round_KeyPress;
            txtScrBksz.MouseDown += TxtScrBksz_MouseDown;
            txtPbkIter.MouseDown += TxtPbkIter_MouseDown;

            // Handle text changes in the RichTextBox displaying hash results.
            rchHashresult.TextChanged += RchHashresult_TextChanged;

            // Handle key press events for Argon2 numeric inputs.
            txtArgMem.KeyPress += TxtPbkdf2round_KeyPress;
            txtArgParal.KeyPress += TxtPbkdf2round_KeyPress;
            txtArgIter.KeyPress += TxtPbkdf2round_KeyPress;

            // Handle selection changes for hash and salt engine ComboBoxes.
            cmbHash.SelectedIndexChanged += CmbHash_SelectedIndexChanged;
            cmbSalt.SelectedIndexChanged += CmbSalt_SelectedIndexChanged;

            // ============================================================
            // Secure Deletion
            // ============================================================

            // Handle selection changes for deletion algorithm and custom method ComboBoxes.
            cmbAlgodel.SelectedIndexChanged += CmbAlgodel_SelectedIndexChanged;
            cmbCustom.SelectedIndexChanged += CmbCustom_SelectedIndexChanged;

            // Assign click events for custom list management buttons.
            listCustom.Click += ListCustom_Click;
            btnRepeatval.Click += BtnRepeatval_Click;
            btnClearval.Click += BtnClearval_Click;
            btnAlgodel.Click += BtnAlgodel_Click;
            btnSaveval.Click += BtnSaveval_Click;
            btnLoadval.Click += BtnLoadval_Click;
            btnClearlistval.Click += BtnClearlistval_Click;

            // Handle changes in secure deletion method radio buttons.
            rdbCust1.CheckedChanged += RdbCust1_CheckedChanged;
            rdbCust2.Click += RdbCust2_Click;    

            // Handle radio buttons for generation and loading mode in secure deletion.
            rdbGendel.CheckedChanged += RdbGendel_CheckedChanged;
            rdbLoaddel.CheckedChanged += RdbLoaddel_CheckedChanged;

            // Assign context menu, text change, and mouse events for deletion file path input.
            txtFilepathdel.ContextMenuStrip = bContextMenuStrip1;
            txtFilepathdel.TextChanged += TxtFilepathdel_TextChanged;

            // Assign click and mouse events for deletion load buttons.
            btnLoaddel.Click += BtnLoaddel_Click;
            btnLoaddel.MouseMove += BtnLoaddel_MouseMove;
            btnLoaddel.MouseLeave += BtnLoaddel_MouseLeave;

            // Assign click event for delete button.
            btnDelete.Click += BtnDelete_Click;

            // Handle double-click on secure deletion file list.
            listFileloaddel.DoubleClick += ListFileloaddel_DoubleClick;

            // ============================================================
            // Benchmark List
            // ============================================================

            // Assign click events for benchmark list import/export and management buttons.
            listBmk.MouseUp += ListBmk_MouseUp;
            btnImpList.Click += BtnImpList_Click;
            btnExplist.Click += BtnExplist_Click;
            btnClearlist.Click += BtnClearlist_Click;
            btnDelitem.Click += BtnDelitem_Click;
            btnSave.Click += BtnSave_Click;

            // Handle mouse down and text change events for process name input field.
            txtProcname.MouseDown += TxtProcname_MouseDown;
            txtProcname.TextChanged += TxtProcname_TextChanged;

            // Handle selection changes for process find ComboBox and tab control.
            cmbFind.SelectedIndexChanged += CmbFind_SelectedIndexChanged;
            tabControl1.SelectedIndexChanged += TabControl1_SelectedIndexChanged;

            // Handle checkbox changes for alternating row colors in benchmark list.
            chkAlternate.CheckedChanged += ChkAlternate_CheckedChanged;

            // ============================================================
            // Paste Menu
            // ============================================================

            // Assign click event for paste menu item.
            pasteFileName.Click += PasteFileName_Click;

            // Contextual help
            btnHelp.Click += BtnHelp_Click;

            #endregion Event handlers

            #region Timer

            // Assign the Tick event handler for timer1.
            // This handler will be executed at each timer interval, enabling periodic actions or updates.
            timer1.Tick += Timer1_Tick;

            #endregion Timer

            #region Initialization

            // Check if the folder path in the ComboBox exists
            if (Directory.Exists(cmbFolderPath.Text))
            {
                FileAttributes attributes = File.GetAttributes(cmbFolderPath.Text.Trim());
                if ((attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                {
                    chkHidden.Checked = true;
                }
            }

            // Refresh drive list when ComboBox is opened
            UpdateDriveList();

            // Load files into ListViews with icons
            Folderfileload();

            // Update disk properties
            Diskprop();

            // Attach hover highlighter to all text boxes
            TextBoxHoverHighlighter.Attach(this);

            // Apply default selection logic
            Selection();

            // Initialize custom password evaluator
            evaluator = new CustomPassEvaluator(listCustom, qualityProgressBar1, labValue);

            // Set indicator image if first hash or salt selected
            if (cmbHash.SelectedIndex == 0 || cmbSalt.SelectedIndex == 0)
                picBic.Image = ForAllUnits.Ledgreen16;

            // Load PBKDF2 rounds
            LoadPbkdf2round();

            // Disable ghost UI initially
            SpeedcryptGhost.Disable(this);
            if (mainForm.Obfs == true)
                SpeedcryptGhost.Enable(this);

            mainForm.Sett = true;

            // Update hash security UI if hash already selected
            if (cmbHash.SelectedItem != null)
            {
                HashSecurityStrength.UpdateUIFromCombo(cmbHash, labHashScore, labHashRec, qualityProgressBar2);
            }

            // Update crypto engine security UI if selected
            if (cmbCrypteng.SelectedItem != null)
            {
                CryptoSecurityStrength.UpdateUIFromCombo(cmbCrypteng, labCryptoScore, labCryptoRec, qualityProgressBar3);

            }

            // Enable hand cursor on ListViews for better UX
            listFileload.EnableHandCursor();
            listFileloaddel.EnableHandCursor();
            listCustom.EnableHandCursor();
            listBmk.EnableHandCursor();

            // Initialize dirty tracker for Save button
            _dirtyTracker = new DirtyTracker(btnSave);

            // Initialize ListView row alternator for alternating row colors
            _alternator = new ListViewRowAlternator(listBmk);
            if (chkAlternate.Checked) _alternator.Enable();

            // Set tooltip for KDF group box
            _tt.Set(grbKdf, "HMAC-based Key Derivation Function (KDF) used for key stretching.");

            // Attach events AFTER controls are fully initialized and loaded
            chkAdvanced.CheckedChanged += (s, e) => Diskprop();

            cmbHash.SelectedIndexChanged += (s, ev) =>
            {
                HashSecurityStrength.UpdateUIFromCombo(cmbHash, labHashScore, labHashRec, qualityProgressBar2);
            };

            cmbCrypteng.SelectedIndexChanged += (s, ev) =>
            {
                CryptoSecurityStrength.UpdateUIFromCombo(cmbCrypteng, labCryptoScore, labCryptoRec, qualityProgressBar3);
            };

            // Enable form to intercept key presses
            this.KeyPreview = true;

            // Block space key interference
            SpaceKeyBlocker.Enable(this);

            // Prevent overwriting of active PGP keys
            ConfigPGPvalidator();

            // Ensure caret is always positioned at the end of the text and no selection remains
            CaretManager.Attach(cmbFolderPath);

            #endregion Initialization
        }        

        #endregion Form Routines

        #region  Benchmark Proposal
        private void BtnGenfile_Click(object sender, EventArgs e)
        {
            btnGenfile.Enabled = false;
            //string tempFolderPath = Path.Combine(Application.StartupPath, "Encryptbmk");
            if (!Directory.Exists(ForAllUnits.DirPath + @"\Speedbmk"))
                Directory.CreateDirectory(ForAllUnits.DirPath + @"\Speedbmk");

            string fileName = "";
            long fileSize = 0;

            if (rdb1MB.Checked)
            {
                fileName = "1mega.txt";
                fileSize = 1 * 1024 * 1024;
            }
            else if (rdb10MB.Checked)
            {
                fileName = "10mega.txt";
                fileSize = 10 * 1024 * 1024;
            }
            else if (rdb100MB.Checked)
            {
                fileName = "100mega.txt";
                fileSize = 100 * 1024 * 1024;
            }
            else if (rdb500MB.Checked)
            {
                fileName = "500mega.txt";
                fileSize = 500 * 1024 * 1024;
            }
            else if (rdbCustom.Checked)
            {
                fileName = $"{numCustomSize.Value}mega.txt";
                fileSize = (long)numCustomSize.Value * 1024 * 1024;
            }

            string filePath = Path.Combine(ForAllUnits.DirPath + @"\Speedbmk\", fileName);

            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                {
                    string text = "Speedcrypt for a sample text file to be used for benchmarking purposes.\n";
                    byte[] textBytes = Encoding.ASCII.GetBytes(text);
                    long totalBytesWritten = 0;

                    // Configure the ProgressBar
                    progressBar1.Visible = true;
                    progressBar1.Minimum = 0;
                    progressBar1.Maximum = 100;
                    progressBar1.Value = 0;

                    int progressUpdateStep = 100; // how often to update (in KB)
                    long nextProgressUpdate = progressUpdateStep * 1024;

                    while (totalBytesWritten < fileSize)
                    {
                        fs.Write(textBytes, 0, textBytes.Length);
                        totalBytesWritten += textBytes.Length;

                        if (totalBytesWritten >= nextProgressUpdate || totalBytesWritten >= fileSize)
                        {
                            int progress = (int)((totalBytesWritten * 100) / fileSize);
                            progressBar1.Value = Math.Min(progress, 100);
                            nextProgressUpdate += progressUpdateStep * 1024;
                            Application.DoEvents(); // to visually update the bar
                        }
                    }
                }

                progressBar1.Value = 100;
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Access Error!", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show("A generic error occurred during file generation!", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "SETTINGS", "A generic error occurred during file generation!");
            }
            finally
            {
                if (progressBar1.Value == 100)
                    MessageBox.Show($"File {fileName} successfully created in Folder {ForAllUnits.DirPath + @"\Speedbmk"}", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
                progressBar1.Value = 0;
                btnGenfile.Enabled = true;

                if (chkOpenfoldbmk.Checked)
                    Process.Start("Explorer.exe", "/select, \"" + Path.GetDirectoryName(filePath) + "\\" + Path.GetFileName(filePath) + "\"");

                if (chkImmediate.Checked)
                {
                    if (rdbEnc.Checked)
                    {
                        txtFilepath.Text = filePath;
                        FileInfo fileInfo = new FileInfo(filePath);
                        labMb.Text = fileInfo.Strbytes();
                        tabControl1.SelectedIndex = 1;
                        rdbGen.Enabled = true;
                        rdbGen.Checked = true;
                        listFileload.Enabled = true;
                        labFoldgen.ForeColor = Color.Brown;
                    }
                    else if (rdbDel.Checked)
                    {
                        txtFilepathdel.Text = filePath;
                        FileInfo fileInfo = new FileInfo(filePath);
                        labKb.Text = fileInfo.Strbytes();
                        tabControl1.SelectedIndex = 3;
                        rdbGendel.Enabled = true;
                        rdbGendel.Checked = true;
                        listFileloaddel.Enabled = true;
                        labFoldgendel.ForeColor = Color.Brown;
                    }

                    Passwbmk();
                }

                Folderfileload();
            }
        }
        private void NumCustomSize_TextChanged(object sender, EventArgs e)
        {
            if (numCustomSize.Value < 1)
            {
                numCustomSize.Value = 1; // Set the minimum value
            }
            if (numCustomSize.Value > 2000)
            {
                numCustomSize.Value = 2000; // Set the maximum value
            }
        }
        private void ChkImmediate_CheckedChanged(object sender, EventArgs e)
        {
            grbTestnow.Enabled = chkImmediate.Checked;
        }
        private void Diskprop_Shown(object sender, EventArgs e)
        {
            this.Shown -= Diskprop_Shown; // Atomic unsubscription guaranteed
            Diskprop();
        }
        void Diskprop()
        {
            // Safely defer if the handle is not fully ready by using a non-anonymous named event handler
            if (!IsHandleCreated || IsDisposed)
            {
                this.Shown -= Diskprop_Shown;
                this.Shown += Diskprop_Shown;
                return;
            }

            try
            {
                // Snapshot UI state and config once (UI thread)
                bool showAdvanced = chkAdvanced.Checked;
                bool cfgExists = File.Exists(AppConfigHelper.ConfigFilePath);

                // Reduce flicker immediately
                listAdvise.SetDoubleBuffered(true);

                // Show the form instantly; defer heavy work
                listAdvise.BeginUpdate();
                listAdvise.Items.Clear();
                listAdvise.Items.Add(new ListViewItem(new[] { "", "Loading drives..." })); // Placeholder to ensure it is displayed correctly
                listAdvise.EndUpdate();

                // Offload heavy work from UI thread
                Task.Run(() =>
                {
                    try
                    {
                        long tot = 0; // kept for compatibility with existing logic
                        var detectedDrives = Detector.DetectFixedDrives(QueryType.SeekPenalty);

                        // FIX: Wrap the expensive WMI operation in a Task with a 4-second timeout to prevent Windows 10 permanent freezes
                        var wmiTask = Task.Run(() => HDInfomodel.GetAllDiskBrandsFromWMI(
                            includeRemovables: showAdvanced,
                            includeWithoutLogical: showAdvanced
                        ));

                        Dictionary<string, string> diskBrands;
                        if (wmiTask.Wait(4000))
                        {
                            diskBrands = wmiTask.Result ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        }
                        else
                        {
                            // Fallback to empty dictionary if WMI hangs or times out on Win10
                            diskBrands = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                            CentralLog.LogException(new TimeoutException("WMI query timed out."), "SETTINGS", "WMI sweep timed out on Windows 10, using fallback.");
                        }

                        // Build items in memory to avoid incremental UI churn
                        var itemsToAdd = new List<ListViewItem>(64);
                        int? finalSelectedIndex = null;

                        if (detectedDrives.Count > 0)
                        {
                            foreach (var detectedDrive in detectedDrives)
                            {
                                string driveKey = detectedDrive.DriveLetter + ":";

                                if (!diskBrands.TryGetValue(driveKey, out var brand) || string.IsNullOrEmpty(brand))
                                    brand = "Unknown";

                                // Preserve original variable usage
                                tot = detectedDrive.TotalSize - detectedDrive.AvailableFreeSpace;

                                itemsToAdd.Add(new ListViewItem(new[] { "", $"Drive {detectedDrive.Name} ({brand})" }, 7));

                                // SSD vs HDD logic (unchanged in meaning)
                                bool isSsd = detectedDrive.HardwareType.ToString().IndexOf("SSD", StringComparison.OrdinalIgnoreCase) >= 0;
                                if (isSsd)
                                {
                                    if (!cfgExists) finalSelectedIndex = 12;
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Deletion Algorithm: NIST 800-88 Rev.1 Secure Erase" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: AES" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: PGP" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: AES-GCM" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: CAMELLIA" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: KUZNYECHIK" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: XCHACHA20-POLY1305" }));
                                }
                                else
                                {
                                    if (!cfgExists) finalSelectedIndex = 3;
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Deletion Algorithm: DoD 7 Passes" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Deletion Algorithm: Schneier 7 Passes" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Deletion Algorithm: Custom Erase by Mariano Ortu" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: AES" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: IDEA" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: GOST" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: TWOFISH" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: SERPENT" }));
                                    itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: THREEFISH" }));
                                }

                                itemsToAdd.Add(new ListViewItem(new[] { "", "" }));
                            }

                            if (showAdvanced)
                            {
                                foreach (var kvp in diskBrands)
                                {
                                    string driveLetter = kvp.Key;
                                    string model = kvp.Value;

                                    // Skip duplicates already present in detected list
                                    bool alreadyListed = detectedDrives.Any(d => string.Equals(d.DriveLetter + ":", driveLetter, StringComparison.OrdinalIgnoreCase));
                                    if (!alreadyListed)
                                    {
                                        string modelInfo = (driveLetter.IndexOf(model ?? string.Empty, StringComparison.OrdinalIgnoreCase) >= 0) ? "" : $" ({model})";
                                        itemsToAdd.Add(new ListViewItem(new[] { "", $"Drive {driveLetter}{modelInfo}" }, 7));

                                        if (!driveLetter.EndsWith("[no volume]", StringComparison.OrdinalIgnoreCase))
                                        {
                                            if (!cfgExists) finalSelectedIndex = 3;
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Deletion Algorithm: DoD 7 Passes" }));
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Deletion Algorithm: Schneier 7 Passes" }));
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Deletion Algorithm: Custom Erase by Mariano Ortu" }));
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: AES" }));
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: IDEA" }));
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: GOST" }));
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: TWOFISH" }));
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: SERPENT" }));
                                            itemsToAdd.Add(new ListViewItem(new[] { "", "Encryption Algorithm: THREEFISH" }));
                                        }

                                        itemsToAdd.Add(new ListViewItem(new[] { "", "" }));
                                    }
                                }
                            }
                        }

                        // Marshal batched UI updates back to UI thread
                        if (IsHandleCreated && !IsDisposed)
                        {
                            BeginInvoke(new Action(() =>
                            {
                                try
                                {
                                    listAdvise.BeginUpdate();
                                    listAdvise.ShowSubItemIcons(true);
                                    listAdvise.Items.Clear();

                                    if (itemsToAdd.Count > 0)
                                        listAdvise.Items.AddRange(itemsToAdd.ToArray());

                                    // Apply subitem icons after items are present
                                    for (int i = 0; i < listAdvise.Items.Count; i++)
                                    {
                                        var subs = listAdvise.Items[i].SubItems;
                                        if (subs.Count > 1)
                                        {
                                            // FIX: Corrected text extraction using index 1 as verified
                                            string text = subs[1].Text;
                                            if (text.IndexOf("Deletion", StringComparison.OrdinalIgnoreCase) >= 0)
                                                listAdvise.AddIconToSubitem(i, 1, 3);
                                            else if (text.IndexOf("Encryption", StringComparison.OrdinalIgnoreCase) >= 0)
                                                listAdvise.AddIconToSubitem(i, 1, 0);
                                        }
                                    }

                                    // Set algorithm only once on UI thread (Safe and centralized)
                                    if (finalSelectedIndex.HasValue)
                                    {
                                        if (cmbAlgodel.Items.Count > finalSelectedIndex.Value)
                                            cmbAlgodel.SelectedIndex = finalSelectedIndex.Value;
                                    }
                                    else
                                    {
                                        if (cmbAlgodel.Items.Count > 0 && cmbAlgodel.SelectedIndex == -1)
                                            cmbAlgodel.SelectedIndex = 0;
                                    }
                                }
                                finally
                                {
                                    listAdvise.EndUpdate();
                                }
                            }));
                        }
                    }
                    catch (Exception ex)
                    {
                        CentralLog.LogException(ex, "SETTINGS", "An error occurred while selecting the most appropriate algorithms!");
                    }
                });
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "SETTINGS", "An error occurred while selecting the most appropriate algorithms!");
            }
        }

        #endregion Benchmark Proposal

        #region Encryption Engines
        private void CmbCrypteng_SelectedIndexChanged(object sender, EventArgs e)
        {
            grbPgp.Enabled = false;
            CryptoSecurityStrength.UpdateUIFromCombo(cmbCrypteng, labCryptoScore, labCryptoRec, qualityProgressBar3);

            InactivePGP();

            _keyarrowManager.UpdateIndicator(cmbCrypteng.SelectedIndex);

            // PGP Control
            if (cmbCrypteng.SelectedIndex == 1) HandleFolderUpdate();
        }
        private void CmbStringcrypto_SelectedIndexChanged(object sender, EventArgs e)
        {
            LoadPbkdf2round();
        }
        private void CmbDrives_DropDownClosed(object sender, EventArgs e)
        {
            try
            {
                if (cmbDrives.SelectedItem == null)
                    return;

                string selectedDrive = cmbDrives.SelectedItem as string;
                if (string.IsNullOrEmpty(cmbFolderPath.Text) || Directory.Exists(selectedDrive))
                {
                    CaretManager.SetText(cmbFolderPath, cmbDrives.SelectedItem.ToString(), true);
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "SETTINGS", "An error occurred in Drives selection!");
            }
        }
        private void BtnFoldernew_Click(object sender, EventArgs e)
        {
            string folderPath = cmbFolderPath.Text.Trim();

            // Ensure path ends with backslash
            if (!folderPath.EndsWith("\\"))
                folderPath += "\\";

            // ======================
            // Strict validation
            // ======================
            if (string.IsNullOrWhiteSpace(folderPath) || folderPath.Length < 3 || !char.IsLetter(folderPath[0]) || folderPath[1] != ':' || folderPath[2] != '\\')
            {
                MessageBox.Show("Please enter a valid folder path starting with a drive letter and colon (e.g. C:\\FolderName).",
                                ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Comboreb();
                return;
            }

            string root = Path.GetPathRoot(folderPath);
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
            {
                MessageBox.Show("The selected drive does not exist.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Comboreb();
                return;
            }

            // ======================
            // Creation logic
            // ======================
            try
            {
                if (Directory.Exists(folderPath))
                {
                    MessageBox.Show("The folder already exists.", ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                // Create folder
                Directory.CreateDirectory(folderPath);

                MessageBox.Show("Folder successfully created!", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);

                // Add to manager only if not already present
                if (!foldersManager.GetFolders().Contains(folderPath, StringComparer.OrdinalIgnoreCase))
                {
                    foldersManager.AddFolder(folderPath);
                }

                // Bind ComboBox and force selection to the newly created folder
                cmbFolderPath.Items.Clear();
                foreach (string f in foldersManager.GetFolders())
                {
                    cmbFolderPath.Items.Add(f);
                }

                cmbFolderPath.SelectedItem = folderPath;
                btnFoldernew.Enabled = false;
                btnGen.Enabled = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error creating the folder! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "SETTINGS", "Error creating the folder!");
            }
        }
        private void BtnFolderpath_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog fld = new FolderBrowserDialog
            {
                ShowNewFolderButton = true
            };

            // Show the FolderBrowserDialog.  
            DialogResult result = fld.ShowDialog();

            if (result == DialogResult.OK && Directory.Exists(fld.SelectedPath))
            {
                string selectedPath = fld.SelectedPath.Trim();

                // Ensure the path ends with a single backslash
                if (!selectedPath.EndsWith("\\"))
                {
                    selectedPath += "\\";
                }

                // --- DYNAMIC COLLECTION SYNCHRONIZATION SUB-SYSTEM ---
                if (cmbFolderPath.Items != null)
                {
                    bool exists = false;

                    // Execute linear scan to prevent duplicate entries within the collection scope
                    foreach (var item in cmbFolderPath.Items)
                    {
                        if (item != null && item.ToString().Equals(selectedPath, StringComparison.OrdinalIgnoreCase))
                        {
                            exists = true;
                            break;
                        }
                    }

                    // Append unique target path to maintain multi-item state consistency
                    if (!exists)
                    {
                        cmbFolderPath.Items.Add(selectedPath);
                    }

                    // --- UI STATE SYNCHRONIZATION AND INDEX ALIGNMENT ---
                    // Resolve exact collection index to safely trigger structural UI updates
                    int itemIndex = cmbFolderPath.Items.IndexOf(selectedPath);
                    if (itemIndex >= 0)
                    {
                        cmbFolderPath.SelectedIndex = itemIndex;
                    }
                }
            }
        }
        private void BtnGen_Click(object sender, EventArgs e)
        {
            // Extract text, trim spaces, and ensure it ends with a single backslash
            string folderPath = cmbFolderPath.Text.Trim();
            if (!string.IsNullOrEmpty(folderPath) && !folderPath.EndsWith("\\"))
            {
                folderPath += "\\";
            }

            // Update the ComboBox text visually in the UI if it was missing the backslash
            cmbFolderPath.Text = folderPath;

            // Validate the normalized folder path
            if (!ValidateFolderPath(folderPath))
                return; // Stop if validation fails

            // Check if the path already exists in the configuration file
            PgpPathValidator validator = new PgpPathValidator();
            if (validator.IsValid(folderPath))
            {
                MessageBox.Show("The selected folder already contains PGP engine keys in the configuration file! Operation aborted to prevent data loss.",
                                ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return; // Stop everything / abort operation
            }

            try
            {
                // Warn user about impending data overwrite
                if (MessageBox.Show("Warning: Speedcrypt is generating RSA keys. Any existing keys in the selected folder will be overwritten!", ForAllUnits.BoxWrg,
                                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    return;
                }

                Keysize();

                // Generate key password using Blake256 hash function
                string password = BitConverter.ToString(new Blake256().ComputeHash(Encoding.UTF8.GetBytes("Speedcrypt BenchMark"))).ToLower().Replace("-", "");

                // Ensure the target directory physically exists
                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                // Reset progress bar controls
                progressBar2.Minimum = 0;
                progressBar2.Maximum = 100;

                // Local function for UI thread safe progress updates
                void ProgressCallback(int percent)
                {
                    this.Invoke(new Action(() =>
                    {
                        progressBar2.Value = percent;
                    }));
                }

                // Assign to Action<int> delegate
                Action<int> progressCallback = ProgressCallback;

                // Execute key generation asynchronously to keep UI responsive
                Task.Run(() =>
                {
                    // Enforce InvariantCulture to ensure accurate RSA key size extraction across international environments
                    RSAkeygenerator.GenerateKey(password, folderPath, int.Parse(Regex.Match(ForAllUnits.KeySize, @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture), progressCallback);


                    // Return to UI thread to notify user and optionally open directory
                    this.Invoke(new Action(() =>
                    {
                        MessageBox.Show("PGP Keys generated successfully", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);
                        if (chkOpenfoldkeys.Checked) Process.Start("Explorer.exe", Path.GetDirectoryName(folderPath));
                    }));
                });
            }
            catch (Exception ex)
            {
                // Handle unexpected errors during generation and log them
                MessageBox.Show("Error during PGP keys generation! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "SETTINGS", "Error during PGP keys generation!");
            }
        }
        private void BtnDelFolder_Click(object sender, EventArgs e)
        {
            string folderToDelete = cmbFolderPath.Text.Trim();

            if (string.IsNullOrEmpty(folderToDelete))
                return;

            DialogResult result = MessageBox.Show("Are you sure you want to delete the selected folder? It may contain PGP keys!",
                                  ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (result != DialogResult.Yes)
                return;

            try
            {
                if (Directory.Exists(folderToDelete))
                {
                    FileAttributes attributes = File.GetAttributes(folderToDelete);

                    if ((attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                    {
                        File.SetAttributes(folderToDelete, FileAttributes.Normal);
                    }

                    Directory.Delete(folderToDelete, true);
                }

                // Remove from manager (this updates the txt file)
                foldersManager.RemoveFolder(folderToDelete);

                // Rebind (selection handled inside manager)
                foldersManager.BindToComboBox(cmbFolderPath);
                labNumkey.Text = cmbFolderPath.Items.Count.ToString();

                MessageBox.Show("Folder deleted successfully.", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error deleting folder! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "SETTINGS", "Error deleting folder!");
            }
        }
        private void CmbFolderPhat_TextChanged(object sender, EventArgs e)
        {
            HandleFolderUpdate();
        }
        private void CmbFolderPhat_SelectedIndexChanged(object sender, EventArgs e)
        {
            HandleFolderUpdate();
            labNumkey.Text = foldersManager.GetFolders().Count.ToString();
        }

        // Event that triggers the validation only when user leaves the ComboBox
        private void ChkHidden_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(cmbFolderPath.Text.Trim()) || !Directory.Exists(cmbFolderPath.Text.Trim()))
            {
                MessageBox.Show("The specified folder does not exist.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                chkHidden.Checked = false; // Reset checkbox
                return;
            }

            try
            {
                if (chkHidden.Checked)
                {
                    // Set folder as hidden
                    DirectoryInfo dirInfo = new DirectoryInfo(cmbFolderPath.Text.Trim());
                    dirInfo.Attributes |= FileAttributes.Hidden;
                    chkHidden.Text = "Hidden";
                }
                else
                {
                    // Remove hidden attribute
                    DirectoryInfo dirInfo = new DirectoryInfo(cmbFolderPath.Text.Trim());
                    dirInfo.Attributes &= ~FileAttributes.Hidden;
                    chkHidden.Text = "Visible";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error updating folder visibility! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "SETTINGS", "Error updating folder visibility!");
            }
        }
        private void ListFileload_DoubleClick(object sender, EventArgs e)
        {
            foreach (ListViewItem exploItem in listFileload.SelectedItems)
                if (File.Exists(ForAllUnits.DirPath + @"\SpeedBmk\" + exploItem.Text))
                {
                    txtFilepath.Text = ForAllUnits.DirPath + @"\SpeedBmk\" + exploItem.Text;
                    Passwbmk();
                }
            if (File.Exists(txtFilepath.Text))
            {
                FileInfo fileInfo = new FileInfo(txtFilepath.Text);
                labMb.Text = fileInfo.Strbytes();
            }
        }
        private void RdbGen_CheckedChanged(object sender, EventArgs e)
        {
            btnLoad.Enabled = false;
            listFileload.Enabled = rdbGen.Checked;
            labFoldgen.ForeColor = Color.Brown;
            listFileload.Focus();
        }
        private void RdbLoad_CheckedChanged(object sender, EventArgs e)
        {
            listFileload.Enabled = false;
            labFoldgen.ForeColor = Color.Gray;
            btnLoad.Enabled = rdbLoad.Checked;
            btnLoad.Focus();
        }
        private void Btnload_Click(object sender, EventArgs e)
        {
            // ENTERPRISE ARCHITECTURE: INSTANTIATE AN ISOLATED DIALOG TO PRESERVE COMPONENT ISOLATION AND AVOID STATE POLLUTION
            using (OpenFileDialog localFileDialog = new OpenFileDialog())
            {
                try
                {
                    // CONFIGURE ISOLATED METADATA AND VALIDATION CONTROLS FOR THE CURRENT RUNTIME CONTEXT
                    localFileDialog.Title = "Speedcrypt: Load File to Encrypt / Decrypt";
                    localFileDialog.CheckFileExists = true;

                    // OPEN SYSTEM DIALOG AND CAPTURE THE ENCAPSULATED USER ACTION
                    DialogResult fle = localFileDialog.ShowDialog();

                    if (fle == DialogResult.OK)
                    {
                        txtFilepath.Text = string.Empty;
                        labPassword.Text = txtFilepath.Text;
                        txtFilepath.Text = localFileDialog.FileName;
                        FileInfo fileInfo = new FileInfo(localFileDialog.FileName);

                        // EXECUTE STRUCT TO STRING EXTRACTION ON COMPACT METRICS
                        labMb.Text = fileInfo.Strbytes();
                    }
                }
                finally
                {
                    // EXECUTE POST-SELECTION INTEGRITY VERIFICATION PIPELINE WITHOUT INFLUENCING GLOBAL STATE
                    Passwbmk();
                }
            }

        }
        private async void BtnEncrypt_Click(object sender, EventArgs e)
        {
            // if the file does not exist
            if (!File.Exists(txtFilepath.Text))
            {
                MessageBox.Show("The file does not exist!", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (cmbCrypteng.Text == "PGP")
            {
                DialogResult result = MessageBox.Show("Are you sure you want to encrypt this file? Have you placed the PGP keys in the selected folder? Do you want to continue?",
                                                      ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (result == DialogResult.No)
                    return;
            }

            // if the keys do not exist
            if (cmbCrypteng.Text == "PGP" && !KeyPathValidator.Validate(cmbFolderPath.Text))
            {
                MessageBox.Show("Required PGP key files are missing. Operation aborted!", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // if the keys are registered in the configuration file
            if (cmbCrypteng.Text == "PGP" && btnGen.Enabled == false)
            {
                MessageBox.Show("You cannot use these PGP keys to perform the test. Operation aborted!", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            ForAllUnits.LwIcon = 0;
            _ENC_DEC = "Encrypt";
            Gensize();
            Keysize();
            Start();
            btnEncrypt.Enabled = false;
            btnCleartest.Enabled = false;

            await Encrypt();

            // Stop timer ONLY after successful encryption and message display
            timer1.Stop();
            timer1.Enabled = false;

            MessageBox.Show("File Encrypted successfully", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);

            if (chkLoadlistbmk.Checked) Addlistbmk();
            if (chkDisplaybmk.Checked && chkLoadlistbmk.Checked) tabControl1.SelectedIndex = 4;

            if (chkOpfldencdecbmk.Checked)
                Process.Start("Explorer.exe", "/select, \"" + Path.GetDirectoryName(txtFilepath.Text) + "\\" + Path.GetFileName(txtFilepath.Text) + ".SPCR" + "\"");

            if (chkDeloriginalbmk.Checked && File.Exists(txtFilepath.Text))
            {
                File.Delete(txtFilepath.Text);
                Folderfileload();
            }

            Folderfileload();
            Cleartest();
        }
        private async void BtnDecrypt_Click(object sender, EventArgs e)
        {
            if (!btnDecrypt.Enabled || !txtFilepath.Text.Contains(".SPCR") || !File.Exists(txtFilepath.Text))
            {
                MessageBox.Show("The file does not exist", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (cmbCrypteng.Text == "PGP" && !KeyPathValidator.Validate(cmbFolderPath.Text))
            {
                MessageBox.Show("Required PGP key files are missing. Operation aborted.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            ForAllUnits.LwIcon = 1;
            _ENC_DEC = "Decrypt";
            Gensize();
            Keysize();
            Start();
            btnDecrypt.Enabled = false;
            btnCleartest.Enabled = false;
            await Decrypt();

            // Stop timer ONLY after successful decryption and message display
            timer1.Stop();
            timer1.Enabled = false;

            if (ForAllUnits.DecSett == 0)
            {
                MessageBox.Show("File Decrypted successfully", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);

                Addlistbmk();
                if (chkDisplaybmk.Checked) tabControl1.SelectedIndex = 4;

                if (chkOpfldencdecbmk.Checked)
                    Process.Start("Explorer.exe", "/select, \"" + Path.GetDirectoryName(txtFilepath.Text) + "\\" + Path.GetFileNameWithoutExtension(txtFilepath.Text) + "\"");

                btnDecrypt.Enabled = false;

                if (chkDelencryptedbmk.Checked)
                {
                    if (!txtFilepath.Text.Contains("SPCR"))
                    {
                        if (File.Exists(txtFilepath.Text + ".SPCR")) File.Delete(txtFilepath.Text + ".SPCR");
                    }
                    else
                    {
                        if (File.Exists(txtFilepath.Text)) File.Delete(txtFilepath.Text);
                    }
                }
            }

            Folderfileload();
            Cleartest();
        }
        private void BtnCleartest_Click(object sender, EventArgs e)
        {
            Cleartest();
        }
        private void TxtFilepath_TextChanged(object sender, EventArgs e)
        {
            Enablencdec();
        }

        // Centralized error handling for folder updates
        void HandleFolderUpdate()
        {
            try
            {
                // Prevent overwriting active PGP keys
                ConfigPGPvalidator();
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "SETTINGS", "An error occurred while updating folder controls!");
            }
        }
        bool ValidateFolderPath(string folderPath)
        {
            folderPath = folderPath.Trim();

            // Strict check: drive letter + colon + backslash
            if (folderPath.Length < 3 || !char.IsLetter(folderPath[0]) || folderPath[1] != ':' || folderPath[2] != '\\')
            {
                MessageBox.Show("Folder path is invalid.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                cmbFolderPath.Focus();
                return false;
            }

            // Check if folder exists
            bool exists = false;
            try
            {
                exists = Directory.Exists(folderPath);
            }
            catch
            {
                exists = false;
            }

            if (!exists)
            {
                MessageBox.Show("Folder does not exist.", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                cmbFolderPath.Focus();
                return false;
            }

            // Folder exists: update buttons
            btnGen.Enabled = true;
            btnDelFolder.Enabled = true;
            btnFoldernew.Enabled = true; // keep enabled for new folder creation

            // Update Hidden checkbox
            try
            {
                FileAttributes attributes = File.GetAttributes(folderPath);
                chkHidden.Checked = (attributes & FileAttributes.Hidden) == FileAttributes.Hidden;
            }
            catch
            {
                chkHidden.Checked = false;
            }

            return true; // everything is OK
        }
        void UpdateDriveList()
        {
            try
            {
                cmbDrives.Items.Clear(); // Clear existing items
                DriveInfo[] drives = DriveInfo.GetDrives();
                foreach (DriveInfo drive in drives)
                {
                    if (drive.IsReady) // Only show available drives
                        cmbDrives.Items.Add(drive.Name);
                }

                if (_xmlConfig.Exists("Result.PGPKeyFolderPath"))
                {
                    string pgpPath = _xmlConfig.GetValue("Result.PGPKeyFolderPath").Trim();
                    if (!string.IsNullOrEmpty(pgpPath) && pgpPath.Length >= 3)
                    {
                        string driveLetter = pgpPath.Substring(0, 3);

                        // Safe selection without triggering SelectedIndexChanged twice
                        if (cmbDrives.Items.Contains(driveLetter))
                            cmbDrives.SelectedItem = driveLetter;

                        cmbFolderPath.Text = pgpPath; // Force exact folder path from config
                    }
                    cmbDrives.SelectedIndex = 0;
                }
                else
                {
                    if (cmbDrives.Items.Count > 0)
                        cmbDrives.SelectedIndex = 0; // Select first available drive
                }

                // Enable delete button only if folder exists
                btnDelFolder.Enabled = Directory.Exists(cmbFolderPath.Text);

                btnGen.Enabled = Directory.Exists(cmbFolderPath.Text);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "SETTINGS", "An error occurred while updating the Drive List!");
            }
        }
        void Enablencdec()
        {
            btnCleartest.Enabled = txtFilepath.Text != string.Empty;
            btnEncrypt.Enabled = txtFilepath.Text != string.Empty && File.Exists(txtFilepath.Text) && !txtFilepath.Text.Contains(".SPCR");
            btnDecrypt.Enabled = txtFilepath.Text != string.Empty && File.Exists(txtFilepath.Text) && txtFilepath.Text.Contains(".SPCR");
        }
        void Folderfileload()
        {
            FolderContentLoader.LoadFilesToListViewWithIcons(ForAllUnits.DirPath + @"\SpeedBmk\", listFileload, imageList3);
            FolderContentLoader.LoadFilesToListViewWithIcons(ForAllUnits.DirPath + @"\SpeedBmk\", listFileloaddel, imageList3);
        }
        void Cleartest()
        {
            txtFilepath.Text = string.Empty;
            labPassword.Text = txtFilepath.Text;
            btnEncrypt.Enabled = false;
            btnDecrypt.Enabled = btnEncrypt.Enabled;
            btnCleartest.Enabled = btnEncrypt.Enabled;
            labMb.Text = string.Empty;
            labTime.Text = "00.00:00:000";
        }
        void Addlistbmk()
        {
            listBmk.ShowSubItemIcons(true);
            listBmk.View = View.Details;
            ListViewItem item = new ListViewItem();
            DateTime thisDay = DateTime.Now;
            item.ImageIndex = ForAllUnits.LwIcon;
            if (tabControl1.SelectedIndex == 1)
            {
                item.SubItems.Add(cmbCrypteng.Text);
                item.SubItems.Add(_ENC_DEC.ToUpper());
                item.SubItems.Add(labMb.Text);
            }
            else
            if (tabControl1.SelectedIndex == 3)
            {
                item.SubItems.Add(cmbAlgodel.Text);
                item.SubItems.Add("DELETION");
                item.SubItems.Add(labKb.Text);
            }

            item.SubItems.Add(labTime.Text);
            item.SubItems.Add(thisDay.ToString("g"));
            listBmk.Items.Add(item);
            listBmk.AddIconToSubitem(listBmk.Items.Count - 1, 4, 2);// 4 = column 1 = icons

            // Toggle the row color
            if (chkAlternate.Checked) _alternator.Enable();

            // Enable the Save Button
            _dirtyTracker.MarkDirty();

            // Enable the panel
            labFilter.Text = listBmk.Items.Count.ToString();
            pnlList.Enabled = true;
        }
        void Start()
        {
            labTime.Text = "00.00.00.000";
            timer1.Enabled = true;
            ForAllUnits.Start = DateTime.Now;
            timer1.Start();
        }
        void Keysize()
        {
            switch (cmbCrypteng.SelectedIndex)
            {
                case 0:
                    {
                        ForAllUnits.KeySize = cmbAeskeysize.Text;
                        break;
                    }
                case 1:
                    {
                        ForAllUnits.KeySize = cmbRsaKeysize.Text;
                        break;
                    }
                case 2:
                    {
                        ForAllUnits.KeySize = labIdea.Text;
                        break;
                    }
                case 3:
                    {
                        ForAllUnits.KeySize = labGost.Text;
                        break;
                    }
                case 4:
                    {
                        ForAllUnits.KeySize = labAesgcm.Text;
                        break;
                    }
                case 5:
                    {
                        ForAllUnits.KeySize = cmbSepentkeysize.Text;
                        break;
                    }
                case 6:
                    {
                        ForAllUnits.KeySize = cmbTwofishkeysize.Text;
                        break;
                    }
                case 7:
                    {
                        ForAllUnits.KeySize = cmbCamelliakeysize.Text;
                        break;
                    }
                case 8:
                    {
                        ForAllUnits.KeySize = cmbThreefishkeysize.Text;
                        break;
                    }
                case 9:
                    {
                        ForAllUnits.KeySize = labKuznyechik.Text;
                        break;
                    }
                case 10:
                    {
                        ForAllUnits.KeySize = labXchacha20.Text;
                        break;
                    }
            }
        }
        void Gensize()
        {
            if (rdbGen.Checked)
            {
                if (rdb1MB.Checked) _MB_SIZE = rdb1MB.Text;
                else
                if (rdb10MB.Checked) _MB_SIZE = rdb10MB.Text;
                else
                if (rdb100MB.Checked) _MB_SIZE = rdb100MB.Text;
                else
                if (rdb500MB.Checked) _MB_SIZE = rdb500MB.Text;
                else
                if (rdbCustom.Checked) _MB_SIZE = numCustomSize.Text + "MB";
            }
        }
        async Task Encrypt()
        {
            await Task.Run(() =>
            {
                if (cmbCrypteng.SelectedIndex == 1)
                {
                    PgpEncryptor.EncryptFile(txtFilepath.Text, txtFilepath.Text + ".SPCR", cmbFolderPath.Text + @"\PGPPublicKeyRSA.asc");
                }
                else
                    // Enforce InvariantCulture to ensure the correct cryptographic key size is parsed regardless of the host locale
                    EncryptionManager.EncryptFile(txtFilepath.Text, txtFilepath.Text, Encoding.UTF8.GetBytes(labPassword.Text),
                                                  int.Parse(Regex.Match(ForAllUnits.KeySize, @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture),
                                                  cmbCrypteng.SelectedItem.ToString());
            });
        }
        async Task Decrypt()
        {
            await Task.Run(() =>
            {
                if (cmbCrypteng.SelectedIndex == 1)
                {
                    Blake256 blake = new Blake256();
                    string hashString = BitConverter.ToString(blake.ComputeHash(Encoding.UTF8.GetBytes("Speedcrypt BenchMark"))).ToLower().Replace("-", "");
                    char[] password = hashString.ToCharArray();

                    if (!txtFilepath.Text.Contains(".SPCR"))
                    {
                        PgpDecryptor.DecryptFile(
                            txtFilepath.Text + ".SPCR",
                            txtFilepath.Text,
                            cmbFolderPath.Text + @"\PGPPrivateKeyRSA.asc",
                            password
                        );
                    }
                    else
                    {
                        PgpDecryptor.DecryptFile(
                            txtFilepath.Text,
                            txtFilepath.Text.Replace(".SPCR", ""),
                            cmbFolderPath.Text + @"\PGPPrivateKeyRSA.asc",
                            password
                        );
                    }
                }
                else
                {
                    if (!txtFilepath.Text.Contains(".SPCR"))
                    {
                        // Enforce InvariantCulture to handle standard key size parsing during fallback decryption
                        EncryptionManager.DecryptFile(txtFilepath.Text + ".SPCR", txtFilepath.Text, Encoding.UTF8.GetBytes(labPassword.Text),
                                                      int.Parse(Regex.Match(ForAllUnits.KeySize, @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture),
                                                      cmbCrypteng.SelectedItem.ToString());
                    }
                    else
                    {
                        // Enforce InvariantCulture to handle standard key size parsing when file already contains the extension
                        EncryptionManager.DecryptFile(txtFilepath.Text, txtFilepath.Text.Replace(".SPCR", ""), Encoding.UTF8.GetBytes(labPassword.Text),
                                                      int.Parse(Regex.Match(ForAllUnits.KeySize, @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture),
                                                      cmbCrypteng.SelectedItem.ToString());
                    }
                }
            });
        }
        void Passwbmk()
        {
            Blake256 blake = new Blake256();
            labPassword.Text = BitConverter.ToString(blake.ComputeHash(Encoding.UTF8.GetBytes("Speedcrypt BenchMark"))).ToLower().Replace("-", "");

        }
        void ConfigPGPvalidator()
        {
            // Evaluates if the path has a valid root structure, is not a bare drive root, and does not exist yet
            btnFoldernew.Enabled = !string.IsNullOrWhiteSpace(cmbFolderPath.Text) &&
                                   Path.IsPathRooted(cmbFolderPath.Text) &&
                                   cmbFolderPath.Text.Contains(Path.DirectorySeparatorChar.ToString()) &&
                                   !Directory.Exists(cmbFolderPath.Text) &&
                                   cmbFolderPath.Text.Length > 3;

            btnGen.Enabled = Directory.Exists(cmbFolderPath.Text) && cmbFolderPath.Text.Length > 3; ;
            btnDelFolder.Enabled = btnGen.Enabled;
            // --- NEW: Check if path is already in configuration ---
            PgpPathValidator pgpValidator = new PgpPathValidator();
            if (!string.IsNullOrEmpty(cmbFolderPath.Text.Trim()) && pgpValidator.IsValid(cmbFolderPath.Text.Trim()))
            {
                // Inform the user in the ComboBox tooltip
                cmbFolderPath.Tag = "This folder already contains PGP engine keys in the configuration!";
                _tt.Set(cmbFolderPath, "This folder already contains PGP engine keys in the configuration!");
                btnGen.Enabled = false; // Prevent generating keys for existing paths
                btnDelFolder.Enabled = btnGen.Enabled;
            }
            else
            {
                cmbFolderPath.Tag = null; // Clear tooltip if not in config
                _tt.Set(cmbFolderPath, "Select the appropriate folder where you want to create the PGP key");
            }

            // Update Hidden checkbox
            try
            {
                FileAttributes attributes = File.GetAttributes(cmbFolderPath.Text);
                if (Directory.Exists(cmbFolderPath.Text) && cmbFolderPath.Text.Length > 3)
                    chkHidden.Checked = (attributes & FileAttributes.Hidden) == FileAttributes.Hidden;
            }
            catch
            {
                chkHidden.Checked = false;
            }
        }
        void Comboreb()
        {
            try
            {
                cmbFolderPath.Text = string.Empty;
                if (cmbFolderPath.Items.Count > 0)
                    cmbFolderPath.SelectedIndex = 0;
                cmbFolderPath.Focus();
            }
            catch
            {
                // Suppress and absorb all exceptions silently within this context to prevent execution halting.
                // Forcing 'SelectedIndex = 0' can deterministically trigger synchronous cascade events (e.g., SelectedIndexChanged),
                // which may introduce unstable UI states or race conditions if items collection mutation occurs simultaneously.
                // High-isolation fail-silent pattern ensures the main processing pipeline of Speedcrypt remains entirely unimpeded.
            }
        }
        void InactivePGP()
        {
            if (cmbCrypteng.Text.IndexOf("PGP", StringComparison.OrdinalIgnoreCase) >= 0)
                return;

            if (!IsValidDrivePath(cmbFolderPath.Text))
            {
                if (cmbFolderPath.Items.Count > 0)
                    cmbFolderPath.SelectedIndex = 0;
                else
                    cmbFolderPath.Text = string.Empty;
            }
        }
        bool IsValidDrivePath(string folderPath)
        {
            if (string.IsNullOrWhiteSpace(folderPath))
                return false;

            if (!Path.IsPathRooted(folderPath))
                return false;

            string root = Path.GetPathRoot(folderPath);

            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
                return false;

            return true;
        }

        #endregion Encryption Engines

        #region HASH Engines
        private void BtnSaltTest_Click(object sender, EventArgs e)
        {
            btnSaltTest.Enabled = false;
            Saltgenerate();
            btnCanc.Enabled = true;
            btnSaltTest.Enabled = true;
            btnSaltTest.Focus();
        }
        private void BtnSaltTest_MouseLeave(object sender, EventArgs e)
        {
            txtSalt.BackColor = Color.White;
        }
        private void BtnSaltTest_MouseMove(object sender, MouseEventArgs e)
        {
            txtSalt.BackColor = Color.Yellow;
        }
        private void BtnStringval_Click(object sender, EventArgs e)
        {
            byte[] val = new byte[32];
            new SecureRandom().NextBytes(val);
            txtHashInput.Text = Convert.ToBase64String(val).Replace("=", "");

            if (rdbAll.Checked)
                txtHashInput.Text = txtHashInput.Text;
            else if (rdbNumber.Checked)
                txtHashInput.Text = new string(txtHashInput.Text.Where(char.IsDigit).ToArray());
            else if (rdbChr.Checked)
                txtHashInput.Text = new string(txtHashInput.Text.Where(char.IsLetter).ToArray());
            btnCanc.Enabled = true;
        }
        private void BtnStringval_MouseLeave(object sender, EventArgs e)
        {
            txtHashInput.BackColor = Color.White;
        }
        private void BtnStringval_MouseMove(object sender, MouseEventArgs e)
        {
            txtHashInput.BackColor = Color.Yellow;
        }
        private void TxtSalt_TextChanged(object sender, EventArgs e)
        {
            labSaltstr.Text = txtSalt.Text.Length.ToString();
            // Enforce InvariantCulture for both parsing and string conversion to ensure cross-region arithmetic consistency
            labKeysaltstr.Text = (int.Parse(labKeystr.Text, System.Globalization.CultureInfo.InvariantCulture) + int.Parse(labSaltstr.Text,
                                  System.Globalization.CultureInfo.InvariantCulture)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        private void TxtSalt_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtSalt.ContextMenuStrip = cms;
            }
        }
        private void BtnHashtest_Click(object sender, EventArgs e)
        {
            bool isHashValid =
            cmbHash.SelectedIndex >= 41 &&
            cmbHash.SelectedIndex <= 47;

            bool isSaltValid =
               cmbSalt.SelectedIndex == 1;

            if (isHashValid || isSaltValid)
            {
                ablebut();
            }

            string salt = string.Empty;
            Scrparam();
            Argonparam();
            Stopwatch sw = Stopwatch.StartNew();
            // Enforce InvariantCulture to read user-defined PBKDF2 iterations safely across all Windows regional settings
            HASHLib.pbkdf2iterations = int.Parse(txtPbkIter.Text, System.Globalization.CultureInfo.InvariantCulture);

            _HASH_TEST = txtHashInput.Text;

            if (!chkNosalt.Checked)
            {
                Saltgenerate();
                if (cmbHash.SelectedIndex == 3 || cmbHash.SelectedIndex == 4 || cmbHash.SelectedIndex == 5)
                {
                    _SALT_TEST = _SALT_TEST.Substring(0, 16);
                    txtSalt.Text = _SALT_TEST;
                }
                _HASH_TEST = _SALT_TEST + _HASH_TEST;
            }

            string hashOutput = string.Empty;
            bool toBase64 = rdbBase64.Checked;
            bool upperCase = rdbHexUpper.Checked;

            try
            {
                switch (cmbHash.SelectedIndex)
                {
                    case 0: // Bcrypt
                        {
                            // Enforce InvariantCulture to ensure Bcrypt rounds are parsed correctly from the UI selection across all locales
                            int rounds = int.Parse(Regex.Match(cmbBcrRound.SelectedItem.ToString(), @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture);

                            byte[] saltBytes = BCryptBouncy.BcryptSalt();
                            txtSalt.Text = Convert.ToBase64String(saltBytes);
                            if (txtHashInput.TextLength < 73)
                                hashOutput = BCryptBouncy.ComputeBcrypt(txtHashInput.Text, saltBytes, rounds);
                            else
                                if (txtHashInput.TextLength > 72)
                                hashOutput = BCryptBouncy.ComputeBcrypt(txtHashInput.Text.Substring(0, 72), saltBytes, rounds);
                            break;
                        }
                    case 1: // Scrypt
                        {
                            // Fixed password for test
                            byte[] passwordBytes = Encoding.UTF8.GetBytes("Speedcrypt");

                            // Compute salt once, either empty or from _SALT_TEST
                            byte[] saltBytes = (!chkNosalt.Checked && !string.IsNullOrEmpty(_SALT_TEST))
                                                ? Encoding.UTF8.GetBytes(_SALT_TEST)
                                                : Array.Empty<byte>();

                            // Compute Scrypt using HASHLib
                            byte[] scryptOutput = HASHLib.ComputeScrypt(passwordBytes, saltBytes);

                            // Convert output according to user selection
                            if (rdbBase64.Checked)
                            {
                                hashOutput = Convert.ToBase64String(scryptOutput);
                            }
                            else
                            {
                                string hex = BitConverter.ToString(scryptOutput).Replace("-", "");
                                hashOutput = rdbHexUpper.Checked ? hex.ToUpper() : hex.ToLower();
                            }

                            // Clear sensitive buffers
                            Array.Clear(passwordBytes, 0, passwordBytes.Length);
                            Array.Clear(saltBytes, 0, saltBytes.Length);
                            Array.Clear(scryptOutput, 0, scryptOutput.Length);

                            break;
                        }
                    case 41: hashOutput = ComputeHMAC("SHA1"); break;
                    case 42: hashOutput = ComputeHMAC("MD5"); break;
                    case 43: hashOutput = ComputeHMAC("SHA256"); break;
                    case 44: hashOutput = ComputeHMAC("SHA384"); break;
                    case 45: hashOutput = ComputeHMAC("SHA512"); break;
                    case 46: hashOutput = ComputeHMAC("RIPEMD160"); break;
                    case 47: // PBKDF2
                        hashOutput = HASHLib.GeneratePBKDF2Hash(Encoding.UTF8.GetBytes(_HASH_TEST), "", HASHLib.pbkdf2iterations, 32, toBase64);
                        break;
                    default: // Other hash
                        hashOutput = HASHLib.ComputeHash(_HASH_TEST, cmbHash.SelectedItem.ToString());
                        break;
                }

                sw.Stop();
                TimeSpan ts = sw.Elapsed;
                string elapsedTime = string.Format("{0:00}:{1:00}:{2:00}", ts.Minutes, ts.Seconds, ts.Milliseconds);

                string formattedHash = toBase64 ? Convert.ToBase64String(Encoding.Default.GetBytes(hashOutput))
                                       : (upperCase ? string.Concat(hashOutput.Select(c => char.ToUpper(c)))
                                                   : string.Concat(hashOutput.Select(c => char.ToLower(c))));

                labHashstr.Text = hashOutput.Length.ToString();

                // Block formatting
                string hashName = cmbHash.SelectedItem.ToString();
                string prefix = hashName.PadRight(10) + ": ";
                string indent = new string(' ', prefix.Length);
                StringBuilder resultBuilder = new StringBuilder();
                int blockSize = (int)numIndent.Value;
                int countBlocksPerLine = (int)numTextblock.Value;
                int blocksInLine = 0;
                bool isFirstLine = true;

                for (int i = 0; i < formattedHash.Length; i += blockSize)
                {
                    int length = Math.Min(blockSize, formattedHash.Length - i);
                    string block = formattedHash.Substring(i, length);

                    if (isFirstLine) { resultBuilder.Append(prefix); isFirstLine = false; }
                    resultBuilder.Append(block);
                    blocksInLine++;

                    if (blocksInLine % countBlocksPerLine == 0 && (i + length) < formattedHash.Length)
                    {
                        resultBuilder.AppendLine();
                        resultBuilder.Append(indent);
                        blocksInLine = 0;
                    }
                    else if ((i + length) < formattedHash.Length)
                    {
                        resultBuilder.Append(" ");
                    }
                }

                rchHashresult.Text = chkElapsed.Checked ? resultBuilder.ToString() + " " + elapsedTime : resultBuilder.ToString();
            }
            catch (Exception ex)
            {
                // Silent Exception
                CentralLog.LogException(ex, "SETTINGS", "An error occurred during hash testing!");
            }
            finally
            {
                if (chkHighlight.Checked) Hashcolor();
                btnHashTest.Enabled = true;
                btnSaltTest.Enabled = true;
                btnStringval.Enabled = true;
                if (cmbHash.SelectedIndex != 0) chkNosalt.Enabled = true;
                btnCanc.Enabled = true;
                btnHashTest.Focus();
            }

            string ComputeHMAC(string type)
            {
                // If the password is null or empty, use fixedPassword; otherwise, use the real one (_HASH_TEST).
                byte[] pbText = string.IsNullOrEmpty(_HASH_TEST)
                                ? (byte[])HASHLib.fixedPassword.Clone()
                                : Encoding.Default.GetBytes(_HASH_TEST);

                // If chkNosalt is checked, use an empty salt; otherwise, use txtSalt.
                byte[] saltBytes = chkNosalt.Checked
                                   ? new byte[0]
                                   : Encoding.Default.GetBytes(txtSalt.Text);

                byte[] result = null;

                switch (type.ToUpperInvariant())
                {
                    case "SHA1": result = HASHLib.HMACSHA1(pbText, saltBytes); break;
                    case "MD5": result = HASHLib.HMACMD5(pbText, saltBytes); break;
                    case "SHA256": result = HASHLib.HMACSHA256(pbText, saltBytes); break;
                    case "SHA384": result = HASHLib.HMACSHA384(pbText, saltBytes); break;
                    case "SHA512": result = HASHLib.HMACSHA512(pbText, saltBytes); break;
                    case "RIPEMD160": result = HASHLib.HMACRIPEMD160(pbText, saltBytes); break;
                }

                // Sensitive buffer cleanup
                if (pbText != null) Array.Clear(pbText, 0, pbText.Length);
                if (saltBytes != null) Array.Clear(saltBytes, 0, saltBytes.Length);

                return BitConverter.ToString(result).Replace("-", "").ToLower();
            }
        }
        private void TxtKey_TextChanged(object sender, EventArgs e)
        {
            btnHashTest.Enabled = txtHashInput.Text != string.Empty;
            labKeystr.Text = txtHashInput.Text.Length.ToString();
            // Enforce InvariantCulture for both parsing and string conversion to ensure cross-region arithmetic consistency
            labKeysaltstr.Text = (int.Parse(labKeystr.Text, System.Globalization.CultureInfo.InvariantCulture) +
                                  int.Parse(labSaltstr.Text, System.Globalization.CultureInfo.InvariantCulture)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        private void TxtKey_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtHashInput.ContextMenuStrip = cms;
            }
        }
        private void BtnCanc_Click(object sender, EventArgs e)
        {
            rchHashresult.Clear();
            txtSalt.Text = string.Empty;
            txtHashInput.Text = txtSalt.Text;
            labHashstr.Text = "0";
            btnCanc.Enabled = false;
        }
        private void TxtArgMem_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtArgMem.ContextMenuStrip = cms;
            }
        }
        private void TxtArgParal_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtArgParal.ContextMenuStrip = cms;
            }
        }
        private void TxtArgIter_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtArgIter.ContextMenuStrip = cms;
            }
        }
        private void TxtScrMem_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtScrMem.ContextMenuStrip = cms;
            }
        }
        private void TxtPbkdf2round_KeyPress(object sender, KeyPressEventArgs e)
        {
            e.Handled = (!char.IsDigit(e.KeyChar) && !char.IsControl(e.KeyChar));
        }
        private void TxtPbkdf2round_Leave(object sender, EventArgs e)
        {
            if (!int.TryParse(txtPbkdf2round.Text, out int rounds) || rounds < 100000)
            {
                txtPbkdf2round.Text = "100000"; // enforce minimum safe rounds
            }
        }
        private void TxtScrParal_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtScrParal.ContextMenuStrip = cms;
            }
        }
        private void TxtScrBksz_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtScrBksz.ContextMenuStrip = cms;
            }
        }
        private void TxtPbkIter_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtPbkIter.ContextMenuStrip = cms;
            }
        }
        private void RchHashresult_TextChanged(object sender, EventArgs e)
        {
            btnCanc.Enabled = rchHashresult.Text != string.Empty;
        }
        private void CmbHash_SelectedIndexChanged(object sender, EventArgs e)
        {
            bool isBcrypt = cmbHash.SelectedIndex == 0;

            if (cmbSalt.SelectedIndex != 0)
                picBic.Image = ForAllUnits.Ledred16;

            picPbk.Image = ForAllUnits.Ledred16;
            picHkdf.Image = ForAllUnits.Ledred22;

            chkNosalt.Enabled = !isBcrypt;

            switch (cmbHash.SelectedIndex)
            {
                case 0:
                    {
                        cmbSalt.Enabled = false; // disable SALT for BCRYPT
                        chkNosalt.Enabled = false;
                        cmbSalt.SelectedIndex = 0;
                        picBic.Image = ForAllUnits.Ledgreen16;
                        break;
                    }

                case 41:
                case 42:
                case 43:
                case 44:
                case 45:
                case 46:
                case 47:
                    {
                        cmbSalt.Enabled = true;
                        chkNosalt.Enabled = true;
                        picPbk.Image = ForAllUnits.Ledgreen16;
                        picHkdf.Image = ForAllUnits.Ledgreen22;
                        break;
                    }

                default:
                    {
                        cmbSalt.Enabled = true;
                        break;
                    }
            }

            HashSecurityStrength.UpdateUIFromCombo(cmbHash, labHashScore, labHashRec, qualityProgressBar2);
        }
        private void CmbSalt_SelectedIndexChanged(object sender, EventArgs e)
        {
            grbGen.Enabled = false;

            if (cmbHash.SelectedIndex != 0)
                picBic.Image = ForAllUnits.Ledred16;
            switch (cmbSalt.SelectedIndex)
            {
                case 0:
                    {
                        picBic.Image = ForAllUnits.Ledgreen16;
                        //grbOutputsalt.Enabled = false;
                        break;
                    }
                case 2:
                case 3:
                case 4:
                    grbGen.Enabled = true;
                    break;
            }
        }
        void ablebut()
        {
            btnHashTest.Enabled = false;
            btnSaltTest.Enabled = false;
            btnStringval.Enabled = false;
            btnCanc.Enabled = false;
            chkNosalt.Enabled = false;
        }
        void Argonparam()
        {
            // Enforce InvariantCulture to read user-defined Argon2 parameters safely across all regional settings
            HASHLib.memoryCost = int.Parse(txtArgMem.Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.iterations = int.Parse(txtArgIter.Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.parallelism = int.Parse(txtArgParal.Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.hashSize = int.Parse(Regex.Match(cmbArgsize.SelectedItem.ToString(), @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture);
        }
        void Scrparam()
        {
            // Enforce InvariantCulture to read user-defined Scrypt parameters safely across all regional settings
            HASHLib.srcmem = int.Parse(txtScrMem.Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.scrblksz = int.Parse(txtScrBksz.Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.scrparal = int.Parse(txtScrParal.Text, System.Globalization.CultureInfo.InvariantCulture);
            HASHLib.scrhashsz = int.Parse(Regex.Match(cmbScrypsize.SelectedItem.ToString(), @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture);
        }
        void LoadPbkdf2round()
        {
            _xmlConfig = AppConfigHelper.XmlConfig;
            string keyStr = "100000"; // default value

            switch (cmbStringcrypto.SelectedIndex)
            {
                case 0:
                    keyStr = _xmlConfig.GetValue("Result.FRSAES-CGMStrCrp") ?? "100000";
                    break;
                case 1:
                    keyStr = _xmlConfig.GetValue("Result.SERPENTStrCrp") ?? "100000";
                    break;
                case 2:
                    keyStr = _xmlConfig.GetValue("Result.TWOFISHStrCrp") ?? "100000";
                    break;
                case 3:
                    keyStr = _xmlConfig.GetValue("Result.THREEFISHStrCrp") ?? "100000";
                    break;
                case 4:
                    keyStr = _xmlConfig.GetValue("Result.SECXCHACHA20StrCrp") ?? "100000";
                    break;
                case 5:
                    keyStr = _xmlConfig.GetValue("Result.XCHACHA20POLY1305StrCrp") ?? "100000";
                    break;
                case 6:
                    keyStr = _xmlConfig.GetValue("Result.AESStrCrp") ?? "100000";
                    break;
            }

            txtPbkdf2round.Text = string.IsNullOrEmpty(keyStr) ? "100000" : keyStr;
        }
        void PBKDF2led()
        {
            bool isKdf = cmbHash.SelectedIndex >= 41 && cmbHash.SelectedIndex <= 47;

            // 16x16 LED
            picPbk.Image = isKdf
                ? ForAllUnits.Ledgreen16
                : ForAllUnits.Ledred16;

            // 22x22 LED
            picHkdf.Image = isKdf
                ? ForAllUnits.Ledgreen22
                : ForAllUnits.Ledred22;
        }
        void Hashcolor()
        {
            // Lock the layout to avoid flickering
            rchHashresult.SuspendLayout();

            // Reset all to basic style
            rchHashresult.SelectAll();
            rchHashresult.SelectionBackColor = rchHashresult.BackColor;
            rchHashresult.SelectionColor = rchHashresult.ForeColor;
            rchHashresult.SelectionFont = rchHashresult.Font;

            // Highlight only the first line up to and including the first ":"
            if (rchHashresult.Lines.Length > 0)
            {
                string firstLine = rchHashresult.Lines[0];
                int colonIndex = firstLine.IndexOf(":");
                if (colonIndex != -1)
                {
                    rchHashresult.SelectionStart = 0;
                    rchHashresult.SelectionLength = colonIndex + 1;
                    rchHashresult.SelectionBackColor = Color.Yellow;
                }
            }
            // Search for the time in all lines (with both ":" and ".")
            string fullText = rchHashresult.Text;
            MatchCollection timeMatches = Regex.Matches(fullText, @"\d{2}[:.]\d{2}[:.]\d{2,3}");

            foreach (Match timeMatch in timeMatches)
            {
                // If we find a match for the time
                int timeStartIndex = fullText.IndexOf(timeMatch.Value);
                if (timeStartIndex != -1)
                {
                    rchHashresult.SelectionStart = timeStartIndex;
                    rchHashresult.SelectionLength = timeMatch.Value.Length;
                    rchHashresult.SelectionColor = Color.RoyalBlue;//Color.FromArgb(72, 118, 255);
                    rchHashresult.SelectionFont = new Font(rchHashresult.Font, FontStyle.Regular);
                }
            }

            // Reactivate the layout
            rchHashresult.ResumeLayout();
        }
        void Saltgenerate()
        {
            byte[] saltBytes;
            int rounds = 10; // Default BCRYPT rounds
            bool numericMode = rdbNumb.Checked;
            string saltType = "CRIPTO_RANDOM";

            // Determine SALT type from ComboBox
            if (cmbSalt.SelectedIndex == 0)
                saltType = "BCRYPT";
            else if (cmbSalt.SelectedIndex == 1)
                saltType = "FORTUNA";
            else if (cmbSalt.SelectedIndex == 2)
                saltType = numericMode ? "AES_CTR_DRB" : "AES_CTR_DRB_SEQ";
            else if (cmbSalt.SelectedIndex == 3)
                saltType = numericMode ? "CRIPTO_RANDOM" : "CRIPTO_RANDOM_SEQ";
            else if (cmbSalt.SelectedIndex == 4)
                saltType = numericMode ? "BLUMBLUM" : "BLUMBLUM_SEQ";

            // Get rounds if BCRYPT is selected
            if (saltType == "BCRYPT")
                // Enforce InvariantCulture to ensure Bcrypt rounds are parsed correctly from the UI selection across all locales
                rounds = int.Parse(Regex.Match(cmbBcrRound.SelectedItem.ToString(), @"\d+").Value, System.Globalization.CultureInfo.InvariantCulture);

            // Generate SALT using centralized manager
            saltBytes = SaltManager.GenerateSalt(saltType, rounds, numericMode);

            // Format SALT according to selected RadioButton
            if (rdbBase64salt.Checked)
                _SALT_TEST = Convert.ToBase64String(saltBytes).Replace("=", "");
            else if (rdbHexLowersalt.Checked)
                _SALT_TEST = BitConverter.ToString(saltBytes).Replace("-", "").ToLower();
            else if (rdbHexUppersalt.Checked)
                _SALT_TEST = BitConverter.ToString(saltBytes).Replace("-", "").ToUpper();

            // Update TextBox
            txtSalt.Text = _SALT_TEST;

            // Clear internal buffer
            SaltManager.SecureErase(); // Not necessary
        }

        #endregion HASH Engines

        #region Secure Deletion
        private void CmbAlgodel_SelectedIndexChanged(object sender, EventArgs e)
        {
            Selection();
        }
        private void CmbCustom_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (listCustom.Items.Count < 8) listCustom.Items.Add(cmbCustom.SelectedItem.ToString());

            Custombut(true);

            if (listCustom.Items.Count == 8) btnRepeatval.Enabled = false;

            Enabledelbut();

            evaluator.UpdateStrength();
        }
        private void ListCustom_Click(object sender, EventArgs e)
        {
            if (listCustom.Items.Count > 0) btnClearval.Enabled = true;
        }
        private void BtnRepeatval_Click(object sender, EventArgs e)
        {
            if (listCustom.Items.Count < 8) listCustom.Items.Add(cmbCustom.SelectedItem.ToString());

            if (listCustom.Items.Count == 8) btnRepeatval.Enabled = false;

            evaluator.UpdateStrength();

            Enabledelbut();
        }
        private void BtnClearval_Click(object sender, EventArgs e)
        {
            // Check if an item is currently selected
            if (listCustom.SelectedItem != null)
            {
                // Capture the current selection index before removal
                int currentIndex = listCustom.SelectedIndex;

                // Remove the selected item from the collection
                listCustom.Items.Remove(listCustom.SelectedItem);

                // UI State management based on remaining items count
                if (listCustom.Items.Count == 0)
                {
                    Custombut(false);
                    btnClearval.Enabled = false;
                    qualityProgressBar1.Value = 0;
                    labValue.Text = "Score";

                    // Trigger baseline cleanup for the UI layout
                    Enabledelbut();

                    // Critical: Exit early to prevent evaluator.UpdateStrength() from overwriting "Score"
                    return;
                }
                else
                {
                    // Enforce upper bound constraints for evaluation scaling
                    if (listCustom.Items.Count < 8)
                    {
                        btnRepeatval.Enabled = true;
                    }

                    // Dynamically reposition the selection focus to the next available item
                    if (currentIndex >= listCustom.Items.Count)
                    {
                        // If the deleted item was the last one, focus on the new trailing item
                        listCustom.SelectedIndex = listCustom.Items.Count - 1;
                    }
                    else
                    {
                        // Otherwise, maintain focus on the same index position (the next item shifts up)
                        listCustom.SelectedIndex = currentIndex;
                    }

                    // Ensure the deletion button state aligns with the new selection index
                    btnClearval.Enabled = (listCustom.SelectedIndex > -1);
                }

                // Trigger cascade UI updates and cryptographic evaluations only for non-empty lists
                Enabledelbut();
                evaluator.UpdateStrength();
            }
            else
            {
                // Enforce safe fallback state if execution is triggered without a valid selection
                btnClearval.Enabled = false;
            }
        }
        private void BtnAlgodel_Click(object sender, EventArgs e)
        {
            listCustom.Items.Clear();

            var sug = PassSuggestionEngine.GetSuggestedAlgorithm();

            foreach (var elem in sug)
            {
                listCustom.Items.Add(elem);
            }

            btnClearlistval.Enabled = true;
            btnSaveval.Enabled = btnClearlistval.Enabled;

            evaluator.UpdateStrength();

            Enabledelbut();
        }
        private void BtnSaveval_Click(object sender, EventArgs e)
        {
            // Enforce defensive validation on active collection state before allocating file dialog resources
            if (listCustom.Items.Count > 0)
            {
                using (SaveFileDialog sfd = new SaveFileDialog())
                {
                    sfd.Filter = "Text Files (*.txt)|*.txt";
                    sfd.Title = "Speedcrypt: Save custom list.";
                    sfd.FileName = "Custom Algorithm";

                    if (sfd.ShowDialog() == DialogResult.OK)
                    {
                        // Execute structural serialization directly from the localized dialog scope
                        CustomAlgorithmPersistence.ExportToStructuredFile(sfd.FileName, listCustom.Items);

                        MessageBox.Show("Algorithm saved successfully.", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
        }
        private void BtnLoadval_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Filter = "Text Files (*.txt)|*.txt";
                ofd.Title = "Speedcrypt: Load custom list.";

                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    // Execute safe asynchronous ingestion directly bypassing unnecessary method redirection
                    bool success = CustomAlgorithmPersistence.ImportAndValidateStructuredFile(ofd.FileName, listCustom);

                    if (success)
                    {
                        evaluator.UpdateStrength();
                        btnSaveval.Enabled = true;
                        btnClearlistval.Enabled = true;
                        //MessageBox.Show("Algorithm loaded successfully.", ForAllUnits.BoxSuc, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        // Gracefully reject corrupt or spoofed payloads to preserve runtime graphical stability
                        MessageBox.Show("Invalid or corrupt Speedcrypt Custom file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }
        private void BtnClearlistval_Click(object sender, EventArgs e)
        {
            // Set the safety lock flag to prevent cascading UI messages during cleanup
            _isClearingList = true;

            try
            {
                listCustom.Items.Clear();
                btnSaveval.Enabled = false;
                labValue.Text = "Score";
                qualityProgressBar1.Value = 0;
                Custombut(false);
                Enabledelbut();
            }
            finally
            {
                // Always release the safety lock flag in the finally block
                _isClearingList = false;
            }
        }
        private void RdbCust1_CheckedChanged(object sender, EventArgs e)
        {
            // Synchronize control states dynamically when the classic mode selection changes
            Enabledelbut();
        }
        private void RdbCust2_Click(object sender, EventArgs e)
        {
            // Trigger baseline control synchronization for the deletion interface
            Enabledelbut();

            // STUPID-PROOF SHIELD: Intercept execution if the programmatic cleanup routine is active
            if (_isClearingList) return;

            // Check if the user-defined algorithm list is currently unpopulated
            if (listCustom.Items.Count == 0)
            {
                // Display an enterprise-level guidance dialogue to the operator
                MessageBox.Show("You have selected the User Defined configuration.\n\n" +
                                "Please populate the ListBox with your preferred custom deletion sequences, " +
                                "or utilize the automated recommendation wizard embedded within Speedcrypt.",
                                ForAllUnits.BoxInfo, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        private void RdbGendel_CheckedChanged(object sender, EventArgs e)
        {
            btnLoaddel.Enabled = false;
            listFileloaddel.Enabled = rdbGendel.Checked;
            labFoldgendel.ForeColor = Color.Brown;
            listFileloaddel.Focus();
        }
        private void RdbLoaddel_CheckedChanged(object sender, EventArgs e)
        {
            btnLoaddel.Enabled = true;
            listFileloaddel.Enabled = rdbGendel.Checked;
            labFoldgendel.ForeColor = Color.Gray;
            btnLoaddel.Focus();
        }
        private void TxtFilepathdel_TextChanged(object sender, EventArgs e)
        {
            Enabledelbut();
        }
        private void BtnLoaddel_Click(object sender, EventArgs e)
        {
            // ENTERPRISE ARCHITECTURE: INSTANTIATE AN ISOLATED DIALOG TO PRESERVE COMPONENT ISOLATION AND AVOID STATE POLLUTION FOR DELETION PIPELINE
            using (OpenFileDialog localFileDialog = new OpenFileDialog())
            {
                // CONFIGURE ISOLATED METADATA AND VALIDATION CONTROLS FOR THE CURRENT DELETION CONTEXT
                localFileDialog.Title = "Speedcrypt: Load file for to delete";
                localFileDialog.CheckFileExists = true;

                // OPEN SYSTEM DIALOG AND CAPTURE THE ENCAPSULATED USER ACTION
                DialogResult fled = localFileDialog.ShowDialog();

                if (fled == DialogResult.OK)
                {
                    txtFilepathdel.Text = localFileDialog.FileName;
                    FileInfo fileInfo = new FileInfo(localFileDialog.FileName);

                    // VERIFY LOCAL FILE EXISTENCE PRIOR TO METRIC DISPLAY EXTRACTION
                    if (File.Exists(txtFilepathdel.Text))
                    {
                        // EXECUTE STRUCT TO STRING EXTRACTION ON COMPACT METRICS
                        labKb.Text = fileInfo.Strbytes();
                    }
                }
            }

        }
        private void BtnLoaddel_MouseMove(object sender, MouseEventArgs e)
        {
            txtFilepathdel.BackColor = Color.Yellow;
        }
        private void BtnLoaddel_MouseLeave(object sender, EventArgs e)
        {
            txtFilepathdel.BackColor = Color.White;
        }
        private async void BtnDelete_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("Do you really want to delete this File?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (result == DialogResult.No)
                return;

            try
            {
                btnDelete.Enabled = false;
                ForAllUnits.LwIcon = 3;
                Gensize();
                Start();
                await Deletefile();
            }
            finally
            {
                timer1.Stop();
                timer1.Enabled = false;
                Folderfileload();
                if (chkLoadlistbmkdel.Checked) Addlistbmk();
                if (chkOpenFoldel.Checked) Process.Start("Explorer.exe", Path.GetDirectoryName(txtFilepathdel.Text));
                if (chkDisplaybmkdel.Checked) tabControl1.SelectedIndex = 4;
                txtFilepathdel.Clear();
                labKb.Text = string.Empty;
                BmkActivate();
            }
        }
        private void ListFileloaddel_DoubleClick(object sender, EventArgs e)
        {
            foreach (ListViewItem bmkItem in listFileloaddel.SelectedItems)
                if (File.Exists(ForAllUnits.DirPath + @"\SpeedBmk\" + bmkItem.Text))
                {
                    txtFilepathdel.Text = ForAllUnits.DirPath + @"\SpeedBmk\" + bmkItem.Text;
                }
            if (File.Exists(txtFilepathdel.Text))
            {
                FileInfo fileInfo = new FileInfo(txtFilepathdel.Text);
                labKb.Text = fileInfo.Strbytes();
            }
        }
        async Task Deletefile()
        {
            // safety check: no file path or algorithm selected
            if (cmbAlgodel.SelectedItem == null || string.IsNullOrWhiteSpace(txtFilepathdel.Text))
                return;

            await Task.Run(() =>
            {
                // determine which custom type is selected
                bool isCustomClassic = rdbCust1.Checked;
                bool isCustomUser = rdbCust2.Checked;

                try
                {
                    // execute the selected shredding algorithm using Allshredder
                    Allshredder.Execute(cmbAlgodel.SelectedItem.ToString(), txtFilepathdel.Text, isCustomClassic, isCustomUser, listCustom);
                }
                catch (Exception ex)
                {
                    // handle any errors during file deletion
                    MessageBox.Show("Error deleting file! " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    CentralLog.LogException(ex, "SETTINGS", "Error deleting file!");
                }
            });
        }
        void Enabledelbut()
        {
            if (txtFilepathdel.Text != string.Empty && File.Exists(txtFilepathdel.Text))
            {
                if (grbAlgdel.Enabled)
                {
                    btnDelete.Enabled = false;
                    if (listCustom.Items.Count > 4 && rdbCust2.Checked && labValue.Text.Contains("Strong"))
                    {
                        btnDelete.Enabled = true;
                    }
                    else
                    if (rdbCust1.Checked) btnDelete.Enabled = true;
                }
                else btnDelete.Enabled = true;
            }
            else btnDelete.Enabled = false;
        }
        void SaveListBoxSetting(string key, ListBox listBox)
        {
            if (listBox.Items.Count > 0)
            {
                var items = new List<string>();
                foreach (var item in listBox.Items)
                {
                    items.Add(item.ToString());
                }
                string value = string.Join("|", items);
                AppConfigHelper.XmlConfig.SetValue(key, value);
            }
        }
        void Custombut(bool State)
        {
            btnRepeatval.Enabled = State;
            btnSaveval.Enabled = State;
            btnClearlistval.Enabled = State;
        }
        void Selection()
        {
            labFilerec.Text = "File Recoverability:";
            grbAlgdel.Enabled = false;

            var algoIndex = cmbAlgodel.SelectedIndex;
            var algoName = cmbAlgodel.Text;
            grbDesc.Text = "Algorithm: " + algoName;

            var algorithms = new Dictionary<int, ShredAlgorithmInfo>
            {
                [0] = new ShredAlgorithmInfo
                {
                    Description = "This method will simply overwrite a file with zeros before deleting it." +
                                  " It is not secure and should only be used for unimportant files and for quick free space locks.",
                    Strength = 35,
                    StrengthText = " 100 %",
                    Speed = "Very Fast",
                    Passes = "1"
                },

                [1] = new ShredAlgorithmInfo
                {
                    Description = "This method will simply overwrite a file one time with random data before deleting it." +
                                  " It is not secure and should only be used for unimportant files.",
                    Strength = 45,
                    StrengthText = " 99 %",
                    Speed = "Fast",
                    Passes = "1"
                },

                [2] = new ShredAlgorithmInfo
                {
                    Description = "This method is based on the U.S. Department of Defense's standard 'National Industrial Security Program Operating Manual' (DoD 5220.22-M E)." +
                                  " It will overwrite a file 3 times. This method offers medium security, use it only on files that do not contain sensitive information.",
                    Strength = 55,
                    StrengthText = " 50 %",
                    Speed = "Fast",
                    Passes = "3"
                },

                [3] = new ShredAlgorithmInfo
                {
                    Description = "This method is based on the U.S. Department of Defense's standard 'National Industrial Security Program Operating Manual' (US DoD 5220.22-M ECE)." +
                                  " It will overwrite a file 7 times. This method incorporates the DoD-3 method. It is secure and should be used for general files.",
                    Strength = 95,
                    StrengthText = " 0,0001 %",
                    Speed = "Moderate",
                    Passes = "7"
                },

                [4] = new ShredAlgorithmInfo
                {
                    Description = "This method is based on Bruce Schneier's data sanitization algorithm described in his book 'Applied Cryptography" +
                                  "It overwrites the file with a specific sequence of 7 passes: two random patterns followed by five fixed values." +
                                  " This method offers strong protection against advanced recovery techniques.",
                    Strength = 95,
                    StrengthText = " 0,0001 %",
                    Speed = "Moderate",
                    Passes = "7"
                },

                [5] = new ShredAlgorithmInfo
                {
                    Description = "This method complies with the German VSITR standard for secure data deletion, used by government agencies." +
                                  "It performs 7 overwriting passes with a defined sequence of fixed and random values." +
                                  "It provides strong protection against forensic recovery on both HDD and SSD devices.",
                    Strength = 95,
                    StrengthText = " 0,0001 %",
                    Speed = "Moderate",
                    Passes = "7"
                },

                [6] = new ShredAlgorithmInfo
                {
                    Description = "This method is based on Peter Gutmann's article 'Secure Deletion of Data From Magnetic and Solid-State Memory." +
                                  "The data will be overwritten 35 times using the patterns and methods described in the article." +
                                  "While this method takes the longest amount of time, it is the most secure method available and should" +
                                  "be used for all files that contain sensitive information.",
                    Strength = 105,
                    StrengthText = " 0 %",
                    Speed = "Very Slow",
                    Passes = "35"
                },

                [7] = new ShredAlgorithmInfo
                {
                    Description = RCMPTSSIT.Description,
                    Strength = 80,
                    StrengthText = " 5 %",
                    Speed = "Moderate",
                    Passes = "8"
                },

                [8] = new ShredAlgorithmInfo
                {
                    Description = HmgIs5Eraser.Description,
                    Strength = 85,
                    StrengthText = " 1 %",
                    Speed = "Moderate",
                    Passes = "3 - 7",
                },

                [9] = new ShredAlgorithmInfo
                {
                    Description = CustomEraser.Description,
                    Strength = 88,
                    StrengthText = " 0,1 %",
                    Speed = "Very Fast",
                    Passes = "5 - 8",
                    EnableCustomGroup = true
                },

                [10] = new ShredAlgorithmInfo
                {
                    Description = NSACSS9PassEraser.Description,
                    Strength = 80,
                    StrengthText = " 5 %",
                    Speed = "Fast",
                    Passes = "9"
                },

                [11] = new ShredAlgorithmInfo
                {

                    Description = NSACSS12PassEraser.Description,

                    Strength = 105,
                    StrengthText = " 0 %",
                    Speed = "Slow",
                    Passes = "12"
                },

                [12] = new ShredAlgorithmInfo
                {
                    Description = Delete.Description,
                    Strength = 95,
                    StrengthText = " 0,1 %",
                    Speed = "Fast",
                    Passes = "HDD",
                    HdType = "HDD"
                },

                [13] = new ShredAlgorithmInfo
                {
                    Description = NistClearMethod.Description,
                    Strength = 95,
                    StrengthText = " 0,0001 %",
                    Speed = "Fast",
                    Passes = "SSD NIST",
                    HdType = "SSD",
                    Manual = "Hardware/Firmware"
                }
            };

            if (algorithms.TryGetValue(algoIndex, out var info))
            {
                labShrd.Text = info.Description;
                passwordStrengthControl1.Strength = info.Strength;
                passwordStrengthControl1.StrengthText = info.StrengthText;
                labSpeed.Text = info.Speed;
                labPass.Text = info.Passes;
                labManual.Text = info.Manual ?? string.Empty;
                labHd.Text = info.HdType ?? string.Empty;
                grbAlgdel.Enabled = info.EnableCustomGroup;
            }
        }

        #endregion Secure Deletion

        #region Benchmark List
        private void ListBmk_MouseUp(object sender, MouseEventArgs e)
        {
            // Check if any item is under the mouse
            ListViewHitTestInfo hit = listBmk.HitTest(e.Location);

            // Enable the delete button only if an item is selected and the click is on an item
            btnDelitem.Enabled = hit.Item != null && listBmk.SelectedItems.Count > 0;
        }
        private void BtnImpList_Click(object sender, EventArgs e)
        {
            // ENTERPRISE ARCHITECTURE: CAPTURE INITIAL RECORD COUNT TO COMPUTE DELTA CHANGES POST-IMPORTATION
            int itemrow = listBmk.Items.Count;

            bool overwrite = chkOverwrite.Checked;

            ExpoImpoBmk.ImportListViewData(listBmk, ForAllUnits.openFileDialog1, ForAllUnits.BoxErr, overwrite);

            labFilter.Text = listBmk.Items.Count.ToString();

            if (listBmk.Items.Count > 0)
            {
                pnlList.Enabled = true;

                // Do NOT mark as dirty here: only user changes will trigger it
                if (chkAlternate.Checked) _alternator.Enable();
            }

            // STATE TRANSITION ENGINE: ACTIVATE SAVE CONTROLS ONLY IF UN-OVERWRITTEN ROWS WERE SUCCESSFULLY APPENDED
            if (!chkOverwrite.Checked && itemrow > 0 && itemrow < listBmk.Items.Count)
                btnSave.Enabled = true;

            // RESET STATE: PREVENT EXTRIOUS REDUNDANT SAVES IF THE ACTIVE LIST COMPLETELY OVERWROTE DISK RECORDS
            if (chkOverwrite.Checked) btnSave.Enabled = false;

            // ENFORCE VOLATILE MEMORY PURGE: RESET TRANSACTIONAL BOUNDARY MARKER
            itemrow = 0;
        }
        private void BtnExplist_Click(object sender, EventArgs e)
        {
            if (listBmk.Items.Count > 0)
                ExpoImpoBmk.ExportListViewData(listBmk);
        }
        private void BtnClearlist_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("Are you sure you want to clear the Benchmark List?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result != DialogResult.Yes)
                return;
            listBmk.Items.Clear();
            labFilter.Text = "0";

            Clearlist();
        }
        /// <summary>
        /// Executes safe chronological deletion sequences on targeted bookmark entities, optimizes UI rendering matrices, 
        /// updates persistence state indicators, and triggers conditional container sanitization protocols.
        /// </summary>
        private void BtnDelitem_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("Are you sure you want to delete selected items?", ForAllUnits.BoxWrg, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result != DialogResult.Yes)
                return;

            // Suspends visual presentation redraw threads to optimize layout mutations and prevent screen flickering
            listBmk.BeginUpdate();
            try
            {
                if (listBmk.SelectedItems.Count > 0)
                {
                    // Cycles backward to safely remove items from the collection without triggering enumeration faults
                    for (int i = listBmk.SelectedItems.Count - 1; i >= 0; i--)
                    {
                        listBmk.Items.Remove(listBmk.SelectedItems[i]);
                    }
                }
            }
            finally
            {
                // Commands immediate visual presentation layer restoration post-mutation routines execution
                listBmk.EndUpdate();
            }

            _dirtyTracker.MarkDirty();
            labFilter.Text = listBmk.Items.Count.ToString();
            btnDelitem.Enabled = false;

            if (listBmk.Items.Count == 0)
                Clearlist();
        }
        private void BtnSave_Click(object sender, EventArgs e)
        {
            try
            {
                // Check if a file is already associated
                if (!ExpoImpoBmk.HasFile)
                {
                    // File does not exist: open SaveFileDialog to choose a path
                    ExpoImpoBmk.ExportListViewData(listBmk);
                }
                else
                {
                    // File exists: save directly
                    ExpoImpoBmk.Save(listBmk);
                }

                // After successful save, mark the list as saved
                _dirtyTracker.MarkSaved();
            }
            catch (System.Exception ex)
            {
                // Show error message in a clean way
                MessageBox.Show("Error during save: " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                CentralLog.LogException(ex, "SETTINGS", "Error during export the benchmark List");
            }
        }
        private void TxtProcname_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                // Clear the default popup menu
                ContextMenuStrip cms = new ContextMenuStrip();
                txtProcname.ContextMenuStrip = cms;
            }
        }
        private void TxtProcname_TextChanged(object sender, System.EventArgs e)
        {
            // ENTERPRISE UI LOCK: Initialize visual suppression framework immediately at method entry for performance stability
            listBmk.BeginUpdate();

            string filterText = txtProcname.Text.Trim();
            string selectedField = cmbFind.Text.ToUpper();

            int col = -1;
            if (selectedField == "ALGORITHM") col = 1;
            else if (selectedField == "PROCESS") col = 2;
            else if (selectedField == "FILE SIZE") col = 3;
            else if (selectedField == "TIME") col = 4;
            else if (selectedField == "DATE TEST") col = 5;

            int filteredCount = 0;

            foreach (ListViewItem item in listBmk.Items)
            {
                // DEFENSIVE BOUNDARY VALIDATION: Prevent argument out of range crashes on variable ListView layouts
                if (col != -1 && item.SubItems.Count <= col)
                    continue;

                bool match = false;

                if (col == -1 || string.IsNullOrEmpty(filterText))
                {
                    match = true;
                }
                else
                {
                    string cell = item.SubItems[col].Text.Trim();

                    if (selectedField == "TIME")
                    {
                        // Flexible TIME comparison: contains filterText
                        match = cell.IndexOf(filterText, StringComparison.OrdinalIgnoreCase) >= 0;
                    }
                    else
                    {
                        // All other fields evaluation using optimized case-insensitive ordinal matching
                        match = cell.IndexOf(filterText, StringComparison.OrdinalIgnoreCase) >= 0;
                    }
                }

                item.ForeColor = match ? SystemColors.WindowText : SystemColors.GrayText;
                if (match) filteredCount++;
            }

            // ENTERPRISE UI RELEASE: Commit synchronized visual state updates back to the UI subsystem surface
            listBmk.EndUpdate();

            labFilter.Text = filteredCount.ToString();

            if (txtProcname.Text == string.Empty)
                labFilter.Text = listBmk.Items.Count.ToString();
        }
        private void CmbFind_SelectedIndexChanged(object sender, EventArgs e)
        {
            // Encapsulates UI state transitions within an explicit redraw inhibition block to eliminate layout flickering
            listBmk.BeginUpdate();

            // Flushes stale evaluation inputs and refocuses user hardware carets onto the pattern matching input textbox
            txtProcname.Clear();
            txtProcname.Focus();

            // Re-enables the visual rendering loop only after the data reset transaction is completely finalized
            listBmk.EndUpdate();
        }
        private void TabControl1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (tabControl1.SelectedIndex == 4 && listBmk.Items.Count > 0) Enablesaved();

            // Timer 
            picTimer.Visible = tabControl1.SelectedIndex == 1 || tabControl1.SelectedIndex == 3;
            labTime.Visible = picTimer.Visible;

            BmkActivate();
        }
        private void ChkAlternate_CheckedChanged(object sender, EventArgs e)
        {
            _alternator = new ListViewRowAlternator(listBmk);
            if (chkAlternate.Checked)
                _alternator.Enable();
            else
                _alternator.Disable();
        }
        void BmkActivate()
        {
            rdbGen.Enabled = listFileload.Items.Count > 0;
            rdbGendel.Enabled = listFileloaddel.Items.Count > 0;

            if (listFileloaddel.Items.Count == 0)
            {
                rdbLoad.Checked = true;
                rdbLoaddel.Checked = true;
                listFileloaddel.Enabled = false;
                labFoldgendel.ForeColor = Color.Gray;
            }
        }
        void Clearlist()
        {
            pnlList.Enabled = false;
            cmbFind.SelectedIndex = 0;
            txtProcname.Clear();
        }
        void Enablesaved()
        {
            if (listBmk.Items.Count == 0)
            {
                cmbFind.SelectedIndex = 0;
                txtProcname.Text = string.Empty;
                labFilter.Text = "0";
            }
        }

        #endregion Benchmark List

        #region Paste Menu
        private void PasteFileName_Click(object sender, EventArgs e)
        {
            IDataObject data = Clipboard.GetDataObject();
            if (!data.GetDataPresent(DataFormats.FileDrop))
                return;

            string[] files = (string[])data.GetData(DataFormats.FileDrop);

            if (tabControl1.SelectedIndex == 1)
            {
                txtFilepath.Text = files[0];
                if (File.Exists(txtFilepath.Text)) Passwbmk();
            }
            else
            if (tabControl1.SelectedIndex == 3)
                txtFilepathdel.Text = files[0];

            bool result = Path.HasExtension(files[0]);

            if (result == false)
            {
                txtFilepath.Text = string.Empty;
                txtFilepathdel.Text = string.Empty;
            }
        }

        #endregion Paste Menu

        #region Contextual help
        private void BtnHelp_Click(object sender, EventArgs e)
        {
            if (File.Exists(ForAllUnits.HelpFile))
                Help.ShowHelp(this, ForAllUnits.HelpFile, HelpNavigator.Topic, ForAllUnits.Settings);
        }

        #endregion Contextual help

        #region Timer
        public void Timer1_Tick(object sender, EventArgs e)
        {
            // Calculates temporal delta elapsed since core execution sequence checkpoint initialization
            TimeSpan diff = DateTime.Now.Subtract(ForAllUnits.Start);

            // Updates UI string layout buffer applying unified standardized chronological formatting protocols (HH:mm:ss.ff)
            labTime.Text = String.Format("{0:00}:{1:00}:{2:00}.{3:00}", (int)diff.TotalHours, diff.Minutes, diff.Seconds, diff.Milliseconds / 10);
        }

        #endregion Timer

        #region Override
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Invokes the base implementation to ensure standard operating system window closure events are processed executionally
            base.OnFormClosing(e);

            try
            {
                // =======================================================
                // Auto-save typed folder (if valid and not already saved)
                // =======================================================
                string typedFolder = cmbFolderPath.Text.Trim();
                if (!string.IsNullOrEmpty(typedFolder) &&
                    foldersManager.IsValidFolderPath(typedFolder) && // <-- strict validation
                    !foldersManager.GetFolders().Contains(typedFolder, StringComparer.OrdinalIgnoreCase))
                {
                    if (chkFoldercreate.Checked)
                    {
                        try
                        {
                            // Ensure folder ends with backslash
                            if (!typedFolder.EndsWith("\\"))
                                typedFolder += "\\";

                            // Ensure folder exists
                            if (!Directory.Exists(typedFolder))
                            {
                                Directory.CreateDirectory(typedFolder);
                            }

                            // Add to manager
                            foldersManager.AddFolder(typedFolder);

                            // Rebind ComboBox (typed folder stays selected)
                            foldersManager.BindToComboBox(cmbFolderPath);
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show("Error creating or saving folder: " + ex.Message, ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                            CentralLog.LogException(ex, "SETTINGS", "Error creating or saving typed folder on close.");
                            e.Cancel = true;
                            cmbFolderPath.Focus();
                            return;
                        }
                    }
                }

                // ======================
                // PGP Folder Validation
                // ======================

                // ======================
                // PGP Folder Validation
                // ======================

                if (!string.IsNullOrEmpty(cmbCrypteng.Text) && cmbCrypteng.Text.IndexOf("PGP", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    string folderPath = cmbFolderPath.Text.Trim();
                    bool isStructuralInvalid = false;
                    bool isUnapprovedPath = false;

                    if (string.IsNullOrWhiteSpace(folderPath))
                    {
                        isStructuralInvalid = true;
                    }
                    else if (!foldersManager.IsValidFolderPath(folderPath)) // <-- strict validation
                    {
                        isStructuralInvalid = true;
                    }
                    else
                    {
                        try
                        {
                            // Normalize path to evaluate its absolute and root characteristics robustly
                            string fullPath = Path.GetFullPath(folderPath);
                            string root = Path.GetPathRoot(fullPath);

                            // Reject paths that resolve directly to a root drive (e.g., "C:\", "H:\")
                            if (string.IsNullOrEmpty(root) || fullPath.Equals(root, StringComparison.OrdinalIgnoreCase))
                            {
                                isStructuralInvalid = true;
                            }
                            else if (!Directory.Exists(root))
                            {
                                isStructuralInvalid = true;
                            }
                            else
                            {
                                // Persistent registration and creation state verification
                                string trackingFilePath = Path.Combine("PGPFolders", "folders.txt");
                                bool isRegistered = false;

                                if (File.Exists(trackingFilePath))
                                {
                                    string[] registeredPaths = File.ReadAllLines(trackingFilePath);
                                    foreach (string line in registeredPaths)
                                    {
                                        if (line.Trim().Equals(fullPath, StringComparison.OrdinalIgnoreCase))
                                        {
                                            isRegistered = true;
                                            break;
                                        }
                                    }
                                }

                                // Identify if the path is well-formed but lacks active configuration approval
                                if (!isRegistered && !chkFoldercreate.Checked)
                                {
                                    isUnapprovedPath = true;
                                }
                            }
                        }
                        catch
                        {
                            // Catch formatting or security exceptions from Path retrieval
                            isStructuralInvalid = true;
                        }
                    }

                    // ENTERPRISE CLOSING OPTIMIZATION: ON FORM CLOSING, ENFORCE SILENT FALLBACK INSTEAD OF BLOCKING EXIT THREADS
                    if (isStructuralInvalid || isUnapprovedPath)
                    {
                        if (cmbFolderPath.Items != null && cmbFolderPath.Items.Count > 0)
                        {
                            cmbFolderPath.Text = cmbFolderPath.Items[0]?.ToString() ?? string.Empty;
                        }
                        else
                        {
                            cmbFolderPath.Text = string.Empty;
                        }

                        // DO NOT SET e.Cancel = true; ALLOW SHUTDOWN PIPELINE TO EXECUTE UNHINDERED
                    }
                }


                InactivePGP();

                // ===========================
                // Benchmark Proposal Settings
                // ===========================
                UiConfigSaver.SaveCheckBoxSetting("Result.ImmediateTest", chkImmediate);
                UiConfigSaver.SaveRadioButtonSetting("Result.Immediateenc", rdbEnc);
                UiConfigSaver.SaveRadioButtonSetting("Result.Immediatedel", rdbDel);

                // ===========================
                // Encryption Engines Settings
                // ===========================
                UiConfigSaver.SaveComboBoxSetting("Result.CryptoEngine", cmbCrypteng);
                UiConfigSaver.SaveComboBoxSetting("Result.SerpentKeySize", cmbSepentkeysize);
                UiConfigSaver.SaveComboBoxSetting("Result.TwofishKeySize", cmbTwofishkeysize);
                UiConfigSaver.SaveComboBoxSetting("Result.CamelliaKeySize", cmbCamelliakeysize);
                UiConfigSaver.SaveComboBoxSetting("Result.ThreefishKeySize", cmbThreefishkeysize);
                UiConfigSaver.SaveComboBoxSetting("Result.RSAKeySize", cmbRsaKeysize);
                UiConfigSaver.SaveComboBoxSetting("Result.AESKeySize", cmbAeskeysize);
                UiConfigSaver.SaveComboBoxSetting("Result.StringCrypto", cmbStringcrypto);

                // PGP Keys Folder Creation
                UiConfigSaver.SaveCheckBoxSetting("Result.PGPFoldercreate", chkFoldercreate);

                // Store algorithm-specific PBKDF2 rounds
                switch (cmbStringcrypto.SelectedIndex)
                {
                    case 0: UiConfigSaver.SaveTextBoxSetting("Result.FRSAES-CGMStrCrp", txtPbkdf2round); break;
                    case 1: UiConfigSaver.SaveTextBoxSetting("Result.SERPENTStrCrp", txtPbkdf2round); break;
                    case 2: UiConfigSaver.SaveTextBoxSetting("Result.TWOFISHStrCrp", txtPbkdf2round); break;
                    case 3: UiConfigSaver.SaveTextBoxSetting("Result.THREEFISHStrCrp", txtPbkdf2round); break;
                    case 4: UiConfigSaver.SaveTextBoxSetting("Result.SECXCHACHA20StrCrp", txtPbkdf2round); break;
                    case 5: UiConfigSaver.SaveTextBoxSetting("Result.XCHACHA20POLY1305StrCrp", txtPbkdf2round); break;
                    case 6: UiConfigSaver.SaveTextBoxSetting("Result.AESStrCrp", txtPbkdf2round); break;
                }

                // ======================
                // File Options Settings
                // ======================
                UiConfigSaver.SaveRadioButtonSetting("Result.GenerateFile", rdbGen);
                UiConfigSaver.SaveRadioButtonSetting("Result.LoadFile", rdbLoad);
                UiConfigSaver.SaveRadioButtonSetting("Result.1MBFile", rdb1MB);
                UiConfigSaver.SaveRadioButtonSetting("Result.10MBFile", rdb10MB);
                UiConfigSaver.SaveRadioButtonSetting("Result.100MBFile", rdb100MB);
                UiConfigSaver.SaveRadioButtonSetting("Result.500MBFile", rdb500MB);
                UiConfigSaver.SaveRadioButtonSetting("Result.CustomFile", rdbCustom);
                AppConfigHelper.XmlConfig.SetValue("Result.CustomSize", numCustomSize.Value.ToString());
                UiConfigSaver.SaveCheckBoxSetting("Result.OpenFolderBmk", chkOpenfoldbmk);
                UiConfigSaver.SaveCheckBoxSetting("Result.OpenfldencdecBmk", chkOpfldencdecbmk);
                UiConfigSaver.SaveCheckBoxSetting("Result.DisolayBmk", chkDisplaybmk);
                UiConfigSaver.SaveCheckBoxSetting("Result.LoadListBmk", chkLoadlistbmk);
                UiConfigSaver.SaveCheckBoxSetting("Result.DeloriginalBmk", chkDeloriginalbmk);
                UiConfigSaver.SaveCheckBoxSetting("Result.DelencryptedBmk", chkDelencryptedbmk);

                // ======================
                // HASH Engines Settings
                // ======================
                UiConfigSaver.SaveComboBoxSetting("Result.HashEngine", cmbHash);
                UiConfigSaver.SaveComboBoxSetting("Result.SaltEngine", cmbSalt);
                AppConfigHelper.XmlConfig.SetValue("Result.NumbSeq", rdbNumb.Checked.ToString());

                // ======================
                // Argon2 Parameters
                // ======================
                UiConfigSaver.SaveTextBoxSetting("Result.ArgonMemSize", txtArgMem);
                UiConfigSaver.SaveTextBoxSetting("Result.ArgonParallelism", txtArgParal);
                UiConfigSaver.SaveTextBoxSetting("Result.ArgonIterations", txtArgIter);
                UiConfigSaver.SaveComboBoxSetting("Result.ArgonHashSize", cmbArgsize);

                // ======================
                // Scrypt Parameters
                // ======================
                UiConfigSaver.SaveTextBoxSetting("Result.ScryptMemSize", txtScrMem);
                UiConfigSaver.SaveTextBoxSetting("Result.ScryptParallelization", txtScrParal);
                UiConfigSaver.SaveTextBoxSetting("Result.ScryptBlockSize", txtScrBksz);
                UiConfigSaver.SaveComboBoxSetting("Result.ScryptHashSize", cmbScrypsize);

                // ======================
                // PBKDF2 & BCrypt Parameters
                // ======================
                UiConfigSaver.SaveComboBoxSetting("Result.BCryptRounds", cmbBcrRound);
                UiConfigSaver.SaveTextBoxSetting("Result.PBKDF2Rounds", txtPbkIter);

                // ======================
                // HASH Options
                // ======================
                UiConfigSaver.SaveRadioButtonSetting("Result.SaltBase64", rdbBase64);
                UiConfigSaver.SaveRadioButtonSetting("Result.SaltHexLower", rdbHexLower);
                UiConfigSaver.SaveRadioButtonSetting("Result.SaltHexUpper", rdbHexUpper);
                UiConfigSaver.SaveCheckBoxSetting("Result.WhitoutSalt", chkNosalt);
                UiConfigSaver.SaveCheckBoxSetting("Result.ElapsedTime", chkElapsed);
                UiConfigSaver.SaveCheckBoxSetting("Result.HashHighlight", chkHighlight);

                // ======================
                // SALT Encoding Options
                // ======================
                UiConfigSaver.SaveRadioButtonSetting("Result.SaltBase64Salt", rdbBase64salt);
                UiConfigSaver.SaveRadioButtonSetting("Result.SaltHexLowerSalt", rdbHexLowersalt);
                UiConfigSaver.SaveRadioButtonSetting("Result.SaltHexUpperSalt", rdbHexUppersalt);

                // ======================
                // String Value Options
                // ======================
                UiConfigSaver.SaveRadioButtonSetting("Result.StringValueAll", rdbAll);
                UiConfigSaver.SaveRadioButtonSetting("Result.StringValueNum", rdbNumber);
                UiConfigSaver.SaveRadioButtonSetting("Result.StringValueChr", rdbChr);
                // ======================
                // Numeric UpDown Controls
                // ======================
                AppConfigHelper.XmlConfig.SetValue("Result.NumIndent", numIndent.Value.ToString());
                AppConfigHelper.XmlConfig.SetValue("Result.NumTextBlock", numTextblock.Value.ToString());

                // ======================
                // Secure Deletion Settings
                // ======================
                UiConfigSaver.SaveComboBoxSetting("Result.DeleteEngine", cmbAlgodel);

                // STUPID-PROOF SHIELD: Validate the custom list state before committing to configuration
                if (listCustom.Items.Count > 0)
                {
                    // Serialize and persist the structural pipeline-delimited token array
                    SaveListBoxSetting("Result.CustomValue", listCustom);
                }
                else
                {
                    // CRITICAL GRACEFUL DEGRADATION: Intercept empty collection context
                    // Enforce automated UI state rollback to prevent orphan state mismatch
                    rdbCust1.Checked = true;  // Force Classic Mode Checked State
                    rdbCust2.Checked = false; // Disable User Custom Mode Checked State

                    // Completely purge the obsolete key from the tracking XML structure
                    _xmlConfig.RemoveKey("Result.CustomValue");
                }

                // Persist the synchronized RadioButton cryptographic operational states
                UiConfigSaver.SaveRadioButtonSetting("Result.ClassicMethod", rdbCust1);
                UiConfigSaver.SaveRadioButtonSetting("Result.UserMethod", rdbCust2);
                UiConfigSaver.SaveRadioButtonSetting("Result.GenerateFileDel", rdbGendel);
                UiConfigSaver.SaveRadioButtonSetting("Result.LoadFileDel", rdbLoaddel);
                UiConfigSaver.SaveCheckBoxSetting("Result.OpenFoldafterdel", chkOpenFoldel);
                UiConfigSaver.SaveCheckBoxSetting("Result.Insertlistafterdel", chkLoadlistbmkdel);
                UiConfigSaver.SaveCheckBoxSetting("Result.Displaylistafterdel", chkDisplaybmkdel);

                // ======================
                // Benchmark List
                // ======================
                UiConfigSaver.SaveCheckBoxSetting("Result.BmkOverwriteAppend", chkOverwrite);
                UiConfigSaver.SaveCheckBoxSetting("Result.BmkAlternateRow", chkAlternate);

                // NOTE: The redundant duplicate check on listCustom.Items.Count has been purged from this section 
                // to prevent overriding the protective state machine evaluated above.

                // ======================
                // Miscellaneous Settings
                // ======================
                AppConfigHelper.XmlConfig.SetValue(
                    "Result.PGPKeyFolderPath",
                    Directory.Exists(cmbFolderPath.Text) ? cmbFolderPath.Text : string.Empty
                );

                // Commit all changes to configuration
                AppConfigHelper.Save();

                // Reload main form settings to reflect changes
                mainForm.LoadSettings();
            }
            catch (Exception ex)
            {
                // Log any exceptions silently to central log with module context
                CentralLog.LogException(ex, "SETTINGS", "An error occurred while closing the module!");
            }
        }

        #endregion Override
    }
}