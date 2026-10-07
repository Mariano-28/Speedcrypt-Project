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
using Speedcrypt.Nuvola;
using Speedcrypt.Autotest.DIGESTS;
using Speedcrypt.Autotest.CRYPTO.PGP;
using Speedcrypt.Autotest.CRYPTO.AES;
using Speedcrypt.Autotest.CRYPTO.GOST;
using Speedcrypt.Autotest.CRYPTO.IDEA;
using Speedcrypt.Autotest.CRYPTO.TWOFISH;
using Speedcrypt.Autotest.CRYPTO.Serpent;
using Speedcrypt.Autotest.DIGESTS.PBKDF2;
using Speedcrypt.Autotest.DIGESTS.WRAPPER;
using Speedcrypt.Autotest.CRYPTO.CAMELLIA;
using Speedcrypt.Autotest.CRYPTO.THREEFISH;
using Speedcrypt.Autotest.CRYPTO.KUZNYECHIK;
using Speedcrypt.Autotest.DIGESTS.SpeedcryptAutotest;

namespace Speedcrypt.Autotest

{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SpeedcryptAutotest: Automated self-test diagnostic suite executing diagnostic
    /// assertions across implementation blocks for verification of cryptographic compliance.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Sequential execution of multi-engine test cases (Symmetric, Digests, Mac layers).
    /// - Low-overhead UI feedback synchronization utilizing asynchronous layout boundaries.
    /// - Custom native GDI rendering for test status reporting with adaptive formatting rules.
    /// - Automated state machine auditing via deterministic execution of polymorphic ITest wrappers.
    /// - Memory-isolated asset streaming using double-buffered object binding to prevent layout flicker.
    ///
    /// The autotest component acts as a local validation authority, guaranteeing execution
    /// integrity of internal assemblies prior to initialization.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    internal class SpeedcryptAutotest
    {
        public enum TestMode
        {
            //Partial,
            Complete
        }
        private bool _allPassed;
        private TestMode _mode;
        private ListView _lvTest;
        private ImageList _imageList;
        private ToolStripProgressBar _progressBar;
        public SpeedcryptAutotest(TestMode mode, ListView lvTest, ToolStripProgressBar progressBar)
        {
            _mode = mode;
            _lvTest = lvTest;
            _progressBar = progressBar;
            // Enable double buffering to prevent flicker
            System.Reflection.PropertyInfo prop = typeof(ListView).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (prop != null)
                prop.SetValue(_lvTest, true, null);

            // Initialize ImageList (for icons)
            _imageList = new ImageList();
            _imageList.ImageSize = new Size(22, 22);
            _imageList.Images.Add("engine", Image.FromStream(new MemoryStream(Nuvola_22._22_encrypted))); // Encryption
            _imageList.Images.Add("hash", Image.FromStream(new MemoryStream(Nuvola_22._22_edu_mathematics)));   // hash
            _imageList.Images.Add("hmac", Image.FromStream(new MemoryStream(Nuvola_22._22_kbrunch)));   // hmac
            _imageList.Images.Add("total", Image.FromStream(new MemoryStream(Nuvola_22._22_ktimer)));   // hmac
            _lvTest.SmallImageList = _imageList;

            // Configure ListView
            _lvTest.View = View.Details;
            _lvTest.FullRowSelect = true;
            _lvTest.GridLines = true;
            _lvTest.OwnerDraw = true;

            // Configure columns
            if (_lvTest.Columns.Count == 0)
            {
                _lvTest.Columns.Add("ID", 26, HorizontalAlignment.Center);
                _lvTest.Columns.Add("ENGINES", 140, HorizontalAlignment.Left);
                _lvTest.Columns.Add("TEST RESULT", 110, HorizontalAlignment.Left);
            }

            // Assign draw handlers
            _lvTest.DrawColumnHeader += DrawColumnHeader;
            _lvTest.DrawSubItem += DrawSubItem;
            _lvTest.DrawItem += DrawItem;
        }
         public bool Run()
         {
             Stopwatch totalSw = Stopwatch.StartNew();
             _allPassed = true;

             if (_mode == TestMode.Complete)
             {
                 int totalTests = 44; // totaltest
                 int currentTest = 0;

                 // Helper for updating the progress bar
                 void UpdateProgress()
                 {
                     currentTest++;
                     int value = (int)((currentTest / (double)totalTests) * 100);
                     _progressBar.Value = Math.Min(value, 100);
                     Application.DoEvents(); // mantiene UI reattiva
                 }

                 // === Begin safe update: hide scrollbar and prevent any movement ===
                 ListViewHelper.UpdateWithoutScrollbarJump(_lvTest, () =>
                 {
                     _lvTest.Items.Clear();

                     // === Encryption (engine icon) ===
                     AESTest(); UpdateProgress();
                     PgpTest(); UpdateProgress();
                     IdeaTest(); UpdateProgress();
                     GostTest(); UpdateProgress();
                     SerpentTest(); UpdateProgress();
                     TwofishTest(); UpdateProgress();
                     CamelliaTest(); UpdateProgress();
                     ThreeFish256Test(); UpdateProgress();
                     ThreeFish512Test(); UpdateProgress();
                     ThreeFish1024Test(); UpdateProgress();
                     KuznyechikTest(); UpdateProgress();
                     ChaCha20Poly1305TestTest(); UpdateProgress();

                     // === Digests / Hash (hash icon) ===
                     BCryptTest(); UpdateProgress();
                     SCryptTest(); UpdateProgress();
                     MD5Test(); UpdateProgress();
                     Argon2Test(); UpdateProgress();
                     Sha224Test(); UpdateProgress();
                     Sha256Test(); UpdateProgress();
                     Sha384Test(); UpdateProgress();
                     Sha512Test(); UpdateProgress();
                     Sha3DigestTest(); UpdateProgress();
                     BlakeTest(); UpdateProgress();
                     Blake2bTest(); UpdateProgress();
                     Blake2sTest(); UpdateProgress();
                     Blake3Test(); UpdateProgress();
                     RipeMD128DigestTest(); UpdateProgress();
                     RipeMD160DigestTest(); UpdateProgress();
                     RipeMD256DigestTest(); UpdateProgress();
                     RipeMD320DigestTest(); UpdateProgress();
                     WhirlpoolDigestTest(); UpdateProgress();
                     ShakeDigestTest(); UpdateProgress();
                     Gost3411DigestTest(); UpdateProgress();
                     Gost34112012256Digest(); UpdateProgress();
                     Gost34112012512Digest(); UpdateProgress();
                     KeccakDigestTest(); UpdateProgress();
                     SkeinDigestTest(); UpdateProgress();
                     Pbkdf2Test(); UpdateProgress();
                     SM3Test(); UpdateProgress();

                     // === HMAC (hmac icon) ===
                     SHA1HMacTest(); UpdateProgress();
                     MD5HMacTest(); UpdateProgress();
                     Sha256HMacTest(); UpdateProgress();
                     Sha384HMacTest(); UpdateProgress();
                     Sha512HMacTest(); UpdateProgress();
                     RipeMD160HMacTest(); UpdateProgress();

                     // === Add total time item ===
                     var totalItem = new ListViewItem(string.Empty, "total");
                     totalItem.SubItems.Add("TOTAL TIME: 44 TEST IN >");
                     totalItem.SubItems.Add($" [ {totalSw.ElapsedMilliseconds} ms / {totalSw.Elapsed.TotalSeconds:F2} S ]");
                     _lvTest.Items.Add(totalItem);

                     // Scroll to last item safely (no movement of scrollbar)
                     Application.DoEvents();
                     _lvTest.BeginInvoke((System.Action)(() =>
                     {
                         if (_lvTest.Items.Count > 0)
                         {
                             var last = _lvTest.Items[_lvTest.Items.Count - 1];
                             last.Selected = true;
                             last.Focused = true;
                             _lvTest.EnsureVisible(_lvTest.Items.Count - 1);
                         }
                     }));

                     // Ensure progress bar reaches 100%
                     _progressBar.Value = 100;
                 });
             }

             return _allPassed;
         }    

        // === CORE: Add result with execution time ===
        private void AddResult(string engine, string result, TimeSpan duration, string iconKey = "engine")
        {
            string timeText;

            // Se la durata è maggiore o uguale a un secondo
            if (duration.TotalSeconds >= 1)
            {
                timeText = $" [{duration.TotalSeconds:00.00} S]";
            }
            else
            {
                // Altrimenti in millisecondi
                timeText = $" [{duration.TotalMilliseconds:00.00} ms]";
            }

            var item = new ListViewItem(string.Empty, iconKey);
            item.SubItems.Add(engine);
            item.SubItems.Add($"{result} {timeText}");
            _lvTest.Items.Add(item);
            
            if (result != "PASSED")
            {
                _allPassed = false; // se almeno un test fallisce, settiamo il flag
            }
        }
        private void RunTest(ITest test, string engine, string iconKey = "engine")
        {
            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                ITestResult result = test.Perform();
                if (result.GetException() != null)
                    throw result.GetException();
                sw.Stop();
                AddResult(engine, "PASSED", sw.Elapsed, iconKey);
            }
            catch
            {
                sw.Stop();
                AddResult(engine, "FAILED", sw.Elapsed, iconKey);
            }
        }

        // === DRAWING ===
        private void DrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            e.DrawDefault = true;
        }
        private void DrawItem(object sender, DrawListViewItemEventArgs e)
        {
            // Icon handled automatically
            e.DrawDefault = false;
        }
        private void DrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            var lv = (ListView)sender;

            // Column 0: draw default (image)
            if (e.ColumnIndex == 0)
            {
                e.DrawDefault = true;
                return;
            }

            // Draw background
            e.DrawBackground();

            // Determine color
            string text = e.SubItem.Text;
            Color color = lv.ForeColor;

            if (text.StartsWith("PASSED"))
                color = Color.ForestGreen;
            else if (text.StartsWith("FAILED"))
                color = Color.Firebrick;
            else if (text.Contains("["))
                color = Color.DarkBlue;

            // Draw text correctly
            TextRenderer.DrawText(e.Graphics, text, e.SubItem.Font, e.Bounds, color,
                                  TextFormatFlags.Left | TextFormatFlags.VerticalCenter);            
        }

        // === TEST METHODS ===

        // Encrypt
        private void AESTest() { RunTest(new AesTest(), "AES", "engine"); }
        private void PgpTest() { RunTest(new PgpTest(), "PGP", "engine"); }
        private void IdeaTest() { RunTest(new IdeaTest(), "IDEA", "engine"); }
        private void GostTest() { RunTest(new Gost28147Test(), "GOST", "engine"); }
        private void SerpentTest() { RunTest(new SerpentTest(), "SERPENT", "engine"); }
        private void TwofishTest() { RunTest(new TwofishTest(), "TWOFISH", "engine"); }
        private void CamelliaTest() { RunTest(new CamelliaTest(), "CAMELLIA", "engine"); }
        private void ThreeFish256Test() { RunTest(new Threefish256Test(), "THREEFISH-256", "engine"); }
        private void ThreeFish512Test() { RunTest(new Threefish512Test(), "THREEFISH-512", "engine"); }
        private void ThreeFish1024Test() { RunTest(new Threefish1024Test(), "THREEFISH-1024", "engine"); }
        private void KuznyechikTest() { RunTest(new KuznyechikTest(), "KUZNYECHIK", "engine"); }
        private void ChaCha20Poly1305TestTest() { RunTest(new ChaCha20Poly1305Test(), "CHACHA20POLY1305", "engine"); }

        // HASH
        private void BCryptTest() { RunTest(new BCryptTest(), "BCRYPT", "hash"); }
        private void SCryptTest() { RunTest(new SCryptTest(), "SCRYPT", "hash"); }
        private void MD5Test() { RunTest(new MD5DigestTest(), "MD5", "hash"); }
        private void Argon2Test() { RunTest(new Argon2TestWrapper(), "ARGON2", "hash"); }
        private void Sha224Test() { RunTest(new Sha224DigestTest(), "SHA-224", "hash"); }
        private void Sha256Test() { RunTest(new Sha256DigestTest(), "SHA-256", "hash"); }
        private void Sha384Test() { RunTest(new Sha384DigestTest(), "SHA-384", "hash"); }
        private void Sha512Test() { RunTest(new Sha512DigestTest(), "SHA-512", "hash"); }
        private void Sha3DigestTest() { RunTest(new Sha3DigestTest(), "SHA3", "hash"); }
        private void BlakeTest() { RunTest(new BlakeTest(), "BLAKE", "hash"); }
        private void Blake2bTest() { RunTest(new Blake2bDigestTest(), "BLAKE2b", "hash"); }
        private void Blake2sTest() { RunTest(new Blake2sDigestTest(), "BLAKE2s", "hash"); }
        private void Blake3Test() { RunTest(new Blake3Test(), "BLAKE3", "hash"); }
        private void RipeMD128DigestTest() { RunTest(new RipeMD128DigestTest(), "RIPEMD-128", "hash"); }
        private void RipeMD160DigestTest() { RunTest(new RipeMD160DigestTest(), "RIPEMD-160", "hash"); }
        private void RipeMD256DigestTest() { RunTest(new RipeMD256DigestTest(), "RIPEMD-256", "hash"); }
        private void RipeMD320DigestTest() { RunTest(new RipeMD320DigestTest(), "RIPEMD-320", "hash"); }
        private void WhirlpoolDigestTest() { RunTest(new WhirlpoolDigestTest(), "WHIRLPOOL", "hash"); }
        private void ShakeDigestTest() { RunTest(new ShakeDigestTest(), "SHAKE", "hash"); }
        private void Gost3411DigestTest() { RunTest(new GOST94DigestTest(), "GOST R 34.11-94", "hash"); }
        private void Gost34112012256Digest() { RunTest(new GOST3411_2012_256DigestTest(), "STREEBOG-256", "hash"); }
        private void Gost34112012512Digest() { RunTest(new GOST3411_2012_512DigestTest(), "STREEBOG-512", "hash"); }
        private void KeccakDigestTest() { RunTest(new KeccakDigestTest(), "KECCAK", "hash"); }
        private void SkeinDigestTest() { RunTest(new SkeinDigestTest(), "SKEIN", "hash"); }
        private void Pbkdf2Test() { RunTest(new Pbkdf2Test(), "PBKDF2", "hash"); }
        private void SM3Test() { RunTest(new SM3DigestTest(), "SM3", "hash"); }

        // HMAC
        private void SHA1HMacTest() { RunTest(new Sha1HMacTest(), "HMACSHA1", "hmac"); }
        private void MD5HMacTest() { RunTest(new MD5HMacTest(), "HMACMD5", "hmac"); }
        private void Sha256HMacTest() { RunTest(new Sha256HMacTest(), "HMACSHA-256", "hmac"); }
        private void Sha384HMacTest() { RunTest(new Sha384HMacTest(), "HMACSHA-384", "hmac"); }
        private void Sha512HMacTest() { RunTest(new Sha512HMacTest(), "HMACSHA-512", "hmac"); }
        private void RipeMD160HMacTest() { RunTest(new RipeMD160HMacTest(), "HMACRIPEMD-160", "hmac"); }
    }
}