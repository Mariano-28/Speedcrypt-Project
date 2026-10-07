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
using Speedcrypt.UI;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

// Speedcrypt
using Speedcrypt.Nuvola;

namespace Speedcrypt.SecureDesktop
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// SpeedcryptSecureDesktop:
    /// Secure desktop isolation manager for protected password entry.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt security core and belongs to the
    /// desktop isolation and credential capture subsystem.
    ///
    /// Purpose:
    /// - Create and switch to a dedicated secure Windows desktop.
    /// - Display a protected password input dialog on the isolated desktop.
    /// - Capture sensitive credentials while reducing exposure to user‑mode threats.
    /// - Restore the original desktop context after completion.
    /// - Minimize sensitive data lifetime using SecureString and char[] buffers.
    ///
    /// Design notes:
    /// - Desktop isolation is used to mitigate common user‑mode keyloggers,
    ///   screen capture tools, and UI‑level interception techniques.
    /// - Password input is visually protected while preserving user reassurance
    ///   by mirroring the original desktop wallpaper.
    /// - Sensitive data is actively cleared as soon as it is no longer required.
    /// - No assumptions are made about UI control types at compile time.
    ///
    /// Security scope and limits:
    /// - This mechanism significantly raises the bar against most software‑based
    ///   keylogging and screen capture attacks operating in user mode.
    /// - It does NOT claim to be an absolute or inviolable shield.
    /// - Kernel‑level malware, fully privileged attackers, or compromised systems
    ///   remain outside the protection scope.
    /// - No software‑only solution can guarantee total immunity.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class SpeedcryptSecureDesktop
    {
        /// <summary>
        /// Creates a new desktop object with the specified name and access rights.
        /// Returns a handle to the created desktop.
        /// </summary>
        [DllImport("user32.dll")]
        public static extern IntPtr CreateDesktop(
            string lpszDesktop,
            IntPtr lpszDevice,
            IntPtr pDevmode,
            int dwFlags,
            uint dwDesiredAccess,
            IntPtr lpsa);

        /// <summary>
        /// Switches the calling thread to the specified desktop.
        /// </summary>
        [DllImport("user32.dll")]
        private static extern bool SwitchDesktop(IntPtr hDesktop);

        /// <summary>
        /// Closes the specified desktop handle.
        /// </summary>
        [DllImport("user32.dll")]
        public static extern bool CloseDesktop(IntPtr handle);

        /// <summary>
        /// Assigns the specified desktop to the calling thread.
        /// </summary>
        [DllImport("user32.dll")]
        public static extern bool SetThreadDesktop(IntPtr hDesktop);

        /// <summary>
        /// Retrieves a handle to the desktop assigned to the specified thread ID.
        /// </summary>
        [DllImport("user32.dll")]
        public static extern IntPtr GetThreadDesktop(int dwThreadId);

        /// <summary>
        /// Returns the thread ID of the calling thread.
        /// </summary>
        [DllImport("kernel32.dll")]
        public static extern int GetCurrentThreadId();

        /// <summary>
        /// Retrieves system parameters, such as the current desktop wallpaper path.
        /// </summary>
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SystemParametersInfo(int uAction, int uParam, StringBuilder lpvParam, int fuWinIni);

        private const int SPI_GETDESKWALLPAPER = 0x0073;

        /// <summary>
        /// Desktop access rights for secure desktop creation.
        /// GENERIC_ALL combines all necessary permissions.
        /// </summary>
        private enum DESKTOP_ACCESS : uint
        {
            DESKTOP_NONE = 0,
            DESKTOP_READOBJECTS = 0x0001,
            DESKTOP_CREATEWINDOW = 0x0002,
            DESKTOP_CREATEMENU = 0x0004,
            DESKTOP_HOOKCONTROL = 0x0008,
            DESKTOP_JOURNALRECORD = 0x0010,
            DESKTOP_JOURNALPLAYBACK = 0x0020,
            DESKTOP_ENUMERATE = 0x0040,
            DESKTOP_WRITEOBJECTS = 0x0080,
            DESKTOP_SWITCHDESKTOP = 0x0100,
            GENERIC_ALL = (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
                           DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
                           DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP)
        }

        /// <summary>
        /// Opens a secure desktop, displays a password dialog, captures the password securely,
        /// and returns to the original desktop. Populates the provided SecureTextBox
        /// and optionally invokes a callback after capture.
        /// </summary>
        /// <param name="secMasKey">Dynamic reference to a SecureTextBox control to populate securely.</param>
        /// <param name="callMastKey">Action delegate called after password capture for further processing.</param>
        //public void ProtectionMode(dynamic secMasKey, Action callMastKey)       
        public void ProtectionMode(dynamic secMasKey, Action callMastKey, dynamic secPasw = null)
        {
            // Save handle of current desktop
            IntPtr hOldDesktop = GetThreadDesktop(GetCurrentThreadId());

            // Create a new secure desktop
            IntPtr hNewDesktop = CreateDesktop(
                "SecureDesktop",
                IntPtr.Zero,
                IntPtr.Zero, 0, (uint)DESKTOP_ACCESS.GENERIC_ALL, IntPtr.Zero
            );

            // Switch to secure desktop immediately
            SwitchDesktop(hNewDesktop);

            // Master key buffer (char[]) instead of string to reduce immutable-string lifetime
            char[] MasterkeyBuffer = null;

            // CheckBox declared here so it's visible after Task
            CheckBox chkExportPass = null;

            // Run password dialog on new desktop thread
            Task.Factory.StartNew(() =>
            {
                SetThreadDesktop(hNewDesktop);

                // Play Windows UAC sound
                try
                {
                    string soundPath = @"C:\Windows\Media\Windows Foreground.wav";
                    if (File.Exists(soundPath))
                    {
                        using (System.Media.SoundPlayer player = new System.Media.SoundPlayer(soundPath))
                        {
                            player.Play(); // Play async
                        }
                    }
                }
                catch
                {
                    // Fail silently if sound cannot play
                }

                // Capture current desktop wallpaper
                Image desktopBackground = null;
                try
                {
                    StringBuilder sb = new StringBuilder(260);
                    if (SystemParametersInfo(SPI_GETDESKWALLPAPER, sb.Capacity, sb, 0))
                    {
                        string wallpaperPath = sb.ToString();
                        if (File.Exists(wallpaperPath))
                            desktopBackground = Image.FromFile(wallpaperPath);
                    }
                }
                catch
                {
                    desktopBackground = null;
                }

                // Overlay form
                Form overlayForm = new Form
                {
                    FormBorderStyle = FormBorderStyle.None,
                    Bounds = Screen.PrimaryScreen.Bounds,
                    BackColor = Color.Black,
                    Opacity = 0.5,
                    TopMost = true,
                    StartPosition = FormStartPosition.Manual
                };
                overlayForm.Show();

                if (desktopBackground != null)
                {
                    PictureBox backgroundBox = new PictureBox
                    {
                        Bounds = overlayForm.Bounds,
                        Image = desktopBackground,
                        SizeMode = PictureBoxSizeMode.StretchImage
                    };
                    overlayForm.Controls.Add(backgroundBox);
                    backgroundBox.SendToBack();
                }

                // Password input form
                Form PasswFrm = new Form
                {
                    Width = 470,
                    Height = 250,
                    TopMost = true,
                    Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location),
                    Text = "Speedcrypt Secure Desktop",
                    FormBorderStyle = FormBorderStyle.FixedDialog,
                    MaximizeBox = false,
                    MinimizeBox = false,
                    BackColor = Color.Gainsboro,
                    StartPosition = FormStartPosition.Manual,
                    Location = new Point(
                        (Screen.PrimaryScreen.WorkingArea.Width - 470) / 2,
                        (Screen.PrimaryScreen.WorkingArea.Height - 250) / 2
                    ),
                    TopLevel = true,
                    ShowInTaskbar = false
                };

                // Key icon
                PictureBox pictkey = new PictureBox
                {
                    Size = new Size(48, 48),
                    Location = new Point(20, 30),
                    Image = new Bitmap(new MemoryStream(Nuvola_48._48_kgpg_key3)),
                    SizeMode = PictureBoxSizeMode.StretchImage
                };
                PasswFrm.Controls.Add(pictkey);

                // Password TextBox
                TextBox txtPassw = new TextBox
                {
                    Width = 270,
                    Location = new Point((PasswFrm.Width - 270) / 2, (PasswFrm.Height - 30) / 2),
                    Font = new Font("Arial", 12, FontStyle.Regular),
                    Height = 21,
                    PasswordChar = '\u2022'
                };
                txtPassw.ContextMenuStrip = new ContextMenuStrip();
                txtPassw.ShortcutsEnabled = false;
                txtPassw.KeyDown += (s, e) =>
                {
                    if (e.Control && (e.KeyCode == Keys.C || e.KeyCode == Keys.V || e.KeyCode == Keys.X || e.KeyCode == Keys.A))
                        e.SuppressKeyPress = true;
                };

                PasswFrm.Controls.Add(txtPassw);

                // Password Label
                Label passwordLabel = new Label
                {
                    Text = "Master Key:",
                    AutoSize = true,
                    Font = new Font("Arial", 9, FontStyle.Regular),
                    Location = new Point(txtPassw.Left - 80, txtPassw.Top + 3)
                };
                PasswFrm.Controls.Add(passwordLabel);

                // Hint label (slightly higher)
                Label hintLabel = new Label
                {
                    Text = "This anti-keylogger shield\nprotects you from most threats,\ntype your Master Key safely.",
                    AutoSize = false,
                    Width = 270,
                    Height = 60,
                    Font = new Font("Arial", 9, FontStyle.Regular),
                    TextAlign = ContentAlignment.MiddleLeft,
                    Location = new Point(txtPassw.Left, txtPassw.Top - 100)
                };
                PasswFrm.Controls.Add(hintLabel);

                // CheckBox for routing password to export
                chkExportPass = new CheckBox
                {
                    Text = "Password for Export",
                    AutoSize = true,
                    Font = new Font("Arial", 9, FontStyle.Regular),
                    Location = new Point(txtPassw.Left, hintLabel.Bottom + 5),
                    Cursor = Cursors.Hand,
                    Checked = false
                };
                PasswFrm.Controls.Add(chkExportPass);

                // Make focus jump to txtPassw when checkbox checked (elegant touch)
                chkExportPass.CheckedChanged += (s, e) =>
                {
                    if (chkExportPass.Checked)
                    {
                        txtPassw.Focus();
                        txtPassw.SelectionStart = txtPassw.Text.Length;
                        txtPassw.SelectionLength = 0;
                    }
                };

                // Toggle visibility button
                Button btnToggle = new Button
                {
                    Size = new Size(50, 30),
                    Location = new Point(txtPassw.Right + 5, txtPassw.Top),
                    Image = new Bitmap(new MemoryStream(Nuvola_22._22_password)),
                    BackColor = Color.White,
                    Cursor = Cursors.Hand,
                    Enabled = false
                };
                PasswFrm.Controls.Add(btnToggle);

                // OK button
                Button btnOk = new Button
                {
                    Size = new Size(75, 30),
                    Image = new Bitmap(new MemoryStream(Nuvola_22._22_apply)),
                    ImageAlign = ContentAlignment.MiddleLeft,
                    BackColor = Color.White,
                    Text = "OK",
                    Cursor = Cursors.Hand,
                    Location = new Point((PasswFrm.Width - 75) / 2, txtPassw.Bottom + 35)
                };
                PasswFrm.Controls.Add(btnOk);

                // Toggle password visibility
                btnToggle.Click += (s, e) =>
                {
                    if (txtPassw.PasswordChar == '\0')
                    {
                        txtPassw.PasswordChar = '\u2022';
                        btnToggle.Text = string.Empty;
                        btnToggle.Image = new Bitmap(new MemoryStream(Nuvola_22._22_password));
                    }
                    else
                    {
                        txtPassw.PasswordChar = '\0';
                        btnToggle.Image = null;
                        btnToggle.Text = "\u25CF\u25CF\u25CF";
                    }
                    txtPassw.Focus();
                    txtPassw.SelectionStart = txtPassw.Text.Length;
                    txtPassw.SelectionLength = 0;
                };

                txtPassw.TextChanged += (s, e) => { btnToggle.Enabled = txtPassw.Text != string.Empty; };

                // Capture password into char[] immediately and clear TextBox to reduce string lifetime
                btnOk.Click += (s, e) =>
                {
                    // Copy text to char[] as soon as possible
                    string temp = txtPassw.Text;
                    if (!string.IsNullOrEmpty(temp))
                    {
                        MasterkeyBuffer = temp.ToCharArray(); // minimal string lifetime
                                                              // Clear TextBox to release reference to the string instance
                        txtPassw.Text = string.Empty;
                        // Remove local reference
                        temp = null;
                    }
                    PasswFrm.Close();
                };

                // Also handle form closing (e.g. user presses Esc or closes window)
                PasswFrm.FormClosing += (s, e) =>
                {
                    string temp = txtPassw.Text;
                    if (!string.IsNullOrEmpty(temp))
                    {
                        MasterkeyBuffer = temp.ToCharArray();
                        txtPassw.Text = string.Empty;
                        temp = null;
                    }
                };

                // Run password dialog on new desktop thread
                Application.Run(PasswFrm);

                // Dispose resources and forms to prevent Win32 handle leaks
                pictkey.Image?.Dispose();
                btnToggle.Image?.Dispose();
                desktopBackground?.Dispose();
                PasswFrm.Dispose();
                overlayForm.Dispose();

            }).Wait();

            // Return to original desktop
            SwitchDesktop(hOldDesktop);
            CloseDesktop(hNewDesktop);

            // Populate SecureTextBox with captured password using the char[] buffer
            if (MasterkeyBuffer != null && MasterkeyBuffer.Length > 0)
            {
                try
                {
                    // Route to secPasw if checkbox checked and second textbox exists
                    if (chkExportPass != null && chkExportPass.Checked && secPasw != null)
                    {
                        secPasw.Focus();
                        secPasw.SelectionStart = secPasw.Text.Length;
                        secPasw.SelectionLength = 0;

                        secPasw.SecureText.Clear();
                        ForAllUnits.CharArr = new char[MasterkeyBuffer.Length];
                        Array.Copy(MasterkeyBuffer, ForAllUnits.CharArr, MasterkeyBuffer.Length);
                        foreach (char c in ForAllUnits.CharArr)
                            secPasw.SecureText.AppendChar(c);

                        if (secPasw.PasswordChar == '\0')
                            secPasw.Text = new string(MasterkeyBuffer);
                        else
                            secPasw.Text = new string('\u25CF', ForAllUnits.CharArr.Length);

                        secPasw.SelectionStart = secPasw.Text.Length;
                        secPasw.SelectionLength = 0;
                    }
                    else
                    {
                        secMasKey.Focus();
                        secMasKey.SelectionStart = secMasKey.Text.Length;
                        secMasKey.SelectionLength = 0;

                        secMasKey.SecureText.Clear();
                        ForAllUnits.CharArr = new char[MasterkeyBuffer.Length];
                        Array.Copy(MasterkeyBuffer, ForAllUnits.CharArr, MasterkeyBuffer.Length);
                        foreach (char c in ForAllUnits.CharArr)
                            secMasKey.SecureText.AppendChar(c);

                        if (secMasKey.PasswordChar == '\0')
                            secMasKey.Text = new string(MasterkeyBuffer);
                        else
                            secMasKey.Text = new string('\u25CF', ForAllUnits.CharArr.Length);

                        secMasKey.SelectionStart = secMasKey.Text.Length;
                        secMasKey.SelectionLength = 0;

                        callMastKey?.Invoke();
                    }
                }
                finally
                {
                    // Guaranteed zeroize buffers in any execution path or exception
                    if (ForAllUnits.CharArr != null)
                    {
                        Array.Clear(ForAllUnits.CharArr, 0, ForAllUnits.CharArr.Length);
                        ForAllUnits.CharArr = null;
                    }

                    Array.Clear(MasterkeyBuffer, 0, MasterkeyBuffer.Length);
                    MasterkeyBuffer = null;
                }

                // Force garbage collection to reduce lifetime of any leftover strings
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }
    }
}