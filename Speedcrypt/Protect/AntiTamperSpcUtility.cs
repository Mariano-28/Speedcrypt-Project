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
using System.Windows.Forms;
using System.Security.Cryptography;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Protect
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// AntiTamperSpcUtility: Class to verify the integrity of SpcUtility.exe in the program folder.
    /// Checks for tampering by computing the SHA-256 hash and comparing it to the expected value.
    /// Alerts the user if the file has been modified.
    /// </summary>
    /// <remarks>
    /// Responsibilities:
    /// - Automatically determines the full path to SpcUtility.exe
    /// - Computes SHA-256 hash and compares against the expected hash
    /// - Detects any tampering or modification
    /// - Alerts the user via a message box if tampering is detected
    ///
    /// Security & Reliability Notes:
    /// - Verification is non-blocking; exceptions are handled gracefully
    /// - Designed to be self-contained, requiring no external inputs for file path
    /// - Only the expected hash needs updating when SpcUtility.exe changes
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and overall security validation lies entirely with the author.
    /// </remarks>
    public class AntiTamperSpcUtility
    {
        // SHA-256 hash of the original SpcUtility.exe Generated with EasyHash
        private readonly string expectedHash = "6AF8B0CC6DEE2638CDDEF34684C930706539A415FE83E498991968FCC1CFDABF";

        // Full path to SpcUtility.exe in the program folder
        private readonly string filePath;

        public AntiTamperSpcUtility()
        {
            filePath = Path.Combine(Application.StartupPath, "SpcUtility.exe");
        }

        /// <summary>
        /// Checks if SpcUtility.exe has been tampered with (original method).
        /// </summary>
        public void VerifyFileIntegrity()
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    // File missing: show warning
                    MessageBox.Show("Warning: SpcUtility.exe is missing from the program folder!", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string fileHash = ComputeSHA256(filePath);

                if (!string.Equals(fileHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    MessageBox.Show("Warning: SpcUtility.exe has been modified or tampered with!", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "Tool Utility Test", "Error during integrity check!");
            }
        }

        /// <summary>
        /// Checks if SpcUtility.exe has been tampered with and updates UI status.
        /// </summary>
        public void VerifyFileIntegrity(Label statusLabel, PictureBox statusIcon)
        {
            bool success = true;
            string message = "Tool Utility Test: Passed!";

            try
            {
                if (!File.Exists(filePath))
                {
                    success = false;
                    message = "Tool Utility Test: Failed!";

                    MessageBox.Show("Warning: SpcUtility.exe is missing from the program folder!", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);

                    // Update UI and exit early
                    if (statusLabel != null)
                        statusLabel.Text = message;

                    if (statusIcon != null)
                    {
                        statusIcon.Image?.Dispose();
                        statusIcon.Image = ForAllUnits.Ledred16;
                    }
                    return;
                }

                string fileHash = ComputeSHA256(filePath);

                if (!string.Equals(fileHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    success = false;
                    message = "Tool Utility Test: Failed!";

                    MessageBox.Show("Warning: SpcUtility.exe has been modified or tampered with!", ForAllUnits.BoxWrg, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception ex)
            {
                success = false;
                message = "Tool Utility Test: Failed!";
                CentralLog.LogException(ex, "Tool Utility Test", "Error during integrity check!");
            }

            // Update Label
            if (statusLabel != null)
                statusLabel.Text = message;

            // Update PictureBox
            if (statusIcon != null)
            {
                statusIcon.Image?.Dispose();
                statusIcon.Image = success
                    ? ForAllUnits.Ledgreen16
                    : ForAllUnits.Ledred16;
            }
        }

        /// <summary>
        /// Computes the SHA-256 hash of a file utilizing non-exclusive shared locks to prevent operational restore race conditions.
        /// </summary>
        private string ComputeSHA256(string filePath)
        {
            // Opens the target file stream with permissive shared flags to avoid locking collisions with parallel recovery systems
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(fs);
                StringBuilder sb = new StringBuilder(64); // Pre-allocates buffer size optimized for SHA-256 hex string lengths
                foreach (byte b in hashBytes)
                    sb.Append(b.ToString("X2"));
                return sb.ToString();
            }
        }
    }

        /*
       // Converts a hexadecimal string into a byte array.
       // Example usage:
       // string hex = "03E40E860BD837758A567782D8BF5F2F51EA87DACF05A3E03308473C7F2E14B3";
       // byte[] bytes = HexStringToByteArray(hex);
       private byte[] HexStringToByteArray(string hex)
       {
           if (hex.Length % 2 != 0)
              throw new ArgumentException("Invalid hex string length.");

           byte[] bytes = new byte[hex.Length / 2];

           for (int i = 0; i < bytes.Length; i++)
           {
               bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
           }

           return bytes;
        }

       // ===========================
       // Example: Using HexStringToByteArray from a button click event
       // ===========================
       private void btnConvertHex_Click(object sender, EventArgs e)
       {
           try
           {
               string hex = "4D71AEAC27EB891EFBB4804B48B2286A076407E2F28F1BA5167546A60C843760";

               // Call the conversion function (if made public or temporarily copied)
               byte[] bytes = HexStringToByteArray(hex);

               // Just for demonstration: show first 8 bytes in a message box
               string preview = string.Join(", ", bytes.Take(8).Select(b => b.ToString("X2")));
               MessageBox.Show("First 8 bytes: " + preview, "Hex to Byte Array Conversion", MessageBoxButtons.OK, MessageBoxIcon.Information);
           }
           catch (Exception ex)
           {
               MessageBox.Show("Error converting hex: " + ex.Message);
           }
       }

       // Converts a byte array back into a hexadecimal string.
       // Example usage:
       // byte[] bytes = new byte[] { 0x03, 0xE4, 0x0E, 0x86, 0x0B, 0xD8, 0x37, 0x75 };
       // string hex = ByteArrayToHexString(bytes);
       private string ByteArrayToHexString(byte[] bytes)
       {
           if (bytes == null || bytes.Length == 0)
             return string.Empty;

           StringBuilder sb = new StringBuilder(bytes.Length * 2);
           foreach (byte b in bytes)
           {
               sb.Append(b.ToString("X2"));
           }
           return sb.ToString();
       }

       // ===========================
       // Example: Using ByteArrayToHexString from a button click event
       // ===========================
       private void btnConvertBytes_Click(object sender, EventArgs e)
       {
           try
           {
               byte[] bytes = new byte[] { 0x03, 0xE4, 0x0E, 0x86, 0x0B, 0xD8, 0x37, 0x75 };

               // Call the conversion function (if made public or temporarily copied)
               string hex = ByteArrayToHexString(bytes);

              // Just for demonstration: show the hex string
              MessageBox.Show("Hex string: " + hex, "Byte Array to Hex Conversion", MessageBoxButtons.OK, MessageBoxIcon.Information);
           }
           catch (Exception ex)
           {
              MessageBox.Show("Error converting bytes: " + ex.Message);
           }
        }
        */

        /// Integration & Usage:
        /// - Simply instantiate the class and call VerifyFileIntegrity()
        /// - Example: 
        ///       AntiTamperSpcUtility antiTamper = new AntiTamperSpcUtility();
        ///       antiTamper.VerifyFileIntegrity(labUtil, picUtil);
    }