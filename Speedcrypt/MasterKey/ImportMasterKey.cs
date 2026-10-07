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
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.XMLConfig;
using Speedcrypt.StringCrypto;
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.MasterKey
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ImportMasterKey: Handles the import of an external Speedcrypt master key file (.msk).
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project but is NOT a cryptographic algorithm.
    /// Its sole responsibility is to read a master key file, verify its timestamp against
    /// the configuration, and load it securely into the application using the Keymaster.
    ///
    /// 📒 Security Note:
    /// - The actual cryptographic import, validation, and handling is delegated to Keymasterexpoimpo.
    /// - This class only orchestrates file selection, configuration lookup, and secure wiping of temporary passwords.
    /// - It must NEVER be considered a cryptographic trust component by itself.
    ///
    /// Responsibilities:
    /// - Open file dialog and select .msk files.
    /// - Compare file creation timestamp with stored configuration.
    /// - Determine the last imported algorithm for proper engine initialization.
    /// - Call Keymasterexpoimpo to perform the actual import.
    /// - Securely wipe password fields after successful import.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and cryptographic validation lies entirely with the author.
    /// </remarks>
    public class ImportMasterKey
    {
        private Control _owner;
        private ListView listSett;
        private dynamic secPasw;
        private dynamic secMasKey;
        private Keymasterexpoimpo _keymaster;
        public ImportMasterKey(Control owner, ListView listSettings, dynamic passwordControl, dynamic masterKeyControl)
        {
            _owner = owner;
            listSett = listSettings;
            secPasw = passwordControl;
            secMasKey = masterKeyControl;
        }
        public void Execute()
        {
            try
            {
                string LastImportedAlgorithm = string.Empty;
                string ImportedFilePath = null;
                DateTime ImportedFileTimestamp = DateTime.MinValue;

                using (OpenFileDialog ofd = new OpenFileDialog
                {
                    Title = "Speedcrypt Password Import...",
                    Filter = "msk files (*.msk)|*.msk"
                })
                {
                    if (ofd.ShowDialog() != DialogResult.OK) return;

                    ImportedFilePath = ofd.FileName;
                    ImportedFileTimestamp = File.GetCreationTimeUtc(ImportedFilePath);

                    // Format user file timestamp
                    string userFileStamp = ImportedFileTimestamp.ToString("yyyyMMddHHmmssfff");

                    // Search for matching Master Key in configuration
                    foreach (var kvp in AppConfigHelper.XmlConfig.GetAllKeyValuePairs())
                    {
                        string[] parts = kvp.Value.Split('|');
                        if (parts.Length >= 3)
                        {
                            string configPath = parts[0];
                            string configTimestamp = parts[1];
                            string algorithm = parts[2];

                            if (ImportedFilePath == configPath && userFileStamp == configTimestamp)
                            {
                                LastImportedAlgorithm = algorithm; // store found algorithm
                                break;
                            }
                        }
                    }
                }

                // Create Keymaster with the proper engineTextProvider returning LastImportedAlgorithm
                _keymaster = new Keymasterexpoimpo(cryptoService: new CryptoAdapter(roundsProvider: () => Convert.ToInt32(listSett.Items[3].SubItems[2].Text)),
                                                   engineTextProvider: () => LastImportedAlgorithm ?? "AES");

                string errorMessage;
                bool imported = _keymaster.ImportFromFile(ImportedFilePath, secPasw, secMasKey, out errorMessage);

                if (imported)
                {
                    SecureWipe.WipeSecureTextBox(secPasw);
                }

                if (!imported && !string.IsNullOrEmpty(errorMessage))
                {
                    try
                    {
                        throw new Exception(errorMessage);
                    }
                    catch (Exception ex)
                    {
                        CentralLog.LogException(ex, "Master key", "Import Master Key Failed!");
                    }
                }
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "Master key", "Import Master Key Failed! ");
            }
        }
    }
}