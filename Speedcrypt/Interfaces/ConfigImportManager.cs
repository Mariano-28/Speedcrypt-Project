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
using System.IO.Compression;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.XMLConfig;

namespace Speedcrypt.Interfaces
{
    /// Summary
    /// Created by Mariano Ortu
    /// 
    /// ConfigImportManager: Infrastructure support class responsible for
    /// importing and applying XML configuration files within Speedcrypt.  
    /// 
    /// This class is NOT a cryptographic component.
    /// It does not perform encryption, decryption, hashing, or validation.
    ///
    /// Its sole responsibility is to safely extract, overwrite, and reload
    /// the system configuration from a standard XML file or a compressed archive.
    ///
    /// The import logic is purely administrative and file-system-based.
    /// No cryptographic material is generated, processed, or evaluated.
    ///
    /// Special constraint:
    /// Importing an unverified configuration file can alter system behavior.
    /// Integrity checks and source validation of the package before deployment
    /// are outside the scope of this class.
    ///
    /// Designed for configuration restoration, lifecycle control,
    /// and internal consistency only.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks> 
    public class ConfigImportManager
    {
        private readonly string _configPath;
        public ConfigImportManager()
        {
            _configPath = ForAllUnits.ConfigPath;
        }
        public void ImportAndApply(string sourcePath)
        {
            Import(sourcePath);
            Apply();
        }
        public void Import(string sourcePath)
        {
            if (!File.Exists(sourcePath))
                throw new FileNotFoundException("Import file not found.");

            string extension = Path.GetExtension(sourcePath).ToLowerInvariant();

            if (extension == ".xml")
            {
                File.Copy(sourcePath, _configPath, true);
                return;
            }

            if (extension == ".zip")
            {
                using (ZipArchive archive = ZipFile.OpenRead(sourcePath))
                {
                    ZipArchiveEntry entry = archive.GetEntry("Speedcrypt.config.xml");

                    if (entry == null)
                        throw new InvalidDataException("Config file not found inside archive.");

                    using (Stream input = entry.Open())
                    using (FileStream output = new FileStream(_configPath, FileMode.Create, FileAccess.Write))
                    {
                        input.CopyTo(output);
                    }
                }

                return;
            }

            throw new NotSupportedException("Unsupported file format.");
        }
        private void Apply()
        {
            AppConfigHelper.XmlConfig.Clear();
            AppConfigHelper.XmlConfig.LoadFromFile(AppConfigHelper.ConfigFilePath);
        }
    } 
}