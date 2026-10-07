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

using System.IO;
using System.IO.Compression;

// Speedcrypt
using Speedcrypt.UI;

namespace Speedcrypt.Interfaces
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ConfigExportManager: Infrastructure support class responsible for
    /// exporting the XML configuration file within Speedcrypt.   
    /// 
    /// This class is NOT a cryptographic component.
    /// It does not perform encryption, decryption, hashing, or validation.
    ///
    /// Its sole responsibility is to safely copy or compress the system
    /// configuration file to a designated backup or export path.
    ///
    /// The export logic is purely administrative and file-system-based.
    /// No cryptographic material is generated, processed, or evaluated.
    ///
    /// Special constraint:
    /// Exported configuration files may contain sensitive metadata.
    /// Transmission, access control, and environmental protection of the
    /// exported files are outside the scope of this class.
    ///
    /// Designed for configuration portability, lifecycle control,
    /// and internal consistency only.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>  
    public class ConfigExportManager
    {
        private readonly string _configPath;
        public ConfigExportManager()
        {
            _configPath = ForAllUnits.ConfigPath;
        }

        /// <summary>
        /// Exports the application configuration database to a designated path, supporting optional compression overhead reduction via defect-free ZIP streaming.
        /// </summary>
        /// <param name="destinationPath">The persistent system storage absolute path targeting the generated file output.</param>
        /// <param name="compressed">True activates compressed ZIP deployment packaging routines; false delegates to low-level raw byte copying loops.</param>
        public void Export(string destinationPath, bool compressed)
        {
            if (!File.Exists(_configPath))
                throw new FileNotFoundException("Configuration file not found.");

            if (!compressed)
            {
                File.Copy(_configPath, destinationPath, true);
                return;
            }

            using (FileStream zipToOpen = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                using (ZipArchive archive = new ZipArchive(zipToOpen, ZipArchiveMode.Create, leaveOpen: true))
                {
                    ZipArchiveEntry entry = archive.CreateEntry("Speedcrypt.config.xml");

                    using (Stream entryStream = entry.Open())
                    using (FileStream fs = new FileStream(_configPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        fs.CopyTo(entryStream);
                    }
                }

                // Forces the underlying stream architecture to commit all buffered byte fragments directly to persistent physical media blocks
                zipToOpen.Flush(true);
            }
        }
    }
}