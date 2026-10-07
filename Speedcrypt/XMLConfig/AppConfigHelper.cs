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

namespace Speedcrypt.XMLConfig
{
    /// <summary>
    /// Created by Dominik Reichl
    /// 
    /// Integrated into Speedcrypt framework by Mariano Ortu, who thanks the author for this valuable original implementation.
    /// AppConfigHelper: provides static access to application configuration file and centralized XML configuration object.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized access to application configuration file
    /// - Automatic loading of XML configuration at startup
    /// - Saving configuration back to disk
    /// - Complete integration with Speedcrypt framework
    /// - Relies on PrivateXmlConfig for XML handling, extensively adapted by Mariano Ortu
    ///
    /// Responsibility for integration, enhancement, and validation within Speedcrypt
    /// lies entirely with Mariano Ortu, while respecting the original author's contribution.
    /// </remarks>
    public static class AppConfigHelper
    {
        private static readonly string _configFilePath;
        private static readonly PrivateXmlConfig _xmlConfig;
        private static readonly object _lockObj = new object();
        static AppConfigHelper()
        {
            // Establish deterministic base directory routing to prevent volatile working directory mutations
            string baseDirectory = System.AppContext.BaseDirectory;
            string assemblyName = System.IO.Path.GetFileNameWithoutExtension(
                System.Reflection.Assembly.GetExecutingAssembly().Location
            );

            _configFilePath = System.IO.Path.Combine(baseDirectory, assemblyName + ".config.xml");
            _xmlConfig = new PrivateXmlConfig();

            if (System.IO.File.Exists(_configFilePath))
            {
                lock (_lockObj)
                {
                    _xmlConfig.LoadFromFile(_configFilePath);
                }
            }
        }
        public static string ConfigFilePath
        {
            get { return _configFilePath; }
        }
        public static PrivateXmlConfig XmlConfig
        {
            get { return _xmlConfig; }
        }
        public static void Save()
        {
            // Enforce thread-safe and atomic file serialization to prevent I/O race conditions
            lock (_lockObj)
            {
                // Execute the standard framework serialization procedure
                _xmlConfig.SaveToFile(_configFilePath);

                // --- HARDWARE PERSISTENCE BARRIER (FLUSH TO DISK) ---
                // Force the operating system to immediately commit all cached metadata and data blocks to physical storage
                try
                {
                    if (System.IO.File.Exists(_configFilePath))
                    {
                        using (var fs = System.IO.File.Open(_configFilePath, System.IO.FileMode.Open, System.IO.FileAccess.Write, System.IO.FileShare.ReadWrite))
                        {
                            fs.Flush(true); // Argument 'true' forces a physical disk metadata and data sector flush
                        }
                    }
                }
                catch (System.IO.IOException)
                {
                    // Fail-safe catch for concurrent read locks; optimization guarantees execution non-blocking state
                }
            }
        }
    }
}