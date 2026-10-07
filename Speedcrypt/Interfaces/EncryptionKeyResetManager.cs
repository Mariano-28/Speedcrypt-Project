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
using System.Linq;
using System.Collections.Generic;

// Spedcrypt
using Speedcrypt.XMLConfig;

namespace Speedcrypt.Interfaces
{
    /// Summary
    /// Created by Mariano Ortu
    /// 
    /// EncryptionKeyResetManager: Infrastructure support class responsible for
    /// removing stored configuration keys associated with selected engines within Speedcrypt.
    /// 
    /// This class is NOT a cryptographic component.
    /// It does not perform encryption, decryption, hashing, or validation.
    ///
    /// Its sole responsibility is to scan the XML configuration and safely remove
    /// text-based key entries or metadata matching known engine prefixes.
    ///
    /// The deletion logic is purely administrative and configuration-based.
    /// No cryptographic material is generated, processed, or evaluated.
    ///
    /// Special constraint:
    /// This class only performs administrative cleanup of structural elements.
    /// It does not securely wipe data from memory or physical storage disks.
    ///
    /// Designed for configuration maintenance, lifecycle control,
    /// and internal consistency only.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>   
    public class EncryptionKeyResetManager
    {
        private static readonly Dictionary<string, string> EnginePrefixes =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
        { "AES", "AESEencryptedSalt-" },
        { "PGP", "PGPEencryptedSalt-" },
        { "IDEA", "IDEAEencryptedSalt-" },
        { "GOST", "GOSTEencryptedSalt-" },
        { "AES-GCM", "AES-GCMEencryptedSalt-" },
        { "SERPENT", "SERPENTEencryptedSalt-" },
        { "TWOFISH", "TWOFISHEencryptedSalt-" },
        { "CAMELLIA", "CAMELLIAEencryptedSalt-" },
        { "THREEFISH", "THREEFISHEencryptedSalt-" },
        { "KUZNYECHIK", "KUZNYECHIKEencryptedSalt-" },
        { "XCHACHA20-POLY1305", "XCHACHA20POLY1305EencryptedSalt-" }
        };
        public void DeleteKeys(List<string> selectedEngines)
        {
            if (selectedEngines == null || selectedEngines.Count == 0)
                return;

            PrivateXmlConfig config = AppConfigHelper.XmlConfig;

            foreach (string engine in selectedEngines)
            {
                if (!EnginePrefixes.TryGetValue(engine, out string prefix))
                    continue;

                List<string> keysToDelete = config
                    .GetAllKeyValuePairs()
                    .Keys
                    .Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                foreach (string key in keysToDelete)
                {
                    config.RemoveKey(key);
                }
            }

            AppConfigHelper.Save();
        }
    }
}