/// Speedcrypt software - The Open-Source for encrypt and decrypt files
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

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// KeyPathValidator: Utility class that validates the presence of the required
    /// PGP key files inside a specified directory.
    /// </summary>
    /// 
    /// <remarks>
    /// This validator ensures that:
    /// - The provided folder path is not null or empty
    /// - The directory exists on disk
    /// - Both required PGP key files are present:
    ///   - PGPPrivateKeyRSA.asc
    ///   - PGPPublicKeyRSA.asc
    ///
    /// The method is designed to safely validate paths originating
    /// from user interface controls such as ComboBox, TextBox, or Label.
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public sealed class KeyPathValidator
    {
        // Required private key filename
        private const string PrivateKeyFileName = "PGPPrivateKeyRSA.asc";

        // Required public key filename
        private const string PublicKeyFileName = "PGPPublicKeyRSA.asc";

        /// <summary>
        /// Validates that the specified directory exists and contains both required PGP key files.
        /// </summary>
        /// <param name="folderPath">
        /// Absolute or relative directory path coming from any UI control (ComboBox, TextBox, Label, etc.).
        /// </param>
        /// <returns>
        /// true  = directory exists and both key files are present.
        /// false = directory is invalid or one or both key files are missing.
        /// </returns>
        public static bool Validate(string folderPath)
        {
            // Reject null reference immediately
            if (folderPath == null)
                return false;

            // Reject empty or whitespace-only paths
            if (folderPath.Trim().Length == 0)
                return false;

            // Verify that the directory exists on disk
            if (!System.IO.Directory.Exists(folderPath))
                return false;

            // Build full path for private key file
            string privateKeyFullPath = System.IO.Path.Combine(folderPath, PrivateKeyFileName);

            // Build full path for public key file
            string publicKeyFullPath = System.IO.Path.Combine(folderPath, PublicKeyFileName);

            // Verify existence of private key file
            if (!System.IO.File.Exists(privateKeyFullPath))
                return false;

            // Verify existence of public key file
            if (!System.IO.File.Exists(publicKeyFullPath))
                return false;

            // All required conditions satisfied: directory and both key files exist
            return true;
        }
    }
}