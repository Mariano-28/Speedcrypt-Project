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
using System.Windows.Forms;
using System.Security.Cryptography;

namespace Speedcrypt.Protect
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// HashGenerator: Developer-side hash regeneration utility.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the
    /// anti-tamper protection and build verification subsystem.
    ///
    /// Intended audience:
    /// - Developers recompiling or modifying the Speedcrypt project.
    /// - Maintainers responsible for final delivery and integrity sealing.
    /// - Auditors verifying binary consistency after a rebuild.
    ///
    /// Purpose:
    /// - Generate SHA-256 hashes for all critical project binaries.
    /// - Produce copy-paste ready byte arrays for AntiTamperProtection.
    /// - Allow safe and deterministic regeneration of hashes after recompilation.
    /// - Reduce human error during final delivery and integrity updates.
    ///
    /// Design notes:
    /// - This class is NOT used at runtime.
    /// - It is intended strictly for development and build-time operations.
    /// - Hashes are generated directly from the compiled binaries on disk.
    /// - Output format is intentionally verbose and explicit for auditability.
    ///
    /// Security scope and limits:
    /// - This class does not protect the application by itself.
    /// - It assists the anti-tamper mechanism by providing trusted hash material.
    /// - If a developer is compromised, regenerated hashes will reflect that state.
    /// - No hash-based protection is meaningful without a trusted build environment.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and overall security validation lies entirely with the author.
    /// </remarks>
    public static class HashGenerator
    {
        /// <summary>
        /// Generates SHA-256 hashes for all critical files in the project directory
        /// and returns them in C# byte array format with file names as comments.
        /// </summary>
        /// <returns>String ready for copy-paste into SpeedcryptProtection.</returns>
        /// <exception cref="FileNotFoundException">Thrown if a file is missing.</exception>
        public static string GenerateHashesWithFileNames()
        {
            string basePath = AppDomain.CurrentDomain.BaseDirectory;

            string[] files =
            {
            "OpenGost.Security.Cryptography.dll",
            "Speedcrypt.exe",
            "Blake3Core.dll",
            "BouncyCastle.Cryptography.dll",
            "GostCryptography.dll",
            "Konscious.Security.Cryptography.Argon2.dll",
            "Konscious.Security.Cryptography.Blake2.dll",
            "Microsoft.ApplicationInsights.dll",
            "System.Reflection.Metadata.dll",
            "System.Runtime.CompilerServices.Unsafe.dll",
            "System.Threading.Tasks.Extensions.dll",
            "System.ValueTuple.dll",
            "Newtonsoft.Json.dll",
            "System.Buffers.dll",
            "System.Collections.Immutable.dll",
            "System.Diagnostics.DiagnosticSource.dll",
            "System.Formats.Asn1.dll",
            "System.Memory.dll",
            "System.Numerics.Vectors.dll"
        };

            StringBuilder sb = new StringBuilder(2048);

            using (SHA256 sha = SHA256.Create())
            {
                foreach (string file in files)
                {
                    string path = Path.Combine(basePath, file);

                    if (!File.Exists(path))
                        throw new FileNotFoundException("File not found: " + path);

                    byte[] hash;
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        hash = sha.ComputeHash(fs);
                    }

                    // Comment with file name
                    sb.AppendLine("// " + file);

                    // Hash in new byte[] { 0x.. } style
                    sb.AppendLine("new byte[] { " + string.Join(", ", hash.Select(b => "0x" + b.ToString("X2"))) + " },");
                    sb.AppendLine();
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// Copies all hashes with file names to the clipboard.
        /// </summary>
        public static void CopyHashesToClipboard()
        {
            string hashes = GenerateHashesWithFileNames();
            Clipboard.SetText(hashes);
            MessageBox.Show("Hashes with file names copied to clipboard!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
    /// You can put the class call into a button, and it will generate the hashes you need within the project.
    /// Usage: HashGenerator.CopyHashesToClipboard();
}