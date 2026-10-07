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

using System.IO;
using System.Linq;
using System.Xml.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Minipgppathvalidator: Checks whether the Speedcrypt configuration file
    /// contains at least one EnginePGP fingerprint entry.
    /// </summary>
    ///
    /// <remarks>
    /// This class reads the Speedcrypt.config.xml file from the executable directory
    /// and verifies the presence of any XML attribute "Value" ending with "|EnginePGP".
    ///
    /// The validation is simple and non-intrusive:
    /// - Read-only access to configuration file
    /// - Returns false on any error or missing file
    /// - No path comparison or transformation is performed
    ///
    /// This class is intended as a lightweight feature flag check for EnginePGP support.
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>  
    public static class MiniPgpPathValidator
    {
        private const string ConfigFileName = "Speedcrypt.config.xml";
        private const string Fingerprint = "|EnginePGP";

        public static bool HasPgpEngine(TextBox txt)
        {
            try
            {
                if (txt == null || string.IsNullOrWhiteSpace(txt.Text))
                    return false;

                string label = txt.Text.Trim();

                string path = Path.Combine(
                    Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                    ConfigFileName
                );

                if (!File.Exists(path))
                    return false;

                XDocument doc = XDocument.Load(path);

                return doc.Descendants().Attributes("Value").Select(a => a.Value).Any(v =>  v.Contains(Fingerprint) &&  v.Contains(label) &&
                       v.Split('|').Any(p =>  File.Exists(p) || Directory.Exists(p)));
            }
            catch
            {
                return false;
            }
        }
    }
}