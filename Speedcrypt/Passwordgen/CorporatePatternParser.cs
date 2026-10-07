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

namespace Speedcrypt.Passwordgen
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CorporatePatternParser: Parses corporate password pattern strings into numeric requirements.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt Password Generator module and is intended
    /// for developers who need to extract numeric constraints from a pattern string.
    ///
    /// Responsibilities:
    /// - Parse pattern strings like "L=12; U>=2; Lw>=3; D>=2; S>=1" into integers.
    /// - Provide output values for length, upper-case, lower-case, digits, and symbols.
    /// - Return true if a valid length is present, false otherwise.
    ///
    /// Responsibility for pattern correctness, integration, and security validation
    /// lies entirely with the author. This class does NOT validate passwords or enforce
    /// rules beyond parsing.
    /// </remarks>
    public static class CorporatePatternParser
    {
        public static bool TryParse(string pattern, out int length, out int upper, out int lower, out int digits, out int symbols)
        {
            length = upper = lower = digits = symbols = 0;

            if (string.IsNullOrWhiteSpace(pattern))
                return false;

            string[] parts = pattern.Split(';');
            foreach (string part in parts)
            {
                string p = part.Trim();
                if (p.StartsWith("L=")) int.TryParse(p.Substring(2), out length);
                else if (p.StartsWith("U>=")) int.TryParse(p.Substring(3), out upper);
                else if (p.StartsWith("Lw>=")) int.TryParse(p.Substring(4), out lower);
                else if (p.StartsWith("D>=")) int.TryParse(p.Substring(3), out digits);
                else if (p.StartsWith("S>=")) int.TryParse(p.Substring(3), out symbols);
            }

            return length > 0;
        }
    }
}