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
    /// PatternItem: Represents a password pattern entry for the Speedcrypt
    /// Password Generator module.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and is used to store
    /// information about a single password pattern.
    ///
    /// Responsibilities:
    /// - Store the pattern name and its corresponding string.
    /// - Indicate whether the pattern is considered advanced.
    /// - Provide a readable string representation (Name) for UI elements.
    ///
    /// Responsibility for using these patterns securely in password
    /// generation lies entirely with the consuming code.
    /// </remarks>
    public class PatternItem
    {
        public string Name { get; }
        public string Pattern { get; }
        public bool Advanced { get; }

        public PatternItem(string name, string pattern, bool advanced = false)
        {
            Name = name;
            Pattern = pattern;
            Advanced = advanced;
        }
        public override string ToString() => Name;
    }
}