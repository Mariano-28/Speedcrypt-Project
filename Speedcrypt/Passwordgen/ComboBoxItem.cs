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
    /// ComboBoxItem: Simple container class for representing a named password pattern
    /// in UI ComboBox controls.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt Password Generator module and is intended
    /// to provide a convenient way to associate a display name with a pattern string
    /// for generating passwords.
    ///
    /// Responsibilities:
    /// - Store a human-readable Name for the ComboBox entry.
    /// - Store a corresponding Pattern string that defines password rules or templates.
    /// - Override ToString() to return the Name for display in UI controls.
    ///
    /// Responsibility for pattern correctness, integration, and security validation
    /// lies entirely with the author. This class does NOT perform password validation
    /// or generation by itself.
    /// </remarks>
    public class ComboBoxItem
    {
        public string Name { get; set; }
        public string Pattern { get; set; }
        public ComboBoxItem(string name, string pattern)
        {
            Name = name;
            Pattern = pattern;
        }
        public override string ToString() => Name;
    }
}