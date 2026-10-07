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
    /// PasswordProfile: Represents a complete set of configuration options
    /// for generating passwords within the Speedcrypt Password Generator module.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and serves as a data container
    /// for password generation parameters. It does not perform any computation or
    /// validation by itself.
    /// 
    /// Responsibilities:
    /// - Store password length and character set preferences (uppercase, lowercase, digits, symbols, etc.).
    /// - Support custom characters and pattern-based password generation.
    /// - Track mode flags for standard, advanced, and corporate patterns, as well as file-based and backup options.
    /// - Maintain entropy and user interaction settings for generating secure passwords.
    ///
    /// Responsibility for integrating these settings into a secure password
    /// generation algorithm, enforcing constraints, and validating outcomes
    /// lies entirely with the author or consuming code.
    /// </remarks>
    public class PasswordProfile
    {
        // Password settings
        public int Length { get; set; }
        public bool UseUppercase { get; set; }
        public bool UseLowercase { get; set; }
        public bool UseDigits { get; set; }
        public bool UseSymbols { get; set; }
        public bool UseMinus { get; set; }
        public bool UseUnderline { get; set; }
        public bool UseSpace { get; set; }
        public bool UseBrackets { get; set; }
        public bool UseLatin1 { get; set; }
        public bool UseCustomChars { get; set; }
        public string CustomChars { get; set; }
        public bool ForceEachCategory { get; set; }
        public bool NoConsecutive { get; set; }
        public bool PatternMode { get; set; }
        public string PatternText { get; set; }
        public string PatternValue { get; set; }
        public bool Permute { get; set; }
        public bool AdvancedPattern { get; set; }
        public int PseudoNumberGen { get; set; }
        public bool CharsetMode { get; set; }
        public bool StandardPatterns { get; set; }
        public bool AdvancedPatterns { get; set; }
        public bool CorporatePatterns { get; set; }
        public bool UserEntropyDialog { get; set; }
        public bool Backup { get; set; }
        public bool BckStandard { get; set; }
        public bool BckAdvanced { get; set; }
        public bool BckCorporate { get; set; }
        public bool UserFile { get; set; }
        public bool OriginalFile { get; set; }
    }
}