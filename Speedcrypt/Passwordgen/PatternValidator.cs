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
using System.Text.RegularExpressions;

namespace Speedcrypt.Passwordgen
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// PatternValidator: Validates password patterns for Speedcrypt
    /// Password Generator module.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and is used to validate
    /// different types of password patterns:
    /// - Standard patterns
    /// - Advanced patterns (regex-based with brackets and repetitions)
    /// - Corporate patterns (blocks, fixed prefixes, and repetition constraints)
    ///
    /// Responsibilities:
    /// - Ensure patterns contain only allowed characters.
    /// - Check for balanced brackets and braces.
    /// - Validate repetition ranges and format correctness.
    /// - Return a boolean indicating whether the pattern is syntactically valid.
    ///
    /// Responsibility for secure password generation using these patterns,
    /// including cryptographic correctness, lies entirely with the consuming code.
    /// </remarks>
    public static class PatternValidator
    {
        private const int MIN_PATTERN_LENGTH = 4; // minimum length for a valid sequence

        /// <summary>
        /// Validates that the input sequence contains only allowed characters
        /// and is a meaningful standard pattern.
        /// </summary>
        public static bool ValidatePattern(string input)
        {
            if (string.IsNullOrEmpty(input) || input.Length < MIN_PATTERN_LENGTH)
                return false;

            foreach (char c in input)
            {
                if (!IsAllowedChar(c))
                    return false;
            }

            bool hasUpper = false, hasLower = false;
            foreach (char c in input)
            {
                if (char.IsUpper(c)) hasUpper = true;
                if (char.IsLower(c)) hasLower = true;
            }
            if (!hasUpper || !hasLower)
                return false;

            return true;
        }

        /// <summary>
        /// Validates an advanced pattern using a strict regex format.
        /// </summary>
        public static bool ValidateAdvancedPattern(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;

            // Balanced brackets e parentesi graffe
            int square = 0, curly = 0;
            foreach (char c in input)
            {
                if (c == '[') square++;
                if (c == ']') square--;
                if (c == '{') curly++;
                if (c == '}') curly--;
                if (square < 0 || curly < 0) return false;
            }
            if (square != 0 || curly != 0) return false;

            // Token regex: [ABC], [a-z], [0-9], simboli, con ripetizioni opzionali
            var tokenRegex = new System.Text.RegularExpressions.Regex(
                @"^([A-Za-z0-9_\-\[\]\{\}!@#\$%\^&\*\(\)_=\+;:,.<>?]+)+$",
                System.Text.RegularExpressions.RegexOptions.Compiled
            );

            return tokenRegex.IsMatch(input);
        }

        /// <summary>
        /// Validates a corporate pattern with blocks, repetitions, and constraints.
        /// </summary>
        public static bool ValidateCorporatePattern(string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return false;

            // Minimum length requirement
            if (pattern.Length < 4) return false;

            // Special case: passphrase type o lunghezza/categorie
            if (pattern.StartsWith("Type=passphrase", StringComparison.OrdinalIgnoreCase)) return true;
            if (pattern.StartsWith("L=", StringComparison.OrdinalIgnoreCase)) return true;

            // Balanced brackets and braces
            int square = 0, curly = 0;
            foreach (char c in pattern)
            {
                if (c == '[') square++;
                else if (c == ']') square--;
                else if (c == '{') curly++;
                else if (c == '}') curly--;

                if (square < 0 || curly < 0) return false;

                // Allow only valid characters
                if (!char.IsLetterOrDigit(c) && c != '[' && c != ']' && c != '{' && c != '}' &&
                    c != '!' && c != '-' && c != '_' && c != ' ')
                {
                    return false;
                }
            }
            if (square != 0 || curly != 0) return false;

            // Validate repetitions {min,max}
            var regexBraces = new Regex(@"\{(\d+)(,(\d+))?\}");
            var matches = regexBraces.Matches(pattern);
            foreach (Match m in matches)
            {
                int minv = int.Parse(m.Groups[1].Value);
                if (m.Groups[3].Success)
                {
                    int maxv = int.Parse(m.Groups[3].Value);
                    if (maxv < minv) return false;
                }
            }

            // Token regex: permette prefissi fissi + blocchi con [A-Z],[0-9],[abc], simboli e ripetizioni
            var tokenRegex = new Regex(
                                       @"^[A-Za-z0-9_\-]*" +           // optional fixed prefix
                                       @"(\[[A-Za-z0-9_\-]+\](\{\d+(,\d+)?\})?)+$", // one or more blocks with optional repetitions
                                       RegexOptions.Compiled);

            return tokenRegex.IsMatch(pattern);
        }
        private static bool IsAllowedChar(char c)
        {
            return char.IsUpper(c) || char.IsLower(c) || char.IsDigit(c) || IsSymbol(c);
        }
        private static bool IsSymbol(char c)
        {
            return c == '!' || c == '-' || c == '_' || c == ' ';
        }
    }
}