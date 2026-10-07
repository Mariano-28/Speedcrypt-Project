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

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// PatternHardValidator: Provides structural validation for user-defined password patterns.
    /// Ensures that patterns are syntactically valid and, where possible, rejects
    /// clearly weak or degenerate structures without altering Speedcrypt’s core behavior.
    /// </summary>
    ///
    /// <remarks>
    /// This component ensures:
    /// - Validation is strictly syntactic at its core level.
    /// - Optional detection of obviously weak structural patterns (e.g. full repetition, trivial alternation).
    /// - No subjective scoring or “quality judgment” of patterns beyond structural sanity checks.
    /// - Safe operation without impacting built-in Speedcrypt pattern libraries.
    /// - Isolation of validation logic from password generation engine.
    /// - Designed to support user-defined patterns without restricting creativity unnecessarily.
    /// - Hard rejection only applies to clearly invalid or structurally degenerate patterns.
    /// - All borderline or unconventional but syntactically valid patterns remain user responsibility.
    ///
    /// Design principle:
    /// Speedcrypt validates correctness and assists where possible in identifying obvious weaknesses,
    /// but does not enforce absolute strength constraints on user-defined patterns.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class PatternHardValidator
    {
        /// <summary>
        /// Returns true only if the pattern is structurally acceptable.
        /// </summary>
        public static bool IsValid(string pattern)
        {
            if (string.IsNullOrEmpty(pattern))
                return false;

            // 1. Reject full repetition patterns
            if (IsFullyPeriodic(pattern))
                return false;

            // 2. Reject excessive consecutive repetition
            if (HasLongRuns(pattern, 4))
                return false;

            // 3. Reject single-class patterns (too weak structure)
            if (HasOnlyOneCharacterClass(pattern))
                return false;

            // 4. Reject trivial alternation (A1A1A1…)
            if (IsSimpleAlternation(pattern))
                return false;

            return true;
        }
        private static bool IsFullyPeriodic(string s)
        {
            for (int len = 1; len <= s.Length / 2; len++)
            {
                if (s.Length % len != 0)
                    continue;

                string chunk = s.Substring(0, len);
                bool ok = true;

                for (int i = 0; i < s.Length; i += len)
                {
                    if (s.Substring(i, len) != chunk)
                    {
                        ok = false;
                        break;
                    }
                }

                if (ok)
                    return true;
            }

            return false;
        }
        private static bool HasLongRuns(string s, int maxRun)
        {
            int run = 1;

            for (int i = 1; i < s.Length; i++)
            {
                if (s[i] == s[i - 1])
                {
                    run++;
                    if (run >= maxRun)
                        return true;
                }
                else
                {
                    run = 1;
                }
            }

            return false;
        }
        private static bool HasOnlyOneCharacterClass(string s)
        {
            bool hasUpper = false;
            bool hasLower = false;
            bool hasDigit = false;
            bool hasSymbol = false;

            foreach (char c in s)
            {
                if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsLower(c)) hasLower = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else hasSymbol = true;
            }

            int classes = 0;
            if (hasUpper) classes++;
            if (hasLower) classes++;
            if (hasDigit) classes++;
            if (hasSymbol) classes++;

            return classes <= 1;
        }
        private static bool IsSimpleAlternation(string s)
        {
            if (s.Length < 4)
                return false;

            string p1 = s.Substring(0, 2);

            for (int i = 0; i < s.Length; i += 2)
            {
                if (i + 2 > s.Length)
                    break;

                if (s.Substring(i, 2) != p1)
                    return false;
            }

            return true;
        }
    }
}