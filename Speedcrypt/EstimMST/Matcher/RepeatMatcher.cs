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

namespace Speedcrypt.EstimMST.Matcher
{
    /// <summary>
    /// Match repeated characters in the password (repeats must be more than two characters long to count)
    /// </summary>
    public class RepeatMatcher : IMatcher
    {
        const string RepeatPattern = "repeat";

        /// <summary>
        /// Find repeat matches in <paramref name="password"/>
        /// </summary>
        /// <param name="password">The password to check</param>
        /// <returns>List of repeat matches</returns>
        /// <seealso cref="RepeatMatch"/>
        public IEnumerable<Match> MatchPassword(string password)
        {
            var matches = new List<Match>();

            // Be sure to not count groups of one or two characters
            return password.GroupAdjacent(c => c).Where(g => g.Count() > 2).Select(g => new RepeatMatch {
                Pattern = RepeatPattern,
                Token = password.Substring(g.StartIndex, g.EndIndex - g.StartIndex + 1),
                i = g.StartIndex,
                j = g.EndIndex,
                Entropy = CalculateEntropy(password.Substring(g.StartIndex, g.EndIndex - g.StartIndex + 1)),
                RepeatChar = g.Key
            });
        }
        private double CalculateEntropy(string match)
        {
            return Math.Log(PasswordScoring.PasswordCardinality(match) * match.Length, 2);
        }
    }

    /// <summary>
    /// A match found with the RepeatMatcher
    /// </summary>
    public class RepeatMatch : Match
    {
        /// <summary>
        /// The character that was repeated
        /// </summary>
        public char RepeatChar { get; set; }
    }
}