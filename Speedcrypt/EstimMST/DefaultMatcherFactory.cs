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

using System.Linq;
using System.Collections.Generic;

// Speedcrypt
using Speedcrypt.UI;
using Speedcrypt.EstimMST.Matcher;

namespace Speedcrypt.EstimMST
{
    /// <summary>
    /// <para>This matcher factory will use all of the default password matchers.</para>
    /// 
    /// <para>Default dictionary matchers use the built-in word lists: passwords, english, male_names, female_names, surnames</para>
    /// <para>Also matching against: user data, all dictionaries with l33t substitutions</para>
    /// <para>Other default matchers: repeats, sequences, digits, years, dates, spatial</para>
    /// 
    /// <para>See <see cref="IMatcher"/> and the classes that implement it for more information on each kind of pattern matcher.</para>
    /// </summary>
    class DefaultMatcherFactory : IMatcherFactory
    {
        string diz = ForAllUnits.DirPath + "\\Dictionaries";
        List<IMatcher> matchers;

        /// <summary>
        /// Create a matcher factory that uses the default list of pattern matchers
        /// </summary>
        public DefaultMatcherFactory()
        {
            
            var dictionaryMatchers = new List<DictionaryMatcher>()
            {
                   
                // new DictionaryMatcher("passwords", diz + "\\passwords.lst"),
                new DictionaryMatcher("passwords", diz + "\\passwords.lst"),
                new DictionaryMatcher("english", diz + "\\english.lst"),
                new DictionaryMatcher("male_names", diz + "\\male_names.lst"),
                new DictionaryMatcher("female_names",diz + "\\female_names.lst"),
                new DictionaryMatcher("surnames", diz + "\\surnames.lst"),
            };

            matchers = new List<IMatcher> {
                new RepeatMatcher(),
                new SequenceMatcher(),
                new RegexMatcher("\\d{3,}", 10, true, "digits"),
                new RegexMatcher("19\\d\\d|200\\d|201\\d", 119, false, "year"),
                new DateMatcher(),
                new SpatialMatcher()
            };

            matchers.AddRange(dictionaryMatchers);
            matchers.Add(new L33tMatcher(dictionaryMatchers));
        }

        /// <summary>
        /// Get instances of pattern matchers, adding in per-password matchers on userInputs (and userInputs with l33t substitutions)
        /// </summary>
        /// <param name="userInputs">Enumerable of user information</param>
        /// <returns>Enumerable of matchers to use</returns>
        public IEnumerable<IMatcher> CreateMatchers(IEnumerable<string> userInputs)
        {
            var userInputDict = new DictionaryMatcher("user_inputs", userInputs);
            var leetUser = new L33tMatcher(userInputDict);

            return matchers.Union(new List<IMatcher> { userInputDict, leetUser });
        }
    }
}