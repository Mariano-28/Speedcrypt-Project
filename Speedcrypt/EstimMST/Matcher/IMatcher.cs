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

using System.Collections.Generic;

namespace Speedcrypt.EstimMST.Matcher
{
    /// <summary>
    /// All pattern matchers must implement the IMatcher interface.
    /// </summary>
    public interface IMatcher
    {
        /// <summary>
        /// This function is called once for each matcher for each password being evaluated. It should perform the matching process and return
        /// an enumerable of Match objects for each match found.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        IEnumerable<Match> MatchPassword(string password);
    }
}