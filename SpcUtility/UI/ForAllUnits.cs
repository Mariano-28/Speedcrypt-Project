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
// https://www.gnu.org/licenses/gpl-3.0.html

namespace SpcUtility.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// Centralized storage of global standard string constants.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Single source of truth for standard UI notification titles (Information, Warning, Error, Success).
    /// - Centralized definitions for specific application operations (Restore, Restore Error).
    /// - Consistent reference mapping for external documentation files (CHM and HTML utilities).
    /// - Fully static, final, and stable container; no computation or logic is performed.
    /// - Designed to minimize duplication across the SpcUtility application units.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class ForAllUnits
    {
        public const string Info = "Speedcrypt Information",
                            Warning = "Speedcrypt Warning",
                            Error = "Speedcrypt Error",
                            Success = "Speedcrypt Success",
                            Restore = "Speedcrypt Restore",
                            Restorerr = "Speedcrypt Restore Error",
                            HelpFile= "Speedcrypt.chm",
                            Utility = "Speedcrypt_Utility.htm";
    }
}