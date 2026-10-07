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

namespace Speedcrypt.Combload
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Threefishkeysize: Enum specifying allowed key sizes for the Threefish block cipher.
    /// </summary>
    ///
    /// <remarks>
    /// This enum defines the standard Threefish key sizes supported within the Speedcrypt framework:
    /// - 256-bit, 512-bit, and 1024-bit keys
    ///
    /// Technical note:
    /// - These sizes align with the Threefish specification for secure block cipher operations.
    /// - Enum ensures type-safety when selecting key size in Speedcrypt Autotest or UI.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public enum Threefishkeysize: int
    {
        K256 = 256,
        K512 = 512,
        K1024 = 1024,
    }
}