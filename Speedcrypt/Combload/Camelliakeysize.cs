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
    /// Camelliakeysize: Defines the valid key sizes for the Camellia block cipher.
    /// </summary>
    ///
    /// <remarks>
    /// This enum specifies the allowed key lengths for Camellia encryption
    /// within the Speedcrypt framework.
    ///
    /// Conceptually inspired by standard cryptographic specifications for Camellia,
    /// ensuring deterministic and secure behavior.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public enum Camelliakeysize: int
    {
        K128 = 128,
        K192 = 192,
        K256 = 256,
    }
}