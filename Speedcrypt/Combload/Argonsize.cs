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
    /// Argonsize: Defines valid key sizes for Argon2-based operations.
    /// </summary>
    ///
    /// <remarks>
    /// This enum specifies the allowable memory block sizes or iteration sizes
    /// for Argon2 cryptographic derivations within the Speedcrypt framework.
    ///
    /// Conceptually inspired by established cryptographic libraries and standards,
    /// ensuring safe and deterministic parameterization for hashing operations.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public enum Argonsize: int
    {
        S8 = 8,
        S16 = 16,
        S32 = 32,
        S64 = 64,
        S128 =128,
        S256 = 256,
        S512 = 512,
        S1024 = 1024,
    }
}