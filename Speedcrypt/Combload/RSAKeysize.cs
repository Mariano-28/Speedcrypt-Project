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
    /// RSAKeysize: Enum specifying allowed key sizes for RSA asymmetric encryption.
    /// </summary>
    ///
    /// <remarks>
    /// This enum defines the standard RSA key sizes supported within the Speedcrypt framework:
    /// - 2048-bit, 3072-bit, and 4096-bit keys
    ///
    /// Technical note:
    /// - These sizes reflect current best-practice security recommendations
    /// - Enum ensures type-safety when selecting key size in the Speedcrypt Autotest or UI
    /// 
    ////// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public enum  RSAKeysize: int
    {
        K2048 = 2048,
        K3072 = 3072,
        K4096 = 4096,
    }
}