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

namespace Speedcrypt.Securerase.Helper
{
    /// <summary>
    ///     Helper class with some useful converters.
    /// </summary>
    public static class ConversionHelper
    {
        /// <summary>
        ///     Converts an integer to a little endian byte array.
        /// </summary>
        /// <param name="data">An integer to convert.</param>
        /// <returns>A little endian byte array.</returns>
        public static byte[] IntegerToLittleEndian(int data)
        {
            var le = new byte[8];
            le[0] = (byte) data;
            le[1] = (byte) (((uint) data >> 8) & 0xFF);
            le[2] = (byte) (((uint) data >> 16) & 0xFF);
            le[3] = (byte) (((uint) data >> 24) & 0xFF);
            return le;
        }
    }
}