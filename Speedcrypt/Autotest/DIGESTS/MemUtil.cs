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
using System.Text;
using System.Diagnostics;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// MemUtil: Utility class for memory and byte array manipulations.
    /// /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// Provides:
    /// - Hexadecimal string ↔ byte array conversion
    /// - Byte array equality comparison
    /// 
    /// All methods are deterministic, safe, and do not perform external logging.
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </summary>
    /// <remarks>
    /// HexStringToByteArray: Converts a hexadecimal string (even-length only) to a byte array.
    /// ByteArrayToHexString: Converts a byte array to its hexadecimal string representation.
    /// ArraysEqual: Compares two byte arrays for equality in length and content.
    /// 
    /// This utility class is intended for cryptographic and low-level memory operations,
    /// avoiding any external side-effects and ensuring safe handling of null or invalid inputs.
    /// </remarks>
    public static class MemUtil
    {
        /// <summary>
        /// Convert a hexadecimal string to a byte array. The input string must be
        /// even (i.e. its length is a multiple of 2).
        /// </summary>
        /// <param name="strHexString">String containing hexadecimal characters.</param>
        /// <returns>Returns a byte array. Returns <c>null</c> if the string parameter
        /// was <c>null</c> or is an uneven string (i.e. if its length isn't a
        /// multiple of 2).</returns>
        /// <exception cref="System.ArgumentNullException">Thrown if <paramref name="strHexString" />
        /// is <c>null</c>.</exception>
        public static byte[] HexStringToByteArray(string strHexString)
        {
            Debug.Assert(strHexString != null); if (strHexString == null) throw new ArgumentNullException("strHexString");

            int nStrLen = strHexString.Length;
            if ((nStrLen & 1) != 0) return null; // Only even strings supported

            byte[] pb = new byte[nStrLen / 2];
            byte bt;
            char ch;

            for (int i = 0; i < nStrLen; ++i)
            {
                ch = strHexString[i];
                if ((ch == ' ') || (ch == '\t') || (ch == '\r') || (ch == '\n')) continue;

                if ((ch >= '0') && (ch <= '9'))
                    bt = (byte)(ch - '0');
                else if ((ch >= 'a') && (ch <= 'f'))
                    bt = (byte)(ch - 'a' + 10);
                else if ((ch >= 'A') && (ch <= 'F'))
                    bt = (byte)(ch - 'A' + 10);
                else bt = 0;

                bt <<= 4;
                ++i;

                ch = strHexString[i];
                if ((ch >= '0') && (ch <= '9'))
                    bt += (byte)(ch - '0');
                else if ((ch >= 'a') && (ch <= 'f'))
                    bt += (byte)(ch - 'a' + 10);
                else if ((ch >= 'A') && (ch <= 'F'))
                    bt += (byte)(ch - 'A' + 10);

                pb[i / 2] = bt;
            }

            return pb;
        }

        /// <summary>
        /// Convert a byte array to a hexadecimal string.
        /// </summary>
        /// <param name="pbArray">Input byte array.</param>
        /// <returns>Returns the hexadecimal string representing the byte
        /// array. Returns <c>null</c>, if the input byte array was <c>null</c>. Returns
        /// an empty string, if the input byte array has length 0.</returns>
        public static string ByteArrayToHexString(byte[] pbArray)
        {
            if (pbArray == null) return null;

            int nLen = pbArray.Length;
            if (nLen == 0) return string.Empty;

            StringBuilder sb = new StringBuilder();

            byte bt, btHigh, btLow;
            for (int i = 0; i < nLen; ++i)
            {
                bt = pbArray[i];
                btHigh = bt; btHigh >>= 4;
                btLow = (byte)(bt & 0x0F);

                if (btHigh >= 10) sb.Append((char)('A' + btHigh - 10));
                else sb.Append((char)('0' + btHigh));

                if (btLow >= 10) sb.Append((char)('A' + btLow - 10));
                else sb.Append((char)('0' + btLow));
            }

            return sb.ToString();
        }
        public static bool ArraysEqual(byte[] pb1, byte[] pb2)
        {
            if ((pb1 == null) || (pb2 == null)) { Debug.Assert(false); return false; }
            if (pb1.Length != pb2.Length) return false;

            for (int i = 0; i < pb1.Length; ++i)
            {
                if (pb1[i] != pb2[i]) return false;
            }

            return true;
        }
    }
}