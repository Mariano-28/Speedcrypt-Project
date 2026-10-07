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
using System.Security;
using System.Runtime.InteropServices;
public static class AdapterCharString
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// SecureStringToCharArray: Converts a SecureString into a mutable char array
    /// for immediate cryptographic use. The returned array must be cleared
    /// after use to prevent sensitive data from lingering in memory.
    /// </summary>
    ///
    /// <remarks>
    /// This method ensures:
    /// - Safe extraction of the SecureString content without creating an immutable string.
    /// - Allocation of a managed char[] buffer containing the plaintext characters.
    /// - Use of Marshal.SecureStringToGlobalAllocUnicode to copy characters to unmanaged memory,
    ///   followed by immediate zeroing and release with Marshal.ZeroFreeGlobalAllocUnicode.
    /// - The returned array is mutable, allowing the caller to clear it securely after use.
    /// - No permanent strings are ever created, minimizing exposure to GC and memory dumps.
    /// 
    /// - Responsibility for clearing and handling the char[] lies entirely with the caller.
    /// - The function is designed to fully compatible with Speedcrypt's approach 
    /// - to secure password handling.
    ///   
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static char[] ToCharArray(SecureString secure)
    {
        if (secure == null || secure.Length == 0)
            return new char[0];

        IntPtr ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.SecureStringToGlobalAllocUnicode(secure);
            char[] result = new char[secure.Length];
            Marshal.Copy(ptr, result, 0, secure.Length);
            return result;
        }
        finally
        {
            if (ptr != IntPtr.Zero)
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }
}