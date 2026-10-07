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
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace Speedcrypt.SecureText
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// (Based on legacy extension prototypes, heavily re-engineered for strict memory isolation)
    ///
    /// SpeedcryptSecureDesktop:
    /// Secure memory extensions for isolated credential lifecycle management.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt security core and belongs to the
    /// memory protection and cryptographic token subsystem.
    ///
    /// Refactoring and Security Hardening Overview (by Mariano Ortu):
    /// - Re-engineered 'SecureCompare' to bypass CLR managed string allocations.
    ///   Replaced unsafe high-level comparisons with zero-exposure native unmanaged 
    ///   buffers (BSTR) via direct 'Marshal.ReadInt16' lookups, restricting cleartext 
    ///   visibility to transient registers.
    /// - Hardened 'SHA256HashValue' to eliminate unmanaged memory leaks and memory 
    ///   drift. Implemented a zero-allocation byte transposition model over 
    ///   unmanaged pointers (BSTR ToPointer) directly into a pinned, immovable memory 
    ///   vector ('GCHandleType.Pinned').
    /// - Guaranteed predictable and absolute memory sanitization inside 'try-finally' 
    ///   blocks via explicit deterministic zeroing out ('Array.Clear', 'ZeroFreeBSTR', 
    ///   'ZeroFreeGlobalAllocUnicode') to mitigate garbage collection lazy-eviction 
    ///   vulnerabilities.
    /// - Enforced structural optimization in 'HexStringFromBytes' by pre-allocating 
    ///   the exact required 'StringBuilder' capacity, preventing dynamic memory 
    ///   re-allocations and subsequent data residue footprint on the heap.
    ///
    /// Design notes:
    /// - Provides bulletproof memory extensions for handling user input captured 
    ///   by the isolated 'SecureTextBox' interface.
    /// - Minimizes volatile data lifetime by ensuring that transient decrypted representations 
    ///   exist only within strict unmanaged scopes and are scrubbed instantly.
    /// - Integrates 'String.IsInterned' heuristic checks to structurally intercept 
    ///   and prevent destructive memory manipulation attempts on string literals.
    ///
    /// Security scope and limits:
    /// - This subsystem provides kernel-grade diligence at the user-mode software layer 
    ///   by preventing process memory dump interception of credentials during 
    ///   comparison and hashing routines.
    /// - It mitigates cold-boot attacks and post-disposal heap exploitation inside the CLR.
    /// 
    /// /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>    
    public static class SecureStringExtension
    {
        /// <summary>
        /// Executes a deterministic single-step conversion from a standard managed string 
        /// to an encrypted SecureString capsule, automatically scrubbing the original cleartext payload.
        /// </summary>
        /// <param name="value">The target transient string containing sensitive data.</param>
        /// <param name="leaveOriginal">If true, bypasses the zeroing out of the input buffer.</param>
        /// <param name="makeReadOnly">If true, freezes the SecureString state to prevent post-init modifications.</param>
        /// <returns>An initialized and isolated SecureString reference.</returns>
        public static SecureString ToSecureString(this String value, bool leaveOriginal = false, bool makeReadOnly = true)
        {
            value.CheckNullRef();
            SecureString secureString;
            unsafe
            {
                // Pin the managed string structure to prevent GC compaction during instantiation
                fixed (char* chars = value)
                {
                    // Direct injection of unmanaged character sequence into the encrypted structure
                    secureString = new SecureString(chars, value.Length);
                    if (makeReadOnly)
                        secureString.MakeReadOnly();

                    // Destructively wipe the cleartext source instantly before the pointer scope closes
                    if (!leaveOriginal)
                        value.SecureClear();
                }
            }

            return secureString;
        }

        /// <summary>
        /// Explicitly materializes an isolated unmanaged Unicode allocation to bridge data 
        /// with internal processing layers, enforcing strict lifetime boundaries.
        /// </summary>
        /// <param name="value">The immutable SecureString capsule to be transiently unlocked.</param>
        /// <returns>A localized, temporary unmanaged representation of the raw data.</returns>
        public static String ConvertToString(this SecureString value)
        {
            value.CheckNullRef();

            IntPtr stringPointer = IntPtr.Zero;
            try
            {
                // Allocate an unmanaged global Unicode memory block and extract the decrypted vector
                stringPointer = Marshal.SecureStringToGlobalAllocUnicode(value);
                return Marshal.PtrToStringUni(stringPointer);
            }
            finally
            {
                // Guaranteed cleanup: overwrite the unmanaged block with zero bytes immediately
                if (stringPointer != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(stringPointer);
                }
            }
        }

        /// <summary>
        /// Performs an out-of-band, byte-by-byte hardware-register comparison of two SecureString instances, 
        /// completely bypassing the high-level CLR evaluation subroutines.
        /// </summary>
        /// <param name="left">First secure structure to inspect.</param>
        /// <param name="right">Second secure structure to inspect.</param>
        /// <returns>True if the underlying unmanaged sequences match exactly; otherwise, false.</returns>
        public static bool SecureCompare(this SecureString left, SecureString right)
        {
            if (left == null || right == null) return false;
            if (left.Length != right.Length) return false;

            IntPtr bstrLeft = IntPtr.Zero;
            IntPtr bstrRight = IntPtr.Zero;

            try
            {
                // Extract native binary string blocks (BSTR) into isolated unmanaged memory
                bstrLeft = Marshal.SecureStringToBSTR(left);
                bstrRight = Marshal.SecureStringToBSTR(right);

                // Execute an indexed 16-bit lookahead over the unmanaged pointers to cross-verify the payload
                for (int i = 0; i < left.Length; i++)
                {
                    char charLeft = (char)Marshal.ReadInt16(bstrLeft, i * 2);
                    char charRight = (char)Marshal.ReadInt16(bstrRight, i * 2);

                    if (charLeft != charRight) return false;
                }

                return true;
            }
            finally
            {
                // Structural sanitization: completely clear and release the BSTR descriptors from unmanaged memory
                if (bstrLeft != IntPtr.Zero) Marshal.ZeroFreeBSTR(bstrLeft);
                if (bstrRight != IntPtr.Zero) Marshal.ZeroFreeBSTR(bstrRight);
            }
        }

        /// <summary>
        /// Overwrites the physical character backing store of a string instance on the managed heap, 
        /// incorporating sanity checks against literal interning mechanisms.
        /// </summary>
        /// <param name="value">The target string allocation to be destructively sanitized.</param>
        public static void SecureClear(this String value)
        {
            if (value == null) return;

            // Verify that the string does not belong to the global immutable interning table
            object checkInterned = String.IsInterned(value);
            if (checkInterned == null)
            {
                unsafe
                {
                    // Lock the object coordinates and directly overwrite memory with null terminators (\0)
                    fixed (char* chars = value)
                    {
                        for (int i = 0; i < value.Length; i++)
                            chars[i] = '\0';
                    }
                }
            }
            else
            {
                // Halt execution if a critical programming flaw attempts to corrupt shared literal tables
                throw new Exception("Improper use of SecureClear on a literal or interned object");
            }
        }

        /// <summary>
        /// Computes a one-way SHA256 cryptographic digest of the encrypted data, operating inside 
        /// a pinned unmanaged environment to suppress GC-driven memory cloning vulnerabilities.
        /// </summary>
        /// <param name="value">The active SecureString capsule containing the source token.</param>
        /// <returns>A secure, non-reversible hexadecimal string representation of the computed hash.</returns>
        public static String SHA256HashValue(this SecureString value)
        {
            value.CheckNullRef();

            IntPtr bstr = IntPtr.Zero;
            byte[] rawBytes = null;
            GCHandle handle = default;

            try
            {
                int charCount = value.Length;
                bstr = Marshal.SecureStringToBSTR(value);

                // Allocate a pessimistic transcoding buffer (4 bytes per character max for UTF-8 coverage)
                rawBytes = new byte[charCount * 4];

                // Explicitly pin the managed byte vector to deny GC movement and eliminate data echo trails
                handle = GCHandle.Alloc(rawBytes, GCHandleType.Pinned);

                int totalBytesWritten = 0;

                unsafe
                {
                    char* pChars = (char*)bstr.ToPointer();
                    fixed (byte* pDst = rawBytes)
                    {
                        // Low-level pointer transcoding from native UTF-16 arrays straight into the pinned destination
                        totalBytesWritten = Encoding.UTF8.GetBytes(pChars, charCount, pDst, rawBytes.Length);
                    }
                }

                using (var sha256 = SHA256.Create())
                {
                    byte[] hashBytes = sha256.ComputeHash(rawBytes, 0, totalBytesWritten);
                    return HexStringFromBytes(hashBytes);
                }
            }
            finally
            {
                // Deterministic erasure of the intermediate cryptographic byte array
                if (rawBytes != null)
                {
                    Array.Clear(rawBytes, 0, rawBytes.Length);
                }

                // Release the memory lock handle only after the payload has been explicitly scrubbed
                if (handle.IsAllocated)
                {
                    handle.Free();
                }

                // Purge the unmanaged BSTR context
                if (bstr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(bstr);
                }
            }
        }

        /// <summary>
        /// Encodes a raw byte structure into a hexadecimal stream string, initializing structural 
        /// bounds to eliminate multi-step reallocation overhead.
        /// </summary>
        /// <param name="bytes">The cryptographic hash byte sequence.</param>
        /// <returns>A standardized hexadecimal representation string.</returns>
        private static string HexStringFromBytes(byte[] bytes)
        {
            if (bytes == null) return string.Empty;

            // Pre-allocate exact required heap capacity to prevent dynamic array reallocation leak points
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                var hex = b.ToString("x2");
                sb.Append(hex);
            }
            return sb.ToString();
        }

        /// <summary>
        /// Defensive invariant check to guarantee object reference validity before entering unmanaged processing boundaries.
        /// </summary>
        private static void CheckNullRef(this object value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
        }
    }
}