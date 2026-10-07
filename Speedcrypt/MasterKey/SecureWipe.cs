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

using System.Threading;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Speedcrypt.MasterKey
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SecureWipe: Utility class for securely wiping sensitive data from memory.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and is used to securely erase
    /// sensitive buffers such as filepass, hashpass, salts, or visible+secure text
    /// from SecureTextBox controls.
    ///
    /// Responsibilities:
    /// - Wipe any byte array, optionally unprotecting it if it was protected with ProtectedMemory.
    /// - Wipe multiple buffers at once for convenience and safety.
    /// - Wipe visible text and SecureString from SecureTextBox controls.
    ///
    /// 📒 Security Notes:
    /// - Uses ProtectedMemory.Unprotect safely before wiping, ignoring buffers that are already unprotected.
    /// - Pins memory with GCHandle to prevent the garbage collector from moving buffers during wiping.
    /// - Uses Thread.MemoryBarrier to ensure writes reach memory immediately.
    /// - Clears all temporary buffers immediately after use to reduce risk of sensitive data leakage.
    ///
    /// Responsibility for integration, correct usage, and security validation lies entirely with the author.
    /// 
    /// Misuse of this class (e.g., not clearing returned buffers) may result in sensitive data remaining in memory.
    /// </remarks>
    public static class SecureWipe
    {
        // Wipe any byte array, automatically unprotecting it if needed
        public static void WipeArray(byte[] data)
        {
            if (data == null) return;

            // Attempt to unprotect before wiping
            try
            {
                ProtectedMemory.Unprotect(data, MemoryProtectionScope.SameLogon);
            }
            catch
            {
                // Ignore: buffer was already unprotected
            }

            GCHandle handle = default(GCHandle);

            try
            {
                handle = GCHandle.Alloc(data, GCHandleType.Pinned);

                for (int i = 0; i < data.Length; i++)
                    data[i] = 0;

                Thread.MemoryBarrier(); // Ensure memory write ordering
            }
            finally
            {
                if (handle.IsAllocated)
                    handle.Free();
            }
        }

        // Specific wipe methods
        public static void WipeFilepass(byte[] filepass) => WipeArray(filepass);
        public static void WipeHashpass(byte[] hashpass) => WipeArray(hashpass);
        public static void WipeSalt(byte[] salt) => WipeArray(salt);

        // Wipe all three arrays at once
        public static void WipeThree(byte[] filepass, byte[] hashpass, byte[] Hashrec, byte[] salt, byte[] newsalt, byte[] decsalt)
        {
            WipeArray(filepass);
            WipeArray(hashpass);
            WipeArray(Hashrec);
            WipeArray(salt);
            WipeArray(newsalt);
            WipeArray(decsalt);
        }

        // Securely wipe a SecureTextBox (visible text + SecureString)
        internal static void WipeSecureTextBox(SecureTextBox textBox)
        {
            if (textBox == null) return;

            // Overwrite visible text
            if (!string.IsNullOrEmpty(textBox.Text))
            {
                unsafe
                {
                    fixed (char* chars = textBox.Text)
                    {
                        for (int i = 0; i < textBox.Text.Length; i++)
                            chars[i] = '\0';
                    }
                }
            }

            // Overwrite SecureString
            textBox.SecureText?.Clear();

            textBox.Text = string.Empty;
        }
    }

    // ========================= Usage =====================================
    //SecureWipe.WipeArray(Hashpass) → Delete Hashpass.

    //SecureWipe.WipeArray(Salt) → Delete only Salt.
    // SecureWipe.WipeSalt(protectedSalt.OriginalSalt); new version
    //SecureWipe.WipeArray(Filepass) → Delete Filepass.

    //SecureWipe.WipeThree(Hashpass, Salt, Filepass) → Delete all Array.
    //SecureWipe.WipeSecureTextBox(mySecureTextBox1);
    //SecureWipe.WipeSecureTextBox(mySecureTextBox2);
}
