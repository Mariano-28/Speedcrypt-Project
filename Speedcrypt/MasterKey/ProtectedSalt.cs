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
using System.Security.Cryptography;

namespace Speedcrypt.MasterKey
{
    /// <summary>
    /// /// Created by Mariano Ortu
    /// 
    /// This class is part of the Speedcrypt project but may be used as a utility for handling salts securely.
    /// It encapsulates a salt byte array with memory protection and ensures safe unprotection when needed.
    /// 
    /// Responsibilities:
    /// - Store a salt in a ProtectedMemory-protected buffer.
    /// - Pad the salt to a multiple of 8 bytes for memory protection requirements.
    /// - Provide a safe method to retrieve the unprotected salt trimmed to its original length.
    /// - Wipe sensitive data on disposal.
    /// 
    /// 📒 Security Note:
    /// - Protects the salt in memory using ProtectedMemory with SameLogon scope.
    /// - All temporary buffers are cleared immediately after use.
    /// - Designed to prevent leakage of sensitive bytes from memory.
    /// 
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>
    public class ProtectedSalt : IDisposable
    {
        private byte[] _salt;      // Protected buffer (with padding)
        private int _originalLength; // Original salt length
        private bool _disposed = false;
        public ProtectedSalt(byte[] salt)
        {
            if (salt == null || salt.Length == 0)
                throw new ArgumentException("Salt cannot be null or empty.");

            _originalLength = salt.Length;
            _salt = (byte[])salt.Clone();

            // Pad to multiple of 8
            int remainder = _salt.Length % 8;
            if (remainder != 0)
            {
                byte[] padded = new byte[_salt.Length + (8 - remainder)];
                Array.Copy(_salt, padded, _salt.Length);
                _salt = padded;
            }

            ProtectedMemory.Protect(_salt, MemoryProtectionScope.SameLogon);
        }

        // Returns the salt in clear, original length
        public byte[] GetUnprotected()
        {
            byte[] temp = (byte[])_salt.Clone();
            ProtectedMemory.Unprotect(temp, MemoryProtectionScope.SameLogon);

            // Trim padding
            if (temp.Length != _originalLength)
            {
                byte[] trimmed = new byte[_originalLength];
                Array.Copy(temp, trimmed, _originalLength);
                Array.Clear(temp, 0, temp.Length); // Wipe temp
                temp = trimmed;
            }

            return temp;
        }
        public void Dispose()
        {
            if (!_disposed)
            {
                if (_salt != null)
                    Array.Clear(_salt, 0, _salt.Length);
                _disposed = true;
            }
        }
    }
}