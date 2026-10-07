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

using System.Security.Cryptography;

// Speedcrypt
using Speedcrypt.HASHLibraries;

namespace Speedcrypt.MasterKey
{
    /// <summary>
    /// /// Created by Mariano Ortu
    /// 
    /// This class is part of the Speedcrypt project and is actively used in the main application.
    /// It provides a deterministic method to derive a master key of arbitrary length from input bytes.
    /// 
    /// 📒 Security Note:
    /// This class performs sensitive operations and must be used only in the context of key derivation.
    /// - Expands input bytes using iterative Blake256 hashing until the desired length is reached.
    /// - All temporary buffers are cleared immediately after use to reduce the risk of sensitive data leakage.
    /// - Pads the final key to a multiple of 8 bytes for safe usage with ProtectedMemory.
    /// - Uses cryptographically secure random bytes for padding to maximize entropy.
    /// - Truncates any excess bytes beyond desiredLength to ensure exact length output.
    /// 
    /// Responsibilities:
    /// - Master key derivation from arbitrary input bytes.
    /// - Memory-safe handling of temporary buffers.
    ///    
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>
    public static class MasterKeyDerivation
    {
        // Derive master key from input bytes with deterministic length expansion using Blake256
        public static byte[] DeriveMasterKey(byte[] inputBytes, int desiredLength)
        {
            if (inputBytes == null || inputBytes.Length == 0)
                throw new System.ArgumentException("Input bytes cannot be null or empty.");

            byte[] working = inputBytes;

            // Local function to append a Blake256 hash for key expansion
            System.Func<byte[], byte[]> appendBlake = delegate (byte[] b)
            {
                byte[] h = HASHLib.ComputeBlake256(b); // Blake256 hash
                byte[] outb = new byte[b.Length + h.Length];
                System.Buffer.BlockCopy(b, 0, outb, 0, b.Length);
                System.Buffer.BlockCopy(h, 0, outb, b.Length, h.Length);
                System.Array.Clear(h, 0, h.Length); // Clear temporary hash
                return outb;
            };

            // Expand until reaching desired length
            while (working.Length < desiredLength)
            {
                byte[] next = appendBlake(working);
                System.Array.Clear(working, 0, working.Length); // Clear previous buffer
                working = next;
            }

            // Truncate if longer than desired length
            if (working.Length > desiredLength)
            {
                byte[] trunc = new byte[desiredLength];
                System.Buffer.BlockCopy(working, 0, trunc, 0, desiredLength);
                System.Array.Clear(working, 0, working.Length);
                working = trunc;
            }

            // Pad to multiple of 8 for compatibility with ProtectedMemory
            int remainder = working.Length % 8;
            if (remainder != 0)
            {
                int pad = 8 - remainder;
                byte[] padded = new byte[working.Length + pad];
                System.Buffer.BlockCopy(working, 0, padded, 0, working.Length);

                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                byte[] padBytes = new byte[pad];
                rng.GetBytes(padBytes); // Secure random padding
                System.Buffer.BlockCopy(padBytes, 0, padded, working.Length, pad);
                System.Array.Clear(padBytes, 0, padBytes.Length);
                rng.Dispose();

                System.Array.Clear(working, 0, working.Length);
                working = padded;
            }

            // Return derived key ready for ProtectedMemory
            return working;
        }
    }
}