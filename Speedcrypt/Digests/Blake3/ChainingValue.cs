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

namespace Speedcrypt.Digests.Blake3
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ChainingValue: Represents a fixed-size chaining value used in hashing.
    /// Provides safe access as uints or bytes and initialization from a key.
    /// Designed for Speedcrypt core hash operations.
    /// </summary>
    ///
    /// <remarks>
    /// This struct ensures:
    /// - Proper handling of fixed-size chaining values in unsafe contexts
    /// - Safe conversion to spans of uints and bytes
    /// - Inspired by BLAKE2 hash function implementation by
    ///   Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O’Hearn, Christian Winnerlein
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    unsafe struct ChainingValue
    {
        public fixed uint h[8];

        public void Initialize(ReadOnlySpan<uint> k)
        {
            for (int i = 0; i < 8; i++)
                h[i] = k[i];
        }
        public ReadOnlySpan<uint> AsUints()
        {
            fixed (uint* hashes = h)
                return new ReadOnlySpan<uint>(hashes, 8);
        }
        public ReadOnlySpan<byte> AsBytes()
            => AsUints().AsBytes();
    }
}