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
    /// Flag: Defines operational flags used during hashing and tree processing.
    /// Supports chunk boundaries, tree structure, and special hashing modes.
    /// Designed for Speedcrypt hashing pipeline.
    /// </summary>
    ///
    /// <remarks>
    /// This enum ensures:
    /// - Clear and safe combination of hashing state flags
    /// - Correct representation of chunk, parent, and root states
    /// - Support for keyed hashing and key derivation modes
    /// - Inspired by the flag model of the BLAKE3 hash function
    ///   by Jack O’Connor, Jean-Philippe Aumasson, Samuel Neves,
    ///   Zooko Wilcox-O’Hearn
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [Flags]
    enum Flag : uint
    {
        None                = 0x00,
        ChunkStart          = 0x01,
        ChunkEnd            = 0x02,
        Parent              = 0x04,
        Root                = 0x08,
        KeyedHash           = 0x10,
        DeriveKeyContext    = 0x20,
        DeriveKeyMaterial   = 0x40,
    }
}