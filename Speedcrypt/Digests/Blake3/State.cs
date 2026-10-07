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
using System.Runtime.InteropServices;

namespace Speedcrypt.Digests.Blake3
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// State: Represents the internal state of the hash function.
    /// Supports direct memory layout for high-performance compression
    /// and XOF operations. Provides access as uint or byte spans.
    /// Designed for Speedcrypt hashing operations with unsafe memory access.
    /// </summary>
    ///
    /// <remarks>
    /// This struct ensures:
    /// - Explicit memory layout for state and chaining value overlap
    /// - Correct initialization with IV, counter, block length, and flags
    /// - Compression and XOF operations using Compressor
    /// - Safe span access methods (read-only and writable)
    /// - Inspired by BLAKE3 reference implementation by
    ///   Jack O’Connor, Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O’Hearn
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    unsafe ref struct State
    {
        [FieldOffset(0)] public fixed uint s[16];
        [FieldOffset(0)] public ChainingValue cv;

        public State(in ChainingValue cv,
                     ulong counter = 0,
                     int blockLen = Blake3.BlockLength,
                     Flag flag = Flag.None)
        {
            this.cv = cv;

            fixed (uint* s8 = &s[8])
            {
                uint* dst = s8;
                *dst++ = Blake3.IV0;
                *dst++ = Blake3.IV1;
                *dst++ = Blake3.IV2;
                *dst++ = Blake3.IV3;
                *dst++ = (uint)counter;
                *dst++ = (uint)(counter >> 32);
                *dst++ = (uint)blockLen;
                *dst++ = (uint)flag;
            }
        }
        public void Compress(ReadOnlySpan<uint> block)
        {
            fixed(uint* state = s)
                Compressor.Compress(block, state);
        }
        public void CompressXof(in ChainingValue cv, ReadOnlySpan<uint> block)
        {
            fixed (uint* state = s)
            {
                Compressor.Compress(block, state);

                fixed (uint* h = &cv.h[0])
                {
                    s[ 8] ^= h[0];
                    s[ 9] ^= h[1];
                    s[10] ^= h[2];
                    s[11] ^= h[3];
                    s[12] ^= h[4];
                    s[13] ^= h[5];
                    s[14] ^= h[6];
                    s[15] ^= h[7];
                }
            }
        }
        public ReadOnlySpan<uint> AsUints()
        {
            fixed (uint * states = s)
                return new ReadOnlySpan<uint>(states, 16);
        }
        public ReadOnlySpan<byte> AsBytes()
            => AsUints().AsBytes();

        public Span<uint> AsWritableUints()
        {
            fixed (uint* states = s)
                return new Span<uint>(states, 16);
        }
    }
}