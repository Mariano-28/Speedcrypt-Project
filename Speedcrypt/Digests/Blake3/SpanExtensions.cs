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
    /// SpanExtensions: Provides extension methods for converting arrays and spans
    /// to byte or uint spans, including little-endian representation.
    /// Designed for Speedcrypt core operations with high-performance memory access.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Safe and efficient conversion between T[] / Span<T> / ReadOnlySpan<T> and byte/uint spans
    /// - Support for little-endian uint conversion (Big Endian TBD)
    /// - Zero-allocation methods leveraging MemoryMarshal
    /// - Assumes little-endian platform for AsLittleEndianUints; no automatic conversion for big-endian machines
    /// - Inspired by memory handling techniques in high-performance hash implementations
    ///
    /// Usage:
    /// - On little-endian systems (e.g., most PCs), AsLittleEndianUints can be used directly for cryptographic operations.
    /// - On big-endian systems, manual byte swapping is required before calling AsLittleEndianUints.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    static class SpanExtensions
    {
        public static ReadOnlySpan<byte> AsBytes<T>(this T[] span) where T : struct
            => MemoryMarshal.AsBytes<T>(span);

        public static Span<byte> AsBytes<T>(this Span<T> span) where T : struct
            => MemoryMarshal.AsBytes<T>(span);

        public static ReadOnlySpan<byte> AsBytes<T>(this ReadOnlySpan<T> span) where T : struct
            => MemoryMarshal.AsBytes<T>(span);

        public static ReadOnlySpan<uint> AsUints<T>(this T[] span) where T : struct
            => MemoryMarshal.Cast<T, uint>(span);

        public static ReadOnlySpan<uint> AsUints<T>(this ReadOnlySpan<T> span) where T : struct
            => MemoryMarshal.Cast<T, uint>(span);

        public static ReadOnlySpan<uint> AsLittleEndianUints<T>(this T[] span) where T : struct
            => MemoryMarshal.Cast<T, uint>(span);

        public static ReadOnlySpan<uint> AsLittleEndianUints<T>(this ReadOnlySpan<T> span) where T : struct
            => MemoryMarshal.Cast<T, uint>(span);
    }

    /// <summary>
    /// Example usage for Speedcrypt hashing or encryption operations
    /// </summary>
    /*
    byte[] data = File.ReadAllBytes("example.SPCR");

    // Convert byte array to ReadOnlySpan<byte>
    ReadOnlySpan<byte> byteSpan = data.AsBytes();

    // Convert to ReadOnlySpan<uint> assuming little-endian platform
    ReadOnlySpan<uint> uintSpan = byteSpan.AsLittleEndianUints();

    // Use uintSpan in a hashing algorithm (e.g., Blake3)
    Blake3 blake3 = new Blake3();
    blake3.Initialize();
    byte[] hash = blake3.ComputeHash(byteSpan.ToArray());

    // uintSpan can also be passed to encryption routines expecting uint arrays
    */
}