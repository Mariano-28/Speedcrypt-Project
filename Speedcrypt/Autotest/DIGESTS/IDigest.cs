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

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// IDigest: Base interface for a message digest (hash) implementation.
    /// /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// Provides a unified contract for all cryptographic hash algorithms used in Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This interface ensures:
    /// - Standardized operations for all digest algorithms:
    /// - Single byte update
    /// - Block and Span-based update
    /// - Finalization producing a digest
    /// - Resetting to initial state
    /// - Compatibility with generic test frameworks such as DigestTest
    /// - Support for both legacy .NET arrays and modern Span<T> APIs for performance and memory safety
    /// - Deterministic behavior across multiple invocations and reset operations
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public interface IDigest
    {
        /// <summary>The algorithm name.</summary>
        string AlgorithmName { get; }

        /// <summary>Return the size, in bytes, of the digest produced by this message digest.</summary>
        /// <returns>The size, in bytes, of the digest produced by this message digest.</returns>
        int GetDigestSize();

        /// <summary>Return the size, in bytes, of the internal buffer used by this digest.</summary>
        /// <returns>The size, in bytes, of the internal buffer used by this digest.</returns>
        int GetByteLength();

        /// <summary>Update the message digest with a single byte.</summary>
        /// <param name="input">The input byte to be entered.</param>
        void Update(byte input);

        /// <summary>Update the message digest with a block of bytes.</summary>
        /// <param name="input">The byte array containing the data.</param>
        /// <param name="inOff">The offset into the byte array where the data starts.</param>
        /// <param name="inLen">The length of the data.</param>
        void BlockUpdate(byte[] input, int inOff, int inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Update the message digest with a span of bytes.</summary>
        /// <param name="input">The span containing the data.</param>
        void BlockUpdate(ReadOnlySpan<byte> input);
#endif

        /// <summary>Close the digest, producing the final digest value.</summary>
        /// <remarks>This call leaves the digest reset.</remarks>
        /// <param name="output">The byte array the digest is to be copied into.</param>
        /// <param name="outOff">The offset into the byte array the digest is to start at.</param>
        /// <returns>The number of bytes written.</returns>
        int DoFinal(byte[] output, int outOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Close the digest, producing the final digest value.</summary>
        /// <remarks>This call leaves the digest reset.</remarks>
        /// <param name="output">The span the digest is to be copied into.</param>
        /// <returns>The number of bytes written.</returns>
        int DoFinal(Span<byte> output);
#endif
        /// <summary>Reset the digest back to its initial state.</summary>
        void Reset();
    }
}