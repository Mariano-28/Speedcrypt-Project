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


using Org.BouncyCastle.Crypto.Digests;

namespace Speedcrypt.Autotest.DIGESTS.WRAPPER
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SkeinDigestWrapper: Wrapper class for the Skein digest algorithm.
    /// Provides a simplified interface conforming to IDigest for use in Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class ensures:
    /// - Correct initialization and usage of the Skein digest with configurable block and output sizes
    /// - Support for cloning an existing SkeinDigest instance
    /// - Full support for incremental updates, finalization, and reset
    /// - Optional Span/ReadOnlySpan support where available
    /// - Exposes the internal digest for advanced use cases
    /// - Conforms to the standard IDigest interface
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    /// 
    /// <summary>
    /// Enterprise-grade wrapper for BouncyCastle SkeinDigest implementation.
    /// Synchronizes structural cryptographic states while maintaining compliance with the IDigest contract.
    /// Provides optimized memory management using conditional compilation for high-throughput span architectures.
    /// </summary>
    public class SkeinDigestWrapper : IDigest
    {
        private readonly SkeinDigest digestInstance;

        /// <summary>
        /// Initializes a new instance of the Skein digest engine with specified configuration parameters.
        /// </summary>
        /// <param name="blockSize">The internal block size matching the cryptographic primitives (256, 512, or 1024 bits).</param>
        /// <param name="outputSize">The final computed digest layout size in bits.</param>
        public SkeinDigestWrapper(int blockSize, int outputSize)
        {
            digestInstance = new SkeinDigest(blockSize, outputSize);
        }

        /// <summary>
        /// Cloning constructor designed for deep-copying existing stateful processing contexts.
        /// </summary>
        /// <param name="existing">The source instance containing the ongoing cryptographic state vector.</param>
        public SkeinDigestWrapper(SkeinDigest existing)
        {
            digestInstance = new SkeinDigest(existing);
        }

        /// <summary>
        /// Gets the unique standardized identifier assigned to this cryptographic hash algorithm instance.
        /// </summary>
        public string AlgorithmName
        {
            get { return digestInstance.AlgorithmName; }
        }

        /// <summary>
        /// Retrieves the standardized length of the computed output byte sequence.
        /// </summary>
        /// <returns>The digest output boundary footprint in bytes.</returns>
        public int GetDigestSize()
        {
            return digestInstance.GetDigestSize();
        }

        /// <summary>
        /// Retrieves the internal working block boundary length utilized by the underlying primitive stream.
        /// </summary>
        /// <returns>The operational block processing framework capacity in bytes.</returns>
        public int GetByteLength()
        {
            return digestInstance.GetByteLength();
        }

        /// <summary>
        /// Ingests a single byte into the running cryptographic hashing computation context.
        /// </summary>
        /// <param name="input">The individual data block byte scheduled for stream update.</param>
        public void Update(byte input)
        {
            digestInstance.Update(input);
        }

        /// <summary>
        /// Ingests an array segment into the running cryptographic hashing computation context.
        /// </summary>
        /// <param name="input">The reference buffer containing the binary processing stream.</param>
        /// <param name="inOff">The explicit initial memory offset indicator within the input sequence.</param>
        /// <param name="inLen">The exact quantitative length segment to parse from the offset reference.</param>
        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            digestInstance.BlockUpdate(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Ingests a contiguous memory region into the running cryptographic hashing context using high-performance spans.
        /// </summary>
        /// <param name="input">The read-only continuous memory block sequence allocated for execution.</param>
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            digestInstance.BlockUpdate(input);
        }
#endif

        /// <summary>
        /// Closes the current transaction, executes the final byte compression steps, and copies the results into the targeted array.
        /// </summary>
        /// <param name="output">The target array buffer allocated to accept the compiled output sequence.</param>
        /// <param name="outOff">The designated starting index within the target array buffer.</param>
        /// <returns>The total number of finalized bytes committed to the target array buffer.</returns>
        public int DoFinal(byte[] output, int outOff)
        {
            return digestInstance.DoFinal(output, outOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Closes the current transaction, executes the final byte compression steps, and commits the output directly to a destination span.
        /// </summary>
        /// <param name="output">The contiguous writable span layout allocated for final state commitment.</param>
        /// <returns>The total number of finalized bytes written to the specified memory space.</returns>
        public int DoFinal(Span<byte> output)
        {
            return digestInstance.DoFinal(output);
        }
#endif

        /// <summary>
        /// Resets the internal state configuration parameters, purging active processing sequences to allow fresh transactions.
        /// </summary>
        public void Reset()
        {
            digestInstance.Reset();
        }

        /// <summary>
        /// Exposes direct access to the raw internal engine instance for specialized macro processing operations.
        /// </summary>
        public SkeinDigest InnerDigest
        {
            get { return digestInstance; }
        }
    }
}