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
using System.IO;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;

namespace Speedcrypt.Autotest
{
    /// <summary>
    /// Created by Mariano Ortu
	/// 
    /// CipherStream: Cryptographic stream wrapper for buffered block and stream ciphers.
	/// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This class provides transparent encryption and decryption over a .NET Stream
    /// using IBufferedCipher instances for read and/or write operations.
    ///
    /// The implementation is conceptually derived from the Bouncy Castle
    /// CipherStream / CipherInputStream / CipherOutputStream design,
    /// adapted to the .NET Stream abstraction and execution model.
    ///
    /// Core responsibilities:
    /// - On-the-fly decryption during Read operations
    /// - On-the-fly encryption during Write operations
    /// - Proper buffering and block handling for both block and stream ciphers
    /// - Correct finalization via DoFinal() at end-of-stream or Close()
    ///
    /// The class intentionally:
    /// - Does not support seeking
    /// - Does not expose stream length or position
    /// - Propagates cryptographic and I/O exceptions without interception
    ///
    /// This behavior is required to preserve correctness, determinism,
    /// and compatibility with the underlying cryptographic primitives.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class CipherStream
		: Stream
    {
        internal Stream stream;
        internal IBufferedCipher inCipher, outCipher;
        private byte[] mInBuf;
		private int mInPos;
		private bool inStreamEnded;

		public CipherStream(
            Stream			stream,
            IBufferedCipher	readCipher,
            IBufferedCipher	writeCipher)
        {
            this.stream = stream;

			if (readCipher != null)
			{
				this.inCipher = readCipher;
				mInBuf = null;
			}

			if (writeCipher != null)
			{
				this.outCipher = writeCipher;
			}
		}
		public IBufferedCipher ReadCipher
		{
			get { return inCipher; }
		}
		public IBufferedCipher WriteCipher
		{
			get { return outCipher; }
		}
		public override int ReadByte()
        {
            if (inCipher == null)
                return stream.ReadByte();

			if (mInBuf == null || mInPos >= mInBuf.Length)
			{
				if (!FillInBuf())
					return -1;
            }

			return mInBuf[mInPos++];
        }
		public override int Read(
			byte[]	buffer,
			int		offset,
			int		count)
        {
            if (inCipher == null)
                return stream.Read(buffer, offset, count);

			int num = 0;
			while (num < count)
			{
				if (mInBuf == null || mInPos >= mInBuf.Length)
				{
					if (!FillInBuf())
						break;
				}

				int numToCopy = System.Math.Min(count - num, mInBuf.Length - mInPos);
				Array.Copy(mInBuf, mInPos, buffer, offset + num, numToCopy);
				mInPos += numToCopy;
				num += numToCopy;
			}

			return num;
		}
		private bool FillInBuf()
        {
			if (inStreamEnded)
				return false;

			mInPos = 0;

			do
			{
				mInBuf = ReadAndProcessBlock();
			}
			while (!inStreamEnded && mInBuf == null);

			return mInBuf != null;
		}
		private byte[] ReadAndProcessBlock()
		{
			int blockSize = inCipher.GetBlockSize();
			int readSize = (blockSize == 0) ? 256 : blockSize;

			byte[] block = new byte[readSize];
			int numRead = 0;
			do
			{
				int count = stream.Read(block, numRead, block.Length - numRead);
				if (count < 1)
				{
					inStreamEnded = true;
					break;
				}
				numRead += count;
			}
			while (numRead < block.Length);

			Debug.Assert(inStreamEnded || numRead == block.Length);

			byte[] bytes = inStreamEnded
				?	inCipher.DoFinal(block, 0, numRead)
				:	inCipher.ProcessBytes(block);

			if (bytes != null && bytes.Length == 0)
			{
				bytes = null;
			}

			return bytes;
		}
		public override void Write(
			byte[]	buffer,
			int		offset,
			int		count)
        {
			Debug.Assert(buffer != null);
			Debug.Assert(0 <= offset && offset <= buffer.Length);
			Debug.Assert(count >= 0);

			int end = offset + count;

			Debug.Assert(0 <= end && end <= buffer.Length);

			if (outCipher == null)
            {
                stream.Write(buffer, offset, count);
                return;
            }

			byte[] data = outCipher.ProcessBytes(buffer, offset, count);
			if (data != null)
			{
				stream.Write(data, 0, data.Length);
			}
		}
		public override void WriteByte(
			byte b)
        {
            if (outCipher == null)
            {
                stream.WriteByte(b);
                return;
            }

			byte[] data = outCipher.ProcessByte(b);
			if (data != null)
			{
				stream.Write(data, 0, data.Length);
			}
		}
		public override bool CanRead
        {
            get { return stream.CanRead && (inCipher != null); }
        }
		public override bool CanWrite
        {
            get { return stream.CanWrite && (outCipher != null); }
        }
		public override bool CanSeek
        {
            get { return false; }
        }
		public sealed override long Length
		{
			get { throw new NotSupportedException(); }
		}
		public sealed override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

#if PORTABLE
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
			    if (outCipher != null)
			    {
				    byte[] data = outCipher.DoFinal();
				    stream.Write(data, 0, data.Length);
				    stream.Flush();
			    }
                Platform.Dispose(stream);
            }
            base.Dispose(disposing);
        }
#else
        public override void Close()
        {
			if (outCipher != null)
			{
				byte[] data = outCipher.DoFinal();
				stream.Write(data, 0, data.Length);
				stream.Flush();
			}
            Platform.Dispose(stream);
            base.Close();
        }
#endif
        public override void Flush()
        {
			// Note: outCipher.DoFinal is only called during Close()
			stream.Flush();
        }
		public sealed override long Seek(
			long		offset,
			SeekOrigin	origin)
		{
			throw new NotSupportedException();
		}
		public sealed override void SetLength(
			long length)
		{
			throw new NotSupportedException();
		}
    }
}