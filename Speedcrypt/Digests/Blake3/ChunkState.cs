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
using System.Diagnostics;

namespace Speedcrypt.Digests.Blake3
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ChunkState: Manages a single chunk in the BLAKE3 hash computation.
    /// Handles block updates, compression, and final output preparation.
    /// Designed for Speedcrypt hashing operations with central logging if needed.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Proper handling of chunked data for hashing
    /// - Correct block compression using internal State class
    /// - Accurate output generation with chunk flags (ChunkStart, ChunkEnd)
    /// - Safe operation on spans and arrays without exceeding bounds
    /// - Inspired by BLAKE3 reference implementation by
    ///   Jack O’Connor, Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O’Hearn
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    class ChunkState
    {
        ChainingValue _cv = new ChainingValue();
        byte[] _block = new byte[Blake3.BlockLength];

        int _blockCount = 0;
        int _blockLength = 0;
        Flag _defaultFlag;

        public ulong ChunkCount { get; private set; } = 0;
        public int Length => _blockCount * Blake3.BlockLength + _blockLength;
        public int Needed => Blake3.ChunkLength - Length;
        public bool IsComplete => Length == Blake3.ChunkLength;

        public Output Output
        {
            get
            {
                for (int i = _blockLength; i < Blake3.BlockLength; i++)
                    _block[i] = 0;

                var isStart = _blockCount == 0 ? Flag.ChunkStart : Flag.None;
                return new Output(cv: _cv,
                                  block: _block.AsLittleEndianUints(),
                                  counter: ChunkCount,
                                  blockLen: _blockLength,
                                  flag: _defaultFlag | isStart | Flag.ChunkEnd);
            }
        }
        public ChunkState(in ChainingValue cv, ulong chunkCount, Flag defaultFlag)
        {
            _cv = cv;
            _defaultFlag = defaultFlag;
            ChunkCount = chunkCount;
        }
        void CompressBlock(ReadOnlySpan<byte> block)
        {
            var isStart = _blockCount == 0 ? Flag.ChunkStart : Flag.None;
            var state = new State(cv: _cv,
                                  counter: ChunkCount,
                                  flag: _defaultFlag | isStart);
            state.Compress(block.AsLittleEndianUints());
            _cv = state.cv;
            _blockCount++;
            _blockLength = 0;
        }
        public void Update(ReadOnlySpan<byte> data)
        {
            Debug.Assert(data.Length <= Blake3.ChunkLength);

            if (_blockLength == Blake3.BlockLength)
                CompressBlock(_block);

            while (data.Length > Blake3.BlockLength)
            {
                CompressBlock(data.Slice(0, Blake3.BlockLength));
                data = data.Slice(Blake3.BlockLength);
            }

            var available = Math.Min(data.Length, Blake3.BlockLength - _blockLength);
            data.Slice(0, available).CopyTo(_block.AsSpan().Slice(_blockLength));
            _blockLength += available;
        }
    }
}