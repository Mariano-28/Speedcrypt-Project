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
using System.Collections.Generic;

namespace Speedcrypt.Digests.Blake3
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Output: Represents the final output state of a hash chunk or root.
    /// Handles compression of blocks and generates XOF bytes for the root.
    /// Designed for Speedcrypt hashing operations with immutable state.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Proper compression of chunk blocks using internal State
    /// - Safe immutability with readonly ChainingValue and block arrays
    /// - Correct XOF generation for root output
    /// - Infinite output generation via GetRootBytes() must be externally controlled
    /// - Inspired by BLAKE3 reference implementation by
    ///   Jack O’Connor, Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O’Hearn
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    class Output
    {
        readonly ChainingValue _cv;
        readonly uint[] _block;
        readonly int _blockLen;
        readonly ulong _counter;
        readonly Flag _flag;
        public ChainingValue ChainingValue
        {
            get
            {
                var state = new State(cv: _cv,
                                      counter: _counter,
                                      blockLen: _blockLen,
                                      flag: _flag);
                state.Compress(_block);
                return state.cv;
            }
        }
        public Output(in ChainingValue cv,
                      ReadOnlySpan<uint> block,
                      ulong counter = 0,
                      int blockLen = Blake3.BlockLength,
                      Flag flag = Flag.None)
        {
            _cv = cv;
            _block = block.ToArray();
            _counter = counter;
            _blockLen = blockLen;
            _flag = flag;
        }
        public IEnumerable<byte> GetRootBytes()
        {
            ulong counter = 0;
            while (true)
            {
                var state = new State(cv: _cv,
                                      counter: counter,
                                      blockLen: _blockLen,
                                      flag: _flag | Flag.Root);
                state.CompressXof(_cv, _block);
                var stateBytes = state.AsBytes().ToArray();
                foreach(var b in stateBytes)
                    yield return b;

                counter++;
            }
        }
    }
}