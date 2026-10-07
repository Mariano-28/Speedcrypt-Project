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
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace Speedcrypt.Digests.Blake3
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Blake3: Cryptographic hash algorithm implementation.
    /// </summary>
    /// 
    /// <remarks>
    /// This class provides a full implementation of the BLAKE3 hash algorithm
    /// compatible with System.Security.Cryptography.HashAlgorithm and C# 7.0.
    ///
    /// Features:
    /// - Incremental hashing support.
    /// - Tree-based chaining value reduction.
    /// - Extended output generation.
    ///
    /// Technical notes:
    /// - Does NOT override HashAlgorithm.Initialize(), which is non-virtual in C# 7.0.
    /// - Uses a dedicated internal state initialization method.
    /// - Access modifiers are strictly compliant with C# 7.0 rules.
    ///
    /// Acknowledgements:
    /// - Original BLAKE3 algorithm by Jack O'Connor, Samuel Neves, Jean-Philippe Aumasson, Zooko Wilcox-O'Hearn.
    /// - Reference to Blake3.NET and Blake3Core for API design: [github.com](https://github.com/xoofx/Blake3.NET)
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>    
    public class Blake3 : HashAlgorithm
    {
        internal const int HashSizeInBits = HashSizeInBytes * 8;
        internal const int HashSizeInBytes = 8 * sizeof(uint);
        internal const int ChunkLength = 1024;
        internal const int BlockLength = 16 * sizeof(uint);

        internal const uint IV0 = 0x6A09E667;
        internal const uint IV1 = 0xBB67AE85;
        internal const uint IV2 = 0x3C6EF372;
        internal const uint IV3 = 0xA54FF53A;

        internal static readonly uint[] IV =
            { IV0, IV1, IV2, IV3, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

        protected private Flag DefaultFlag;

        ChainingValue _cv;
        ChunkState _chunkState;
        Stack<ChainingValue> _chainingValueStack;
        Output _output;
        protected private Blake3(Flag defaultFlag, ReadOnlySpan<uint> key, int? outputSizeInBits)
        {
            if (outputSizeInBits == null)
                HashSizeValue = HashSizeInBits;
            else if (outputSizeInBits.Value < 1)
                throw new ArgumentException("Output size must be positive integer", nameof(outputSizeInBits));
            else
                HashSizeValue = outputSizeInBits.Value;

            DefaultFlag = defaultFlag;

            if (key.Length != 8)
                throw new ArgumentException("Must use 256-bit key", nameof(key));
            _cv.Initialize(key.ToArray());
        }
        protected private Blake3(Flag defaultFlag, ReadOnlySpan<byte> key, int? outputSizeInBits)
            : this(defaultFlag, key.Length == 32 ? key.AsUints() : new ReadOnlySpan<uint>(), outputSizeInBits)
        {
        }
        protected private static Blake3 Create(Flag defaultFlag, ReadOnlySpan<uint> key, int? outputSizeInBits)
            => new Blake3(defaultFlag, key, outputSizeInBits);

        public Blake3(int hashSizeInBits = HashSizeInBits)
            : this(Flag.None, IV, hashSizeInBits)
        {
            if (hashSizeInBits % 8 != 0 || hashSizeInBits < 8)
                throw new ArgumentException("The hash size must be a multiple of 8 and at least 8 bits");
        }
        public override void Initialize()
        {
            _chunkState = new ChunkState(_cv, 0, DefaultFlag);
            _chainingValueStack = new Stack<ChainingValue>();
        }
        Output GetParentOutput(in ChainingValue l, in ChainingValue r)
        {
            Span<ChainingValue> cvs = stackalloc ChainingValue[2] { l, r };
            Span<uint> block = MemoryMarshal.Cast<ChainingValue, uint>(cvs);
            return new Output(cv: _cv, block: block, flag: DefaultFlag | Flag.Parent);
        }
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _output = null;
            if (_chunkState == null)
                Initialize();

            var data = new ReadOnlySpan<byte>(array, ibStart, cbSize);
            while (!data.IsEmpty)
            {
                if (_chunkState.IsComplete)
                {
                    AddChunkChainingValue(_chunkState.Output.ChainingValue);
                    _chunkState = new ChunkState(_cv, _chunkState.ChunkCount + 1, DefaultFlag);
                }

                var available = Math.Min(_chunkState.Needed, data.Length);
                _chunkState.Update(data.Slice(0, available));
                data = data.Slice(available);
            }

            void AddChunkChainingValue(ChainingValue cv)
            {
                var chunkCount = _chunkState.ChunkCount + 1;
                while ((chunkCount & 1) == 0)
                {
                    cv = GetParentOutput(_chainingValueStack.Pop(), cv).ChainingValue;
                    chunkCount >>= 1;
                }
                _chainingValueStack.Push(cv);
            }
        }
        protected override byte[] HashFinal()
        {
            _output = _chunkState.Output;
            while (_chainingValueStack.Count > 0)
                _output = GetParentOutput(_chainingValueStack.Pop(), _output.ChainingValue);

            return GetExtendedOutput().Take(HashSizeValue / 8).ToArray();
        }
        public IEnumerable<byte> GetExtendedOutput() => _output.GetRootBytes();
    }
}