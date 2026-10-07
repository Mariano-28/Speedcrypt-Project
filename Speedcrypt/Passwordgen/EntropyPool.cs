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
using System.Security.Cryptography;

namespace Speedcrypt.Passwordgen
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// EntropyPool: Collects and manages entropy from user interactions
    /// (mouse movements, key presses) and external sources for password generation.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt Password Generator module and is intended
    /// for internal use in generating high-entropy seeds.
    /// 
    /// Responsibilities:
    /// - Collect entropy from multiple sources (mouse, keyboard, external bytes).
    /// - Track bits of entropy collected and raise events for progress and completion.
    /// - Provide a final SHA256 hash representing the collected entropy.
    /// - Securely wipe all temporary and intermediate buffers to prevent data leakage.
    /// - Allow manual reset and controlled disposal of sensitive data.
    ///
    /// Responsibility for correct usage, parameterization, integration, and
    /// cryptographic security lies entirely with the author. This class is designed
    /// to support password generation but does NOT validate or enforce password rules.
    /// </remarks>
    public sealed class EntropyPool : IDisposable
    {
        // Public configuration
        public int MaxEntropyBits = 1024;
        private const int MouseEntropyBits = 2;
        private const int KeyEntropyBits = 4;

        // Internal limits
        private const int MaxBufferSize = 64 * 1024;

        private readonly object _sync = new object();
        private List<byte> _pool;
        private int _bitsCollected;
        private bool _finalized;
        private byte[] _finalHash;
        private bool _disposed;

        // Events
        public Action<int> BitsCollectedChanged;
        public Action Completed;
        public int BitsCollected
        {
            get { lock (_sync) { return _bitsCollected; } }
        }
        public int ProgressPercent
        {
            get
            {
                var bits = BitsCollected;
                long p = (long)bits * 100 / Math.Max(1, MaxEntropyBits);
                return p > 100 ? 100 : (int)p;
            }
        }
        public bool IsComplete
        {
            get { return BitsCollected >= MaxEntropyBits; }
        }
        public EntropyPool()
        {
            _pool = new List<byte>(256);
            _bitsCollected = 0;
            _finalized = false;
            _finalHash = null;
            _disposed = false;
        }
        public void Reset()
        {
            lock (_sync)
            {
                SecureClearInternal();
                _pool = new List<byte>(256);
                _bitsCollected = 0;
                _finalized = false;
                _finalHash = null;
            }
            SafeInvokeBitsChanged(0);
        }
        public void AddMouseMove(int x, int y)
        {
            if (IsComplete || _disposed) return;

            long ticks = DateTime.UtcNow.Ticks;
            lock (_sync)
            {
                AppendInt32(x);
                AppendInt32(y);
                AppendInt64(ticks);
                IncreaseBits(MouseEntropyBits);
            }

            TrimIfNeeded();
            SafeInvokeBitsChanged(BitsCollected);
            if (IsComplete) SafeInvokeCompleted();
        }
        public void AddKeyPress(int keyCode, char ch)
        {
            if (IsComplete || _disposed) return;

            long ticks = DateTime.UtcNow.Ticks;
            lock (_sync)
            {
                AppendInt32(keyCode);
                AppendUInt16((ushort)ch);
                AppendInt64(ticks);
                IncreaseBits(KeyEntropyBits);
            }

            TrimIfNeeded();
            SafeInvokeBitsChanged(BitsCollected);
            if (IsComplete) SafeInvokeCompleted();
        }
        public void MergeExternalEntropy(byte[] data, int estimatedBits)
        {
            if (_disposed || data == null || data.Length == 0) return;
            if (estimatedBits <= 0) estimatedBits = 0;

            lock (_sync)
            {
                AppendBytes(data);
                IncreaseBits(Math.Min(estimatedBits, MaxEntropyBits - _bitsCollected));
            }

            TrimIfNeeded();
            SafeInvokeBitsChanged(BitsCollected);
            if (IsComplete) SafeInvokeCompleted();
        }
        public byte[] GetFinalEntropy()
        {
            lock (_sync)
            {
                if (_finalized) return (byte[])_finalHash.Clone();

                using (var sha = SHA256.Create())
                {
                    byte[] fed = _pool.Count == 0 ? new byte[0] : _pool.ToArray();
                    byte[] seed = sha.ComputeHash(fed);

                    for (int i = 0; i < fed.Length; i++) fed[i] = 0;

                    _finalHash = seed;
                    _finalized = true;

                    SecureClearInternal();
                }

                return (byte[])_finalHash.Clone();
            }
        }
        public void SetBitsCollected(int bits)
        {
            if (_disposed) return;

            lock (_sync)
            {
                _bitsCollected = bits;
                if (_bitsCollected > MaxEntropyBits)
                    _bitsCollected = MaxEntropyBits;
                if (_bitsCollected < 0)
                    _bitsCollected = 0;
            }

            SafeInvokeBitsChanged(_bitsCollected);
        }

        // -----------------------
        // Internal helpers
        // -----------------------
        private void AppendBytes(byte[] b)
        {
            if (b == null || b.Length == 0) return;
            _pool.AddRange(b);
        }
        private void AppendInt32(int v) { _pool.AddRange(BitConverter.GetBytes(v)); }
        private void AppendInt64(long v) { _pool.AddRange(BitConverter.GetBytes(v)); }
        private void AppendUInt16(ushort v) { _pool.AddRange(BitConverter.GetBytes(v)); }
        private void IncreaseBits(int bits)
        {
            if (bits <= 0) return;
            _bitsCollected += bits;
            if (_bitsCollected > MaxEntropyBits) _bitsCollected = MaxEntropyBits;
        }
        private void TrimIfNeeded()
        {
            lock (_sync)
            {
                if (_pool.Count <= MaxBufferSize) return;

                using (var sha = SHA256.Create())
                {
                    byte[] full = _pool.ToArray();
                    byte[] h = sha.ComputeHash(full);
                    Array.Clear(full, 0, full.Length);

                    _pool.Clear();
                    _pool.AddRange(h);
                }
            }
        }
        private void SecureClearInternal()
        {
            if (_pool != null)
            {
                for (int i = 0; i < _pool.Count; i++) _pool[i] = 0;
                _pool.Clear();
            }

            if (_finalHash != null)
            {
                Array.Clear(_finalHash, 0, _finalHash.Length);
                _finalHash = null;
            }
        }
        private void SafeInvokeBitsChanged(int bits)
        {
            try { BitsCollectedChanged?.Invoke(bits); } catch { }
        }
        private void SafeInvokeCompleted()
        {
            try { Completed?.Invoke(); } catch { }
        }

        // -----------------------
        // IDisposable
        // -----------------------
        private void Dispose(bool disposing)
        {
            if (_disposed) return;
            lock (_sync)
            {
                SecureClearInternal();
                _pool = null;
                _bitsCollected = 0;
                _finalized = false;
                _disposed = true;
            }
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        ~EntropyPool()
        {
            Dispose(false);
        }
    }
}