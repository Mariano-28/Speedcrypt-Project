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
using System.Diagnostics;
using System.Collections.Generic;

namespace Speedcrypt.SALT.Fortuna.Accumulator.Sources
{
    public class ProcessorStatisticsProvider : EntropyProviderBase, IDisposable
    {
        private readonly Process _currentProcess = Process.GetCurrentProcess();

        public override string SourceName => "Current Processor Time";
        protected override TimeSpan ScheduledPeriod => TimeSpan.FromMilliseconds(10);
        protected internal override byte[] GetEntropy()
        {
            var ticks = _currentProcess.TotalProcessorTime.Ticks;
            var vMemory = _currentProcess.VirtualMemorySize64;
            var pagedMemory = _currentProcess.PagedMemorySize64;
            var workingMemory = _currentProcess.WorkingSet64;
            IEnumerable<byte> timeBytes = BitConverter.GetBytes(ticks);
            IEnumerable<byte> vMemoryBytes = BitConverter.GetBytes(vMemory);
            IEnumerable<byte> pagedBytes = BitConverter.GetBytes(pagedMemory);
            IEnumerable<byte> workingBytes = BitConverter.GetBytes(workingMemory);

            if (!BitConverter.IsLittleEndian)
            {
                timeBytes = timeBytes.Reverse();
                vMemoryBytes = vMemoryBytes.Reverse();
                pagedBytes = pagedBytes.Reverse();
                workingBytes = workingBytes.Reverse();
            }

            return timeBytes.Take(2)
                .Concat(vMemoryBytes.Take(2))
                .Concat(pagedBytes.Take(2))
                .Concat(workingBytes.Take(2))
                .ToArray();
        }

        #region IDisposable Implementation

        private bool _isDisposed;
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        protected void Dispose(bool disposing)
        {
            if (!disposing) return;

            if (_isDisposed) return;

            _currentProcess?.Dispose();

            _isDisposed = true;
        }

        #endregion
    }
}