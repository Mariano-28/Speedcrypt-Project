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
using System.Threading;
using System.Threading.Tasks;

namespace Speedcrypt.SALT.Fortuna.Accumulator.Event
{
    public class EntropyEventScheduler : IEventScheduler
    {
        private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();

        public event EntropyAvailableHandler EntropyAvailable;

        public void ScheduleEvent(int source, IScheduledEvent @event)
        {
            var token = _cancellationTokenSource.Token;

            // The resolution of our scheduler (Task.Delay) is approximately 15ms (on Windows), which should be sufficient for our purposes
            Task.Delay(@event.ScheduledPeriod, token)
                .ContinueWith(t => RaiseEvent(source, @event), token)
                .ContinueWith(t => ScheduleEvent(source, @event), token, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Current);
        }

        // Including the 'source' value as an argument here is an explicit design decision.
        // Section 9.5.3.1 specifies that this should be passed at the entropy provider level for security reasons, but because all sources are
        // to be used from within the same Application Domain (and hence same shared memory), this is an acceptable risk.
        private void RaiseEvent(int source, IScheduledEvent @event)
        {
            EntropyAvailable?.Invoke(source, @event.EventCallback());
        }

        #region IDisposable Implementation

        private bool _isDisposed = false;
        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed) return;
            
            if (disposing)
            {
                _cancellationTokenSource.Cancel(true);
                _cancellationTokenSource.Dispose();
            }

            EntropyAvailable = null;

            _isDisposed = true;
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}