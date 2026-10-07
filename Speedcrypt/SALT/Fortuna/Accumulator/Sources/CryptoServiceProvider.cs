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
using System.Security.Cryptography;

namespace Speedcrypt.SALT.Fortuna.Accumulator.Sources
{
    public class CryptoServiceProvider : EntropyProviderBase, IDisposable
    {
        private readonly RandomNumberGenerator _cryptoService = RandomNumberGenerator.Create();

        public override string SourceName => ".NET RNGCryptoServiceProvider";
        protected override TimeSpan ScheduledPeriod => TimeSpan.FromMilliseconds(100);
        protected internal override byte[] GetEntropy()
        {
            var randomData = new byte[32];
            _cryptoService.GetBytes(randomData);

            return randomData;
        }

        private bool _isDisposed;
        public void Dispose()
        {
            if (_isDisposed) return;

            _cryptoService?.Dispose();

            _isDisposed = true;
        }
    }
}