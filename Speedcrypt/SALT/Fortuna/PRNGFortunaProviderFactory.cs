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

using System.IO;
using System.Threading;
using System.Threading.Tasks;

//Speedcrypt 
using Speedcrypt.SALT.Fortuna.Generator;
using Speedcrypt.SALT.Fortuna.Accumulator;
using Speedcrypt.SALT.Fortuna.Initialization;
using Speedcrypt.SALT.Fortuna.Accumulator.Event;
using Speedcrypt.SALT.Fortuna.Accumulator.Sources;

namespace Speedcrypt.SALT.Fortuna
{
    public static class PRNGFortunaProviderFactory
    {
        public static IPRNGFortunaProvider Create(CancellationToken token = default(CancellationToken))
        {
            var prng = GetProvider();
            prng.InitializePRNG(token);

            return prng;
        }
        public static async Task<IPRNGFortunaProvider> CreateAsync(CancellationToken token = default(CancellationToken))
        {
            var prng = GetProvider();
            await prng.InitializePRNGAsync(token).ConfigureAwait(false);

            return prng;
        }
        public static IPRNGFortunaProvider CreateWithSeedFile(Stream seedStream,
            CancellationToken token = default(CancellationToken))
        {
            var prng = GetSeedFileDecorator(seedStream);
            prng.InitializePRNG(token);

            return prng;
        }
        public static async Task<IPRNGFortunaProvider> CreateWithSeedFileAsync(Stream seedStream,
            CancellationToken token = default(CancellationToken))
        {
            var prng = GetSeedFileDecorator(seedStream);
            await prng.InitializePRNGAsync(token).ConfigureAwait(false);

            return prng;
        }
        private static PRNGFortunaProvider GetProvider()
        {
            var providers = new IEntropyProvider[]
            {
                new SystemTimeProvider(),
                new GarbageCollectionProvider(),
                new CryptoServiceProvider(),
                new EnvironmentUptimeProvider(),
                new ProcessorStatisticsProvider()
            };

            return new PRNGFortunaProvider(
                new FortunaGenerator(),
                new FortunaAccumulator(new EntropyEventScheduler(), providers));
        }
        private static IPRNGFortunaProvider GetSeedFileDecorator(Stream seedStream)
        {
            return new SeedFileDecorator(GetProvider(), seedStream);
        }
    }
}
