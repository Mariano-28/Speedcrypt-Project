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

using Speedcrypt.XMLConfig;

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// PGPRSAKeyCounter: Manages a persistent counter used to track RSA key operations
    /// within the Speedcrypt PGP module.
    /// </summary>
    ///
    /// <remarks>
    /// This class provides a thread-safe persistent counter used to track the number
    /// of RSA key operations performed by the PGP subsystem.
    ///
    /// Core functionality:
    /// - Loads the counter value from the Speedcrypt XML configuration on initialization
    /// - Automatically initializes the counter to 0 if the configuration entry is missing or invalid
    /// - Provides safe Increment(), GetCurrent(), and Reset() operations
    /// - Persists the updated counter value immediately after each modification
    ///
    /// Thread-safety:
    /// - All read/write operations are protected using a private lock object
    /// - Prevents race conditions in multi-threaded scenarios
    ///
    /// Persistence:
    /// - Counter value is stored in the configuration using the key:
    ///   "Result.PGPRSAKeyCounter"
    /// - Uses AppConfigHelper.XmlConfig as the configuration interface
    ///
    /// Technical notes:
    /// - Uses only .NET Base Class Library components
    /// - Designed for deterministic and safe operation inside the Speedcrypt framework
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public class PGPRSAKeyCounter
    {
        private const string CounterKey = "Result.PGPRSAKeyCounter";
        private int counter;
        private readonly object _lock = new object();
        public PGPRSAKeyCounter()
        {
            LoadOrInitializeCounter();
        }

        // Load counter from AppConfigHelper or initialize if not existing
        private void LoadOrInitializeCounter()
        {
            string value = AppConfigHelper.XmlConfig.GetValue(CounterKey);

            // If the key doesn't exist or value is invalid, initialize it
            if (string.IsNullOrEmpty(value) || !int.TryParse(value, out counter))
            {
                counter = 0;
                AppConfigHelper.XmlConfig.SetValue(CounterKey, "0");
                AppConfigHelper.Save();
            }
        }

        // Increment the counter safely and save it
        public int Increment()
        {
            lock (_lock)
            {
                counter++;
                AppConfigHelper.XmlConfig.SetValue(CounterKey, counter.ToString());
                AppConfigHelper.Save();
                return counter;
            }
        }

        // Get current counter without incrementing
        public int GetCurrent()
        {
            lock (_lock)
            {
                return counter;
            }
        }

        // Reset counter to 0 safely
        public void Reset()
        {
            lock (_lock)
            {
                counter = 0;
                AppConfigHelper.XmlConfig.SetValue(CounterKey, "0");
                AppConfigHelper.Save();
            }
        }
    }
}