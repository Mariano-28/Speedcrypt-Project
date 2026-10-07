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

// Speedcrypt
using Speedcrypt.XMLConfig;

namespace Speedcrypt.MasterKey
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// MasterKeyCounter: Thread-safe utility to track and persist the number of master key operations.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and is actively used in the application
    /// to maintain a consistent counter for master key operations.
    ///
    /// Responsibilities:
    /// - Load and initialize the master key counter from configuration.
    /// - Increment the counter safely in a multi-threaded environment.
    /// - Retrieve the current counter value without incrementing.
    /// - Reset the counter to zero safely.
    /// - Persist counter updates immediately to AppConfigHelper XML configuration.
    ///
    /// 📒 Security & Usage Notes:
    /// - Thread-safe operations are guaranteed via internal locking.
    /// - Counter persistence is done immediately on each change to avoid data loss.
    /// - This class does NOT handle cryptographic operations directly; it only tracks counts.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>
    public class MasterKeyCounter
    {
        private const string CounterKey = "Result.MasterKeyCounter";
        private int counter;
        private readonly object _lock = new object();

        public MasterKeyCounter()
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
                counter = 0; // Default to 0 if no valid value
                AppConfigHelper.XmlConfig.SetValue(CounterKey, "0"); // Write it once
                AppConfigHelper.Save(); // Save once after setting
            }
            else
            {
                // If valid, just parse and use the value
                counter = int.Parse(value);
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