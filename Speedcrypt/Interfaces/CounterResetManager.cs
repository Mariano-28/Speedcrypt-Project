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

using System.Collections.Generic;

// Speedcrypt
using Speedcrypt.XMLConfig;

namespace Speedcrypt.Interfaces
{
    /// Summary
    /// Created by Mariano Ortu
    /// 
    /// CounterResetManager: Infrastructure support class responsible for
    /// resetting operational engine counters within Speedcrypt.
    ///     
    /// This class is NOT a cryptographic component.
    /// It does not perform encryption, decryption, hashing, or validation.
    ///
    /// Its sole responsibility is to safely reset specific configuration
    /// counter metrics back to zero for the selected engines.
    ///
    /// The reset logic is purely administrative and metrics-based.
    /// No cryptographic material is generated, processed, or evaluated.
    ///
    /// Special constraint:
    /// Resetting metrics affects only operational telemetry. It does not alter
    /// the actual operational states or keys of the target engines.
    ///
    /// Designed for configuration monitoring, lifecycle control,
    /// and internal consistency only.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>  
    public class CounterResetManager
    {
        public void ResetCounters(List<string> selectedEngines)
        {
            if (selectedEngines == null || selectedEngines.Count == 0)
                return;

            PrivateXmlConfig config = AppConfigHelper.XmlConfig;

            foreach (string engine in selectedEngines)
            {
                string counterKeyName = "COUNT-" + engine;

                if (config.Exists(counterKeyName))
                {
                    config.SetValue(counterKeyName, "0");
                }
            }

            AppConfigHelper.Save();
        }
    }
}
