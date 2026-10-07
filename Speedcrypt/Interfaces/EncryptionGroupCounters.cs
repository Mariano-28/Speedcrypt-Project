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

// Speedcrypt
using Speedcrypt.XMLConfig;

namespace Speedcrypt.Interfaces
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// EncryptionGroupCounters: Infrastructure support class for tracking
    /// active encryption groups per algorithm within Speedcrypt.
    /// </summary>
    /// <remarks>
    /// This class is NOT a cryptographic component.
    /// It does not perform encryption, decryption, hashing, or validation.
    ///
    /// Its sole responsibility is to maintain persistent counters
    /// associated with encryption groups, synchronized with the
    /// application XML configuration.
    ///
    /// The counters represent logical group presence, not file count
    /// and not cryptographic strength.
    ///
    /// ⚠️ Security Note:
    /// This class has no security relevance.
    /// It must NEVER be considered part of the cryptographic trust chain.
    /// Any misuse of these counters for security decisions is conceptually wrong.
    ///
    /// Designed for accounting, consistency, and configuration integrity only.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>  
    public class EncryptionGroupCounters
    {
        private readonly Dictionary<string, int> groupCounters = new Dictionary<string, int>();
        private readonly string[] algorithms = new string[]
        {
        "AES", "PGP", "IDEA", "GOST", "AES-GCM",
        "SERPENT", "TWOFISH", "CAMELLIA", "THREEFISH",
        "KUZNYECHIK", "XCHACHA20-POLY1305"
        };
        public EncryptionGroupCounters()
        {
            LoadOrInitializeCounters();
        }

        // LOAD PIPELINE: Synchronize internal associative state with the persistent configuration boundary.
        private void LoadOrInitializeCounters()
        {
            foreach (string algo in algorithms)
            {
                string key = "COUNT-" + algo;
                string value = AppConfigHelper.XmlConfig.GetValue(key);

                if (string.IsNullOrEmpty(value))
                {
                    groupCounters[key] = 0;
                    AppConfigHelper.XmlConfig.SetValue(key, "0");
                }
                else
                {
                    int parsed;
                    if (int.TryParse(value, out parsed))
                        groupCounters[key] = parsed;
                    else
                        groupCounters[key] = 0;
                }
            }

            AppConfigHelper.Save();
        }

        // ATOMIC INCREMENT SYSTEM: Real-time dynamic XML state pull to prevent concurrent runtime drift.
        public void Increment(string algorithm)
        {
            string key = "COUNT-" + algorithm;

            // FORCE CONCURRENT SYNCHRONIZATION: Read current XML value to eliminate memory object delta failures.
            string currentXmlValue = AppConfigHelper.XmlConfig.GetValue(key);
            int currentCount = 0;
            if (!string.IsNullOrEmpty(currentXmlValue) && int.TryParse(currentXmlValue, out int parsedXml))
            {
                currentCount = parsedXml;
            }

            currentCount++;
            groupCounters[key] = currentCount;

            AppConfigHelper.XmlConfig.SetValue(key, currentCount.ToString(System.Globalization.CultureInfo.InvariantCulture));
            AppConfigHelper.Save();
        }
        // ATOMIC DECREMENT SYSTEM: Enforce multi-engine string protection boundaries during collection purging.
        public void Decrement(string algorithm, int groupId)
        {
            string key = "COUNT-" + algorithm;

            // FORCE LIVE SYNCHRONIZATION: Pull active configuration state from persistent layer.
            string currentXmlValue = AppConfigHelper.XmlConfig.GetValue(key);
            if (!string.IsNullOrEmpty(currentXmlValue) && int.TryParse(currentXmlValue, out int parsedXml))
            {
                groupCounters[key] = parsedXml;
            }
            else if (!groupCounters.ContainsKey(key))
            {
                groupCounters[key] = 0;
            }

            // METADATA EVALUATION PIPELINE: Scan configuration map targeting engine-specific structural layouts.
            var parents = AppConfigHelper.XmlConfig.GetAllKeyValuePairs()
                .Where(kvp => kvp.Value.Split('|').Last()
                .Equals("Engine" + algorithm, StringComparison.OrdinalIgnoreCase))
                .ToList();

            bool groupStillExists = false;

            foreach (var parent in parents)
            {
                var children = AppConfigHelper.XmlConfig.GetChildNodes(parent.Key);

                foreach (var child in children)
                {
                    string[] parts = child.Value.Split('|');

                    if (parts.Length < 2)
                        continue;

                    int parsedGroupId;

                    // COMPATIBILITY BOUNDARY: Extract exact integer session marker using structural trailing array segment.
                    if (int.TryParse(parts.Last().Trim(), out parsedGroupId))
                    {
                        if (parsedGroupId == groupId)
                        {
                            groupStillExists = true;
                            break;
                        }
                    }
                }

                if (groupStillExists)
                    break;
            }

            // DEFERRED DYNAMIC MUTATION: Commit decremented sequence update only upon verified branch depletion.
            if (!groupStillExists && groupCounters[key] > 0)
            {
                groupCounters[key]--;

                AppConfigHelper.XmlConfig.SetValue(
                    key,
                    groupCounters[key].ToString(System.Globalization.CultureInfo.InvariantCulture));

                AppConfigHelper.Save();
            }
        }

        // STATE INQUIRY: Retrieve structural counter metric allocated to target engine algorithm.
        public int GetCount(string algorithm)
        {
            string key = "COUNT-" + algorithm;

            // SYNCHRONIZED ACQUISITION: Pull direct from active configuration store to prevent reference separation.
            string currentXmlValue = AppConfigHelper.XmlConfig.GetValue(key);
            if (!string.IsNullOrEmpty(currentXmlValue) && int.TryParse(currentXmlValue, out int parsedXml))
            {
                groupCounters[key] = parsedXml;
                return parsedXml;
            }

            if (groupCounters.ContainsKey(key))
                return groupCounters[key];
            return 0;
        }

        // STATE INITIALIZATION: Purge targeted algorithm index tracking allocations.
        public void Reset(string algorithm)
        {
            string key = "COUNT-" + algorithm;
            groupCounters[key] = 0;
            AppConfigHelper.XmlConfig.SetValue(key, "0");
            AppConfigHelper.Save();
        }

        // TOTAL MASTER DEFLATION: Instantly wipe master schema memory indexes.
        public void ResetAll()
        {
            foreach (string algo in algorithms)
            {
                string key = "COUNT-" + algo;
                groupCounters[key] = 0;
                AppConfigHelper.XmlConfig.SetValue(key, "0");
            }

            AppConfigHelper.Save();
        }
    }
}