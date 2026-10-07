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
using System.Management;
using System.Collections.Generic;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// HDInfomodel: Utility class for retrieving hard disk information via WMI.
    /// Provides a dictionary mapping logical drive letters (or pseudo-identifiers)
    /// to disk models, supporting system inventory and diagnostics.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Retrieval of all physical disks on the system using the Win32_DiskDrive WMI query.
    /// - Optional inclusion of removable drives (USB), disks without logical volumes,
    ///   and disconnected or offline disks.
    /// - Generation of pseudo-identifiers for disks lacking logical volumes or
    ///   disconnected drives to guarantee unique dictionary keys.
    /// - Returns a Dictionary<string, string> where Key = drive letter or pseudo-ID,
    ///   Value = disk model (or model with "[DISCONNECTED]" suffix for offline drives).
    /// - All exceptions are silently caught to prevent runtime crashes, especially in UI contexts.
    /// - No modification, deletion, or alteration of disk data; strictly read-only.
    /// - Deterministic and stable behavior suitable for system and storage inventory tools.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class HDInfomodel
    {
        public static Dictionary<string, string> GetAllDiskBrandsFromWMI(
        bool includeRemovables = false,
        bool includeWithoutLogical = false,
        bool includeDisconnected = true)
        {
            var result = new Dictionary<string, string>();

            try
            {
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");

                foreach (ManagementObject drive in searcher.Get())
                {
                    string model = drive["Model"]?.ToString().Trim() ?? "Unknown";
                    string interfaceType = drive["InterfaceType"]?.ToString().Trim() ?? "";
                    string mediaType = drive["MediaType"]?.ToString().Trim() ?? "";
                    string status = drive["Status"]?.ToString().Trim() ?? "";
                    bool mediaLoaded = drive["MediaLoaded"] is bool loaded && loaded;

                    if (!includeRemovables && interfaceType.Equals("USB", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var partitions = drive.GetRelated("Win32_DiskPartition");
                    bool added = false;

                    foreach (ManagementObject partition in partitions)
                    {
                        var logicalDisks = partition.GetRelated("Win32_LogicalDisk");
                        foreach (ManagementObject logicalDisk in logicalDisks)
                        {
                            string letter = logicalDisk["DeviceID"]?.ToString();
                            if (!string.IsNullOrEmpty(letter) && !result.ContainsKey(letter))
                            {
                                result.Add(letter, model);
                                added = true;
                            }
                        }
                    }

                    // If we want to include drives without a volume
                    if (includeWithoutLogical && !added)
                    {
                        string pseudoId = $"{model} [no volume]";
                        if (!result.ContainsKey(pseudoId))
                            result.Add(pseudoId, model);

                    }

                    // If we want to include "disconnected" drives
                    if (includeDisconnected && !mediaLoaded || status != "OK")
                    {
                        string pseudoId = $"{model} [DISCONNECTED]";
                        if (!result.ContainsKey(pseudoId))
                            result.Add(pseudoId, model + " [DISCONNECTED]");
                    }
                }
            }
            catch
            {
                // Silent exception
            }

            return result;
        }
    }
}