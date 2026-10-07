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

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ShredAlgorithmInfo: Represents metadata and characteristics for a secure disk
    /// wiping algorithm within Speedcrypt. Stores descriptive, performance, and
    /// hardware-specific information for display and configuration purposes.
    ///
    /// This class is purely a data container with no computational logic. It provides
    /// default values for certain properties and allows optional grouping or categorization
    /// of algorithms.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized storage of shredding algorithm properties including:
    ///   Description, Strength, StrengthText, Speed, Passes, Manual, and HdType.
    /// - Default values for Manual ("Manual/Software") and HdType ("HDD") are provided.
    /// - EnableCustomGroup flag allows optional grouping or categorization of algorithms.
    /// - No computational logic is performed; purely a data container for algorithm info.
    /// - Designed as a stable, deterministic reference object for UI, configuration, 
    ///   and internal selection of shredding algorithms.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class ShredAlgorithmInfo
    {
        public string Description { get; set; }
        public int Strength { get; set; }
        public string StrengthText { get; set; }
        public string Speed { get; set; }
        public string Passes { get; set; }
        public string Manual { get; set; } = "Manual/Software";
        public string HdType { get; set; } = "HDD"; // Default HDD
        public bool EnableCustomGroup { get; set; } = false;

        /// <summary>
        /// Returns a predefined instance of ShredAlgorithmInfo for standard algorithms.
        /// </summary>
        /// <param name="algorithm">Name of the algorithm to create.</param>
        /// <param name="isSSD">If true, sets HdType to "SSD"; otherwise "HDD".</param>
        /// <returns>Pre-configured ShredAlgorithmInfo instance.</returns>
        public static ShredAlgorithmInfo CreateDefault(string algorithm, bool isSSD = false)
        {
            string hdType = isSSD ? "SSD" : "HDD";

            switch (algorithm.ToLower())
            {
                case "fastwipe":
                    return new ShredAlgorithmInfo
                    {
                        Description = "Fast wipe with moderate security",
                        Strength = 1,
                        StrengthText = "Low",
                        Speed = "High",
                        Passes = "1",
                        HdType = hdType
                    };

                case "securewipe":
                    return new ShredAlgorithmInfo
                    {
                        Description = "Secure wipe with standard security",
                        Strength = 3,
                        StrengthText = "Medium",
                        Speed = "Medium",
                        Passes = "3",
                        HdType = hdType
                    };

                case "ultrawipe":
                    return new ShredAlgorithmInfo
                    {
                        Description = "Ultra secure wipe with maximum security",
                        Strength = 7,
                        StrengthText = "High",
                        Speed = "Low",
                        Passes = "7",
                        HdType = hdType
                    };

                default:
                    return new ShredAlgorithmInfo
                    {
                        Description = algorithm,
                        Strength = 0,
                        StrengthText = "Unknown",
                        Speed = "Unknown",
                        Passes = "0",
                        HdType = hdType
                    };
            }
        }
    }
    // ==================================== Usage =========================================
    //var fastHDD = ShredAlgorithmInfo.CreateDefault("fastwipe"); // HdType = HDD
    //var secureSSD = ShredAlgorithmInfo.CreateDefault("securewipe", true); // HdType = SSD
}