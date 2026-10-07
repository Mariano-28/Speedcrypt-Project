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

namespace Speedcrypt.Digests.Blake
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// BlakeAdapter: Provides a unified interface for computing BLAKE hashes.
    /// </summary>
    /// <remarks>
    /// This class allows deriving hash values using either BLAKE-256 or BLAKE-512 algorithms.
    /// It ensures consistent output formatting (lowercase hexadecimal string) and 
    /// integrates seamlessly with the Speedcrypt framework.
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public sealed class BlakeAdapter
    {
        // Derives hash using selected algorithm ("BLAKE-256" or "BLAKE-512")
        // Note: This class is structured to accommodate future updates for the SpeedCrypt project
        public static string Derive(byte[] input, string algorithm)
        {
            byte[] hash;

            switch (algorithm.ToUpperInvariant())
            {
                case "BLAKE-256":
                    using (var engine256 = new Blake256())
                        hash = engine256.ComputeHash(input);
                    break;

                case "BLAKE-512":
                    using (var engine512 = new Blake512())
                        hash = engine512.ComputeHash(input);
                    break;

                default:
                    throw new ArgumentException("Unsupported algorithm: " + algorithm);
            }

            return BitConverter.ToString(hash).ToLower().Replace("-", "");
        }
    }
}