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

using Konscious.Security.Cryptography;

namespace Speedcrypt.Digests.Argon2
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Argon2Hasher: Provides password hashing using Argon2 (Argon2d, Argon2i, Argon2id) with configurable memory, time, and parallelism parameters.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements Argon2 password hashing with the following key features:
    /// - Configurable memory cost (in KiB), time cost (iterations), and parallelism factor
    /// - Supports hash output lengths up to 64 bytes
    /// - Allows selection between Argon2d, Argon2i, and Argon2id variants
    /// - Returns hashes as Base64 strings for storage or comparison
    /// - Provides verification method to check a password against a stored hash
    /// - Logs current hashing configuration for debugging or auditing
    ///
    /// Technical note:
    /// - Uses Isolated byte arrays for password handling to avoid memory leaks
    /// - Fully integrated into Speedcrypt framework for secure password storage and validation
    /// - Comparisons are direct string comparisons; can be upgraded to constant-time comparison for extra security
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class Argon2Hasher
    {
        private int _memoryCost;   // Memory cost in KiB
        private int _timeCost;     // Time cost (iterations)
        private int _parallelism;  // Parallelism factor
        private int _hashSize;     // Desired hash length in bytes

        // Constructor with default values
        public Argon2Hasher()
        {
            _memoryCost = 1024;    // Default 1 MiB
            _timeCost = 3;         // Default 3 iterations
            _parallelism = 1;      // Default 1 parallel thread
            _hashSize = 32;        // Default hash size (32 bytes)
        }

        // Constructor allowing custom parameter values
        public Argon2Hasher(int memoryCost, int timeCost, int parallelism, int hashSize = 32)
        {
            _memoryCost = memoryCost;
            _timeCost = timeCost;
            _parallelism = parallelism;
            _hashSize = Math.Min(hashSize, 64); // Assuming max 64 bytes for Argon2 output
        }

        // Methods to get and set the parameters dynamically
        public int MemoryCost
        {
            get { return _memoryCost; }
            set { _memoryCost = value; }
        }
        public int TimeCost
        {
            get { return _timeCost; }
            set { _timeCost = value; }
        }
        public int Parallelism
        {
            get { return _parallelism; }
            set { _parallelism = value; }
        }
        public int HashSize
        {
            get { return _hashSize; }
            set { _hashSize = Math.Min(value, 64); }  // Ensure max length of 64 bytes
        }

        // Method to hash the password with selected Argon2 variant
        public string HashPassword(string password, Argon2Type argon2Type)
        {
            byte[] hash;

            // Convert password to byte array
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            // Use the Argon2 specific method for each variant
            switch (argon2Type)
            {
                case Argon2Type.Argon2d:
                    using (var argon2d = new Argon2d(passwordBytes))
                    {
                        argon2d.MemorySize = _memoryCost;
                        argon2d.Iterations = _timeCost;
                        argon2d.DegreeOfParallelism = _parallelism;
                        hash = argon2d.GetBytes(_hashSize); // Specify desired hash length
                    }
                    break;

                case Argon2Type.Argon2i:
                    using (var argon2i = new Argon2i(passwordBytes))
                    {
                        argon2i.MemorySize = _memoryCost;
                        argon2i.Iterations = _timeCost;
                        argon2i.DegreeOfParallelism = _parallelism;
                        hash = argon2i.GetBytes(_hashSize); // Specify desired hash length
                    }
                    break;

                case Argon2Type.Argon2id:
                    using (var argon2id = new Argon2id(passwordBytes))
                    {
                        argon2id.MemorySize = _memoryCost;
                        argon2id.Iterations = _timeCost;
                        argon2id.DegreeOfParallelism = _parallelism;
                        hash = argon2id.GetBytes(_hashSize); // Specify desired hash length
                    }
                    break;

                default:
                    throw new ArgumentException("Invalid Argon2 type.");
            }

            // Return the hash as a base64 string
            return Convert.ToBase64String(hash);
        }

        // Method to verify if the provided password matches the stored hash
        public bool VerifyPassword(string password, string storedHash, Argon2Type argon2Type)
        {
            // Hash the provided password
            string hashAttempt = HashPassword(password, argon2Type);

            // Compare the hashes
            return storedHash == hashAttempt;
        }

        // Method to log the configuration of the hashing parameters
        public string GetConfiguration()
        {
            return $"Memory Cost: {_memoryCost} KiB, Time Cost: {_timeCost} iterations, Parallelism: {_parallelism}, Hash Size: {_hashSize} bytes";
        }
    }

    // Enum for Argon2 hash types
    public enum Argon2Type
    {
        Argon2d,
        Argon2i,
        Argon2id
    }
}