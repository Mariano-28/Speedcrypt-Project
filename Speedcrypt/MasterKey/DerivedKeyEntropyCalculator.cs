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

namespace Speedcrypt.MasterKey
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// DerivedKeyEntropyCalculator: Utility support class for evaluating
    /// theoretical entropy and classification score of derived cryptographic keys
    /// within the Speedcrypt framework.
    /// </summary>
    ///
    /// <remarks>
    /// This class is NOT a cryptographic component.
    /// It does not derive keys, generate randomness, or perform any
    /// cryptographic transformation.
    ///
    /// Its sole responsibility is to:
    /// - Calculate the theoretical entropy of an already-derived key,
    ///   based strictly on key length (uniform byte assumption)
    /// - Classify that entropy into a discrete Speedcrypt security score
    ///
    /// The entropy value is a deterministic, mathematical property
    /// derived from key size only. It does NOT represent:
    /// - Real-world randomness quality
    /// - Resistance to attacks
    /// - Strength of the key derivation function
    /// - Password strength or SALT quality
    ///
    /// The resulting score is a classification indicator,
    /// not a security guarantee and not a probabilistic estimate.
    ///
    /// 📒 Security Note:
    /// This class has no cryptographic authority.
    /// It must NEVER be used as a decision-making component
    /// in the cryptographic trust chain.
    /// Any security assumption based solely on this score
    /// is conceptually incorrect.
    ///
    /// Designed for informational, comparative, and UI-level
    /// evaluation purposes within Speedcrypt.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>
    public static class DerivedKeyEntropyCalculator
    {
        /// <summary>
        /// Calculates the theoretical entropy (in bits) of a derived cryptographic key.
        /// Assumes uniform distribution of bytes.
        /// </summary>
        /// <param name="derivedKey">Derived key as byte array</param>
        /// <returns>Entropy in bits</returns>
        public static int CalculateEntropyBits(byte[] derivedKey)
        {
            if (derivedKey == null)
                throw new ArgumentNullException(nameof(derivedKey));

            // Each byte contributes exactly 8 bits of entropy
            return derivedKey.Length * 8;
        }

        /// <summary>
        /// Calculates the Speedcrypt security score (0–4) based on derived key entropy.
        /// This is a classification, not an estimation.
        /// </summary>
        /// <param name="derivedKey">Derived key as byte array</param>
        /// <returns>Speedcrypt score from 0 (weak) to 4 (very strong)</returns>
        public static int CalculateScore(byte[] derivedKey)
        {
            if (derivedKey == null)
                throw new ArgumentNullException(nameof(derivedKey));

            int entropyBits = CalculateEntropyBits(derivedKey);

            if (entropyBits < 128)
                return 0;

            if (entropyBits < 192)
                return 1;

            if (entropyBits < 256)
                return 2;

            if (entropyBits < 512)
                return 3;

            return 4;
        }
    }
}