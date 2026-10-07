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

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Lightweight assertion utility designed to remove dependency on external test frameworks.
    /// /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// <remarks>
    /// This class provides a minimal set of assertion helpers intended for:
    /// - Internal consistency checks
    /// - Cryptographic test validation
    /// - Self-contained test routines where external frameworks are undesirable
    ///
    /// The implementation is intentionally simple and explicit to ensure:
    /// - Maximum readability
    /// - Immediate failure visibility
    /// - No hidden behavior or side effects
    ///
    /// All failures raise a standard Exception with a clear diagnostic message.
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class Assert
    {
        /// <summary>
        /// Verifies that a condition is true.
        /// Throws an exception if the condition evaluates to false.
        /// </summary>
        public static void IsTrue(bool condition, string message = null)
        {
            if (!condition)
                throw new Exception(message ?? "Assertion failed.");
        }

        /// <summary>
        /// Verifies that two byte arrays are equal in length and content.
        /// Throws an exception on the first detected mismatch.
        /// </summary>
        public static void AreEqual(byte[] expected, byte[] actual, string message = null)
        {
            if (expected == null && actual == null)
                return;

            if (expected == null || actual == null)
                throw new Exception(message ?? "One of the arrays is null.");

            if (expected.Length != actual.Length)
                throw new Exception(
                    message ?? "Array length mismatch. Expected: "
                    + expected.Length + ", actual: " + actual.Length
                );

            for (int i = 0; i < expected.Length; i++)
            {
                if (expected[i] != actual[i])
                    throw new Exception(
                        message ?? "Array mismatch at index " + i + "."
                    );
            }
        }
    }
    // ============================== Usage ======================================
    //byte[] hash1 = ComputeHash(data);
    //byte[] hash2 = ComputeReferenceHash(data);

    //Assert.IsTrue(hash1.Length == 32, "Invalid hash length.");
    //Assert.AreEqual(hash2, hash1, "Hash output does not match reference value.");
}
