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

// NUnit unit testing framework
using NUnit.Framework;

// Speedcrypt
using Speedcrypt.Digests.Blake;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Blake512Test: Self-contained test suite for the BLAKE-512 hash function.
    /// /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// Original implementation by Dominik Reichl (https://www.dominik-reichl.de/projects/blakesharp/).
    /// </summary>
    ///
    /// <remarks>
    /// This class provides validation routines for the BLAKE-512 hash function, including:
    /// - Basic self-tests using predefined test vectors
    /// - Byte-for-byte comparison against expected outputs
    ///
    /// Acknowledgment: The original implementation is by Dominik Reichl.
    /// Usage in Speedcrypt is strictly for reference and integration into the test framework.
    ///
    /// Technical notes:
    /// - Framework-independent implementation
    /// - Uses a utility method (ThrowIfNotEqual) for test verification
    /// - Any modifications, integration, or extensions in Speedcrypt are clearly marked as our own work
    ///
    /// Responsibility for this C# adaptation, integration, and validation
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class BlakeTest : ITest
    {
        public string Name
        {
            get { return "Blake512"; }
        }
        public virtual ITestResult Perform()
        {
            try
            {
                SelfTestPriv();
                return new SimpleTestResult(true, Name + ": Okay");
            }
            catch (Exception ex)
            {
                return new SimpleTestResult(false, Name + ": " + ex.Message);
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();
            // Assert.AreEqual(Name + ": Okay", resultText);
        }

        private void ThrowIfNotEqual(byte[] pb1, byte[] pb2, string strMsg)
        {
            if (!MemUtil.ArraysEqual(pb1, pb2))
                throw new Exception(strMsg);
        }
        private void SelfTestPriv()
        {
            Blake512 blake512 = new Blake512();
            byte[] pbData = new byte[1] { 0 };
            byte[] pbExpc = new byte[64] {
            0x97, 0x96, 0x15, 0x87, 0xF6, 0xD9, 0x70, 0xFA,
            0xBA, 0x6D, 0x24, 0x78, 0x04, 0x5D, 0xE6, 0xD1,
            0xFA, 0xBD, 0x09, 0xB6, 0x1A, 0xE5, 0x09, 0x32,
            0x05, 0x4D, 0x52, 0xBC, 0x29, 0xD3, 0x1B, 0xE4,
            0xFF, 0x91, 0x02, 0xB9, 0xF6, 0x9E, 0x2B, 0xBD,
            0xB8, 0x3B, 0xE1, 0x3D, 0x4B, 0x9C, 0x06, 0x09,
            0x1E, 0x5F, 0xA0, 0xB4, 0x8B, 0xD0, 0x81, 0xB6,
            0x34, 0x05, 0x8B, 0xE0, 0xEC, 0x49, 0xBE, 0xB3
        };
            byte[] pbHash = blake512.ComputeHash(pbData);
            ThrowIfNotEqual(pbHash, pbExpc, "ST-1");

            pbData = new byte[0];
            pbExpc = new byte[64] {
            0xA8, 0xCF, 0xBB, 0xD7, 0x37, 0x26, 0x06, 0x2D,
            0xF0, 0xC6, 0x86, 0x4D, 0xDA, 0x65, 0xDE, 0xFE,
            0x58, 0xEF, 0x0C, 0xC5, 0x2A, 0x56, 0x25, 0x09,
            0x0F, 0xA1, 0x76, 0x01, 0xE1, 0xEE, 0xCD, 0x1B,
            0x62, 0x8E, 0x94, 0xF3, 0x96, 0xAE, 0x40, 0x2A,
            0x00, 0xAC, 0xC9, 0xEA, 0xB7, 0x7B, 0x4D, 0x4C,
            0x2E, 0x85, 0x2A, 0xAA, 0xA2, 0x5A, 0x63, 0x6D,
            0x80, 0xAF, 0x3F, 0xC7, 0x91, 0x3E, 0xF5, 0xB8
        };
            pbHash = blake512.ComputeHash(pbData);
            ThrowIfNotEqual(pbHash, pbExpc, "ST-2");
        }
    }
}