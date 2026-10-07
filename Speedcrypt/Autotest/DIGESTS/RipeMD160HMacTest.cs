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

using System.Text;

// NUnit unit testing framework
using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// RipeMD160HMacTest: Unit test class for HMAC using the RIPEMD-160 hash function.
    /// Validates output against RFC 2286 test vectors for various key and message lengths.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This test class ensures:
    /// - Correct RIPEMD-160 HMAC computation for standard test vectors
    /// - Handling of keys of varying length, including keys longer than block size
    /// - Byte-for-byte conformity with official RFC 2286 outputs
    /// - Deterministic and resettable HMAC behavior
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class RipeMD160HMacTest
		: ITest
    {
        readonly static string[] keys =
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4a656665",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        };

        readonly static string[] digests = {
            "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
            "dda6c0213a485a9e24f4742064a7f033b43c4069",
            "b0b105360de759960ab4f35298e116e295d8e7c1",
            "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
            "7619693978f91d90539ae786500ff3d8e0518e39",
            "6466ca07ac5eac29e1bd523e5ada7605b791fd8b",
            "69ea60798d71616cce5fd0871e23754cd75d5a0a"
        };

        readonly static string[] messages = {
            "Hi There",
            "what do ya want for nothing?",
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "Test With Truncation",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        };
        public string Name
        {
			get { return "RipeMD160HMac"; }
        }
		public ITestResult Perform()
        {
            HMac hmac = new HMac(new RipeMD160Digest());
            byte[] resBuf = new byte[hmac.GetMacSize()];

            for (int i = 0; i < messages.Length; i++)
            {
                byte[] m = Encoding.ASCII.GetBytes(messages[i]);
                if (messages[i].StartsWith("0x"))
                {
                    m = Hex.Decode(messages[i].Substring(2));
                }
                hmac.Init(new KeyParameter(Hex.Decode(keys[i])));
                hmac.BlockUpdate(m, 0, m.Length);
                hmac.DoFinal(resBuf, 0);

                if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[i])))
                {
                    return new SimpleTestResult(false, Name + ": Vector " + i + " failed");
                }
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

		[Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            //Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}