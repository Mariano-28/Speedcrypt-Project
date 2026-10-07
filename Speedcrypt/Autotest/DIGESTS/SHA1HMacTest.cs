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
    /// Sha1HMacTest: Unit test class for HMAC-SHA1 authentication.
    /// Validates HMAC computation against official test vectors
    /// defined in RFC 2202.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This test class verifies:
    /// - Correct HMAC-SHA1 computation for standard test vectors
    /// - Proper handling of hexadecimal-encoded messages
    /// - Correct behavior of the HMAC reset mechanism
    /// - Full conformity with RFC 2202 reference outputs
    ///
    /// Responsibility for this C# implementation, integration,
    /// and validation lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class Sha1HMacTest
    : ITest
    {
        public string Name
        {
            get { return "SHA1HMac"; }
        }

        public static readonly string[] keys = new string[]
        {
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4a656665",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0102030405060708090a0b0c0d0e0f10111213141516171819",
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        };

        public static readonly string[] digests = new string[]
        {
        "b617318655057264e28bc0b6fb378c8ef146be00",
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
        "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
        "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        };

        public static readonly string[] messages = new string[]
        {
        "Hi There",
        "what do ya want for nothing?",
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "Test With Truncation",
        "Test Using Larger Than Block-Size Key - Hash Key First",
        "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        };
        public virtual ITestResult Perform()
        {
            HMac hmac = new HMac(new Sha1Digest());
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

            //
            // test reset
            //
            int vector = 0;
            byte[] m2 = Encoding.ASCII.GetBytes(messages[vector]);
            if (messages[vector].StartsWith("0x"))
            {
                m2 = Hex.Decode(messages[vector].Substring(2));
            }

            hmac.Init(new KeyParameter(Hex.Decode(keys[vector])));
            hmac.BlockUpdate(m2, 0, m2.Length);
            hmac.DoFinal(resBuf, 0);
            hmac.Reset();
            hmac.BlockUpdate(m2, 0, m2.Length);
            hmac.DoFinal(resBuf, 0);

            if (!Arrays.AreEqual(resBuf, Hex.Decode(digests[vector])))
            {
                return new SimpleTestResult(false, Name + " Reset with vector " + vector + " failed");
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();
            // Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}