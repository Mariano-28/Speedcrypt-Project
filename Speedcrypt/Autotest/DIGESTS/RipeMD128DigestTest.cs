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
using Speedcrypt.Autotest.DIGESTS.WRAPPER;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// RipeMD128DigestTest: Unit test class for the RIPEMD-128 hash function.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// Validates output against known reference vectors, including standard messages
    /// and the "million 'a'" test vector.
    /// </summary>
    /// 
    /// <remarks>
    /// This test class ensures:
    /// - Correct RIPEMD-128 digest computation for standard messages
    /// - Correct handling of very large inputs (million 'a' test)
    /// - Byte-for-byte conformity with official reference outputs
    /// - Deterministic and resettable digest behavior
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class RipeMD128DigestTest : DigestTest
    {
        readonly static string[] messages = {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };

        readonly static string[] digests = {
        "cdf26213a150dc3ecb610f18f6b38b46",
        "86be7afa339d0fc7cfc785e72f578d33",
        "c14a12199c66e4ba84636b0f69144c77",
        "9e327b3d6e523062afc1132d7df9d1b8",
        "fd2aa607f71dc8f510714922b371834e",
        "a1aa0689d0fafa2ddc22e88b49133a06",
        "d1e959eb179c911faea4624c60c5c702",
        "3f45ef194732c2dbb2c4a2c769795fa3"
    };

        readonly static string million_a_digest = "4a7f5723f954eba1216c9d8f6320431f";
        public RipeMD128DigestTest()
            : base(new RipeMD128DigestWrapper(), messages, digests)
        {
        }
        public override void PerformTest()
        {
            // Test standard messages
            for (int i = 0; i < messages.Length; i++)
            {
                var digestWrapper = new RipeMD128DigestWrapper();
                byte[] input = System.Text.Encoding.ASCII.GetBytes(messages[i]);
                digestWrapper.BlockUpdate(input, 0, input.Length);

                byte[] result = new byte[digestWrapper.GetDigestSize()];
                digestWrapper.DoFinal(result, 0);

                string hexResult = BitConverter.ToString(result).Replace("-", "").ToLowerInvariant();

                if (hexResult != digests[i])
                    throw new Exception($"Digest mismatch at message index {i}");
            }

            // Optimized Million 'a' test
            var digestMillion = new RipeMD128DigestWrapper();
            byte singleA = (byte)'a';
            byte[] singleBuffer = new byte[1024];
            for (int i = 0; i < singleBuffer.Length; i++) singleBuffer[i] = singleA;

            int loops = 1000000 / singleBuffer.Length; // Reduce the number of iterations
            for (int i = 0; i < loops; i++)
            {
                digestMillion.BlockUpdate(singleBuffer, 0, singleBuffer.Length);
            }

            // Handle remaining bytes if necessary
            int remainder = 1000000 % singleBuffer.Length;
            if (remainder > 0)
            {
                digestMillion.BlockUpdate(singleBuffer, 0, remainder);
            }

            byte[] millionResult = new byte[digestMillion.GetDigestSize()];
            digestMillion.DoFinal(millionResult, 0);

            string millionHex = BitConverter.ToString(millionResult).Replace("-", "").ToLowerInvariant();
            if (millionHex != million_a_digest)
                throw new Exception("Million 'a' test failed");
        }

        protected override IDigest CloneDigest(IDigest digest)
        {
            return new RipeMD128DigestWrapper((RipeMD128DigestWrapper)digest);
        }
    }
}