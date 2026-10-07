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
    /// RipeMD160DigestTest: Unit test class for the RIPEMD-160 hash function.
    /// Validates output against known reference vectors, including standard messages
    /// and the "million 'a'" test vector.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This test class ensures:
    /// - Correct RIPEMD-160 digest computation for standard messages
    /// - Correct handling of very large inputs (million 'a' test)
    /// - Byte-for-byte conformity with official reference outputs
    /// - Deterministic and resettable digest behavior
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    /// 
    [TestFixture]
    public class RipeMD160DigestTest : DigestTest
    {
        private static readonly string[] messages = {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    };

        private static readonly string[] digests = {
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        "5d0689ef49d2fae572b881b123a85ffa21595f36",
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
    };

        private static readonly string million_a_digest = "52783243c1697bdbe16d37f97f68f08325dc1528";
        public RipeMD160DigestTest()
            : base(new RipeMD160DigestWrapper(), messages, digests)
        {
        }
        public override void PerformTest()
        {
            // Standard messages test
            for (int i = 0; i < messages.Length; i++)
            {
                var digestWrapper = new RipeMD160DigestWrapper();
                byte[] input = System.Text.Encoding.ASCII.GetBytes(messages[i]);
                digestWrapper.BlockUpdate(input, 0, input.Length);

                byte[] result = new byte[digestWrapper.GetDigestSize()];
                digestWrapper.DoFinal(result, 0);

                string hexResult = BitConverter.ToString(result).Replace("-", "").ToLowerInvariant();

                if (hexResult != digests[i])
                    throw new Exception($"Digest mismatch at message index {i}");
            }

            // Million 'a' test
            var digestMillion = new RipeMD160DigestWrapper();
            byte singleA = (byte)'a';
            byte[] buffer = new byte[1024];
            for (int i = 0; i < buffer.Length; i++) buffer[i] = singleA;

            int loops = 1000000 / buffer.Length;
            for (int i = 0; i < loops; i++)
            {
                digestMillion.BlockUpdate(buffer, 0, buffer.Length);
            }

            int remainder = 1000000 % buffer.Length;
            if (remainder > 0)
                digestMillion.BlockUpdate(buffer, 0, remainder);

            byte[] millionResult = new byte[digestMillion.GetDigestSize()];
            digestMillion.DoFinal(millionResult, 0);

            string millionHex = BitConverter.ToString(millionResult).Replace("-", "").ToLowerInvariant();
            if (millionHex != million_a_digest)
                throw new Exception("Million 'a' test failed");
        }
        protected override IDigest CloneDigest(IDigest digest)
        {
            return new RipeMD160DigestWrapper((RipeMD160DigestWrapper)digest);
        }
    }
}