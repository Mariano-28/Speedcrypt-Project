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
    /// RipeMD320DigestTest: Unit test class for the RIPEMD-320 hash function.
    /// Validates output against official test vectors and the well-known
    /// "one million 'a'" test vector.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// <remarks>
    /// This test class ensures:
    /// - Correct RIPEMD-320 digest computation for multiple reference messages
    /// - Byte-for-byte conformity with known reference outputs
    /// - Deterministic behavior across repeated invocations
    /// - Correct handling of very large inputs (one million 'a' test)
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class RipeMD320DigestTest : DigestTest
    {
        private readonly static string[] messages = {
            "",
            "a",
            "abc",
            "message digest",
            "abcdefghijklmnopqrstuvwxyz",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        };

        private readonly static string[] digests = {
            "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
            "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d",
            "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
            "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197",
            "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009",
            "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac",
            "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4",
            "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42"
        };

        private readonly static string million_a_digest = "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66";
        public RipeMD320DigestTest()
            : base(new RipeMD320DigestWrapper(), messages, digests)
        {
        }
        public override void PerformTest()
        {
            // Standard test vectors
            for (int i = 0; i < messages.Length; i++)
            {
                var digestWrapper = new RipeMD320DigestWrapper();
                byte[] input = System.Text.Encoding.ASCII.GetBytes(messages[i]);
                digestWrapper.BlockUpdate(input, 0, input.Length);

                byte[] result = new byte[digestWrapper.GetDigestSize()];
                digestWrapper.DoFinal(result, 0);

                string hexResult = BitConverter.ToString(result).Replace("-", "").ToLowerInvariant();

                if (hexResult != digests[i])
                    throw new Exception($"Digest mismatch at message index {i}");
            }

            // Optimized Million 'a' test
            var digestMillion = new RipeMD320DigestWrapper();
            byte singleA = (byte)'a';
            byte[] buffer = new byte[1024];
            for (int i = 0; i < buffer.Length; i++)
                buffer[i] = singleA;

            int loops = 1000000 / buffer.Length;
            for (int i = 0; i < loops; i++)
                digestMillion.BlockUpdate(buffer, 0, buffer.Length);

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
            return new RipeMD320DigestWrapper((RipeMD320DigestWrapper)digest);
        }
    }
}