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
    /// Created by Mariano Ortu
    /// 
    /// RipeMD256DigestTest: Unit test class for the RIPEMD-256 hash function.
    /// Validates output against official test vectors and the well-known
    /// "one million 'a'" test vector.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This test class ensures:
    /// - Correct RIPEMD-256 digest computation for multiple reference messages
    /// - Byte-for-byte conformity with known reference outputs
    /// - Deterministic behavior across repeated invocations
    /// - Correct handling of very large inputs (one million 'a' test)
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class RipeMD256DigestTest : DigestTest
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
            "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
            "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
            "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
            "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
            "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133",
            "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
            "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8",
            "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd"
        };

        private readonly static string million_a_digest = "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978";

        public RipeMD256DigestTest()
            : base(new RipeMD256DigestWrapper(), messages, digests)
        {
        }
        public override void PerformTest()
        {
            // Standard test vectors
            for (int i = 0; i < messages.Length; i++)
            {
                var digestWrapper = new RipeMD256DigestWrapper();
                byte[] input = System.Text.Encoding.ASCII.GetBytes(messages[i]);
                digestWrapper.BlockUpdate(input, 0, input.Length);

                byte[] result = new byte[digestWrapper.GetDigestSize()];
                digestWrapper.DoFinal(result, 0);

                string hexResult = BitConverter.ToString(result).Replace("-", "").ToLowerInvariant();

                if (hexResult != digests[i])
                    throw new Exception($"Digest mismatch at message index {i}");
            }

            // Optimized Million 'a' test
            var digestMillion = new RipeMD256DigestWrapper();
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
            return new RipeMD256DigestWrapper((RipeMD256DigestWrapper)digest);
        }
    }
}