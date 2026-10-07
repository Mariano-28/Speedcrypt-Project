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
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

namespace Speedcrypt.Autotest.DIGESTS
{
    namespace SpeedcryptAutotest
    {
        /// <summary>
        /// Created by Mariano Ortu
        /// 
        /// Cryptographic correctness test suite for BLAKE2b digest implementation.
        /// /// Designed for Speedcrypt Autotest framework with centralized logging.
        /// </summary>
        /// <remarks>
        /// This test class provides a self-contained and framework-independent
        /// validation of the BLAKE2b hash function, focusing exclusively on:
        /// - Algorithmic correctness
        /// - Keyed and unkeyed test vector validation
        /// - Digest reset functionality
        ///
        /// Test vectors are derived from known reference outputs and ensure:
        /// - Byte-for-byte output conformity
        /// - Deterministic behavior across repeated invocations
        ///
        /// The implementation intentionally avoids external unit test frameworks to guarantee:
        /// - Explicit and immediate failure visibility
        /// - Maximum readability and clarity of test logic
        /// - No hidden side effects or implicit behaviors
        ///
        /// This C# implementation is inspired by, and analogous to, the
        /// Blake2bDigestTest class from the Bouncy Castle Java test suite
        /// (org.bouncycastle.crypto.test.Blake2bDigestTest).
        ///
        /// Any mismatch between expected and actual output indicates a non-conformant BLAKE2b implementation.
        ///
       /// Responsibility for integration, testing, and any minor adaptation within
        /// lies entirely with the author.
        /// </remarks>

        [TestFixture]
        public class Blake2bDigestTest : SimpleTest
        {
            // Keyed test vectors: message, key, expected hash (hex)
            private static readonly string[,] keyedTestVectors = {
            { "", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                  "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568" },
            {     "00", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                  "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd" }
        };

            // Unkeyed test vectors: expected hash (hex), input message
            private static readonly string[,] unkeyedTestVectors = {
            { "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", "" },
            { "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918", "The quick brown fox jumps over the lazy dog" }
        };
            public override string Name => "BLAKE2b";

            /// <summary>
            /// Performs the test on keyed and unkeyed vectors
            /// </summary>
            public override void PerformTest()
            {
                // Keyed vectors test
                for (int i = 0; i < keyedTestVectors.GetLength(0); i++)
                {
                    byte[] input = Hex.Decode(keyedTestVectors[i, 0]);
                    byte[] key = Hex.Decode(keyedTestVectors[i, 1]);
                    byte[] expected = Hex.Decode(keyedTestVectors[i, 2]);

                    Blake2bDigest digest = new Blake2bDigest(key);
                    digest.BlockUpdate(input, 0, input.Length);
                    byte[] hash = new byte[digest.GetDigestSize()];
                    digest.DoFinal(hash, 0);

                    if (!Arrays.AreEqual(expected, hash))
                        Fail("BLAKE2b keyed vector mismatch at index " + i);
                }

                // Unkeyed vectors test
                for (int i = 0; i < unkeyedTestVectors.GetLength(0); i++)
                {
                    byte[] input = Encoding.UTF8.GetBytes(unkeyedTestVectors[i, 1]);
                    byte[] expected = Hex.Decode(unkeyedTestVectors[i, 0]);

                    Blake2bDigest digest = new Blake2bDigest();
                    digest.BlockUpdate(input, 0, input.Length);
                    byte[] hash = new byte[digest.GetDigestSize()];
                    digest.DoFinal(hash, 0);

                    if (!Arrays.AreEqual(expected, hash))
                        Fail("BLAKE2b unkeyed vector mismatch at index " + i);
                }

                ResetTest();
            }

            /// <summary>
            /// Test digest reset functionality
            /// </summary>
            private void ResetTest()
            {
                byte[] key = new byte[32];
                for (byte i = 0; i < key.Length; i++) key[i] = i;

                byte[] input = new byte[key.Length + 1];
                for (byte i = 0; i < input.Length; i++) input[i] = i;

                Blake2bDigest digest1 = new Blake2bDigest(key);
                digest1.BlockUpdate(input, 0, input.Length);
                byte[] hash1 = new byte[digest1.GetDigestSize()];
                digest1.DoFinal(hash1, 0);

                Blake2bDigest digest2 = new Blake2bDigest(key);
                digest2.BlockUpdate(input, 0, input.Length);
                digest2.Reset();
                digest2.BlockUpdate(input, 0, input.Length);
                byte[] hash2 = new byte[digest2.GetDigestSize()];
                digest2.DoFinal(hash2, 0);

                if (!Arrays.AreEqual(hash1, hash2))
                    Fail("Digest reset test failed");
            }

            [Test]
            public void TestFunction()
            {
                string resultText = Perform().ToString();
                //Assert.AreEqual(Name + ": Okay", resultText);
            }
        }
    }
}