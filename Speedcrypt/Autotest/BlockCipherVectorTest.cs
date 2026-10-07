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

using Org.BouncyCastle.Crypto;
using Speedcrypt.Exceptionlog;
using Org.BouncyCastle.Utilities.Encoders;

namespace Speedcrypt.Autotest
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Cryptographic correctness test suite for block cipher vector testing.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This test class provides a self-contained and framework-independent
    /// validation of a block cipher implementation, focusing exclusively on:
    /// - Vector‑based encryption correctness
    /// - Roundtrip decryption verification
    ///
    /// The test vectors are used to ensure compliance with known cipher outputs.
    /// Equivalent classes are found in the Bouncy Castle test suite (BlockCipherVectorTest).
    ///
    /// Original reference implementation:
    /// - org.bouncycastle.crypto.test.BlockCipherVectorTest (Java Bouncy Castle)
    ///
    /// This C# adaptation preserves the semantic behavior of the reference tests
    /// while adapting structure, error handling, and execution flow to .NET.
    ///
    /// The class intentionally avoids reliance on external unit test frameworks
    /// for core validation logic, in line with the Speedcrypt philosophy of:
    /// - Explicit behavior
    /// - Deterministic results
    /// - Immediate failure on deviation
    ///
    /// All comparisons are performed byte‑for‑byte.
    /// Any mismatch indicates a non‑conformant block cipher implementation.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class BlockCipherVectorTest : SimpleTest
    {
        int id;
        IBlockCipher engine;
        ICipherParameters param;
        byte[] input;
        byte[] output;

        public BlockCipherVectorTest(
            int id,
            IBlockCipher engine,
            ICipherParameters param,
            string input,
            string output)
        {
            this.id = id;
            this.engine = engine;
            this.param = param;
            this.input = Hex.Decode(input);
            this.output = Hex.Decode(output);
        }
        public override string Name
        {
            get { return engine.AlgorithmName + " Vector Test " + id; }
        }
        public override void PerformTest()
        {
            try
            {
                BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

                cipher.Init(true, param);

                byte[] outBytes = new byte[input.Length];

                int len1 = cipher.ProcessBytes(input, 0, input.Length, outBytes, 0);

                cipher.DoFinal(outBytes, len1);

                if (!AreEqual(outBytes, output))
                {
                    Fail("failed - " + "expected " + Hex.ToHexString(output) + " got " + Hex.ToHexString(outBytes));
                }

                cipher.Init(false, param);

                int len2 = cipher.ProcessBytes(output, 0, output.Length, outBytes, 0);

                cipher.DoFinal(outBytes, len2);

                if (!AreEqual(input, outBytes))
                {
                    Fail("failed reversal got " + Hex.ToHexString(outBytes));
                }
            }
            catch (Exception ex)
            {
                Fail("failed - exception - " + ex);
                CentralLog.LogException(ex, "BlockCipherVectorTest", "failed - exception! " + ex.Message);
            }
        }
    }
}