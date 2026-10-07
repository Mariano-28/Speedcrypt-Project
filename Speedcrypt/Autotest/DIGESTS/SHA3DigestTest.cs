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
using System.IO;
using System.Text;

// NUnit unit testing framework
using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Sha3DigestTest: Unit test class for the SHA-3 hash function.
    /// Validates output against standard test vectors from FIPS 202.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This test class ensures:
    /// - Correct SHA-3 hash computation for multiple bit-lengths
    /// - Validation against known reference vectors from official test files
    /// - Proper handling of partial-byte input and reset for independent computations
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class Sha3DigestTest : SimpleTest
    {
        internal class MySha3Digest : Sha3Digest
        {
            internal MySha3Digest(int bitLength) : base(bitLength) { }

            internal int MyDoFinal(byte[] output, int outOff, byte partialByte, int partialBits)
            {
                return DoFinal(output, outOff, partialByte, partialBits);
            }
        }
        public override string Name => "SHA-3";
        public override void PerformTest()
        {
            TestVectors();
        }
        private void TestVectors()
        {
            string relativePath = @"..\..\Autotest\DIGESTS\TESTVECTORS\SHA3\SHAKETestVectors.txt";
            string filePath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, relativePath));

            if (!File.Exists(filePath))
                return;

            using (StreamReader r = new StreamReader(filePath))
            {
                string line;
                while ((line = ReadLine(r)) != null)
                {
                    if (line.Length != 0)
                    {
                        TestVector v = ReadTestVector(r, line);
                        RunTestVector(v);
                    }
                }
            }
        }
        private MySha3Digest CreateDigest(string algorithm)
        {
            if (algorithm.StartsWith("SHA3-"))
            {
                int bits = int.Parse(algorithm.Substring("SHA3-".Length));
                return new MySha3Digest(bits);
            }
            throw new ArgumentException("Unknown algorithm: " + algorithm, "algorithm");
        }
        private byte[] DecodeBinary(string block)
        {
            int bits = block.Length;
            int fullBytes = bits / 8;
            int totalBytes = (bits + 7) / 8;
            byte[] result = new byte[totalBytes];

            for (int i = 0; i < fullBytes; ++i)
            {
                string byteStr = Reverse(block.Substring(i * 8, 8));
                result[i] = (byte)Convert.ToInt32(byteStr, 2);
            }

            if (totalBytes > fullBytes)
            {
                string byteStr = Reverse(block.Substring(fullBytes * 8));
                result[fullBytes] = (byte)Convert.ToInt32(byteStr, 2);
            }

            return result;
        }
        private TestVector ReadTestVector(StreamReader r, string header)
        {
            string[] parts = SplitAround(header, TestVector.SAMPLE_OF);
            string algorithm = parts[0];
            int bits = int.Parse(StripFromChar(parts[1], '-'));

            SkipUntil(r, TestVector.MSG_HEADER);
            string messageBlock = ReadBlock(r);
            if (messageBlock.Length != bits)
            {
                throw new InvalidOperationException("Test vector length mismatch");
            }
            byte[] message = DecodeBinary(messageBlock);

            SkipUntil(r, TestVector.HASH_HEADER);
            byte[] hash = Hex.Decode(ReadBlock(r));

            return new TestVector(algorithm, bits, message, hash);
        }
        private void RunTestVector(TestVector v)
        {
            int bits = v.Bits;
            int partialBits = bits % 8;

            MySha3Digest d = CreateDigest(v.Algorithm);
            byte[] output = new byte[d.GetDigestSize()];

            byte[] m = v.Message;
            if (partialBits == 0)
            {
                d.BlockUpdate(m, 0, m.Length);
                d.DoFinal(output, 0);
            }
            else
            {
                d.BlockUpdate(m, 0, m.Length - 1);
                d.MyDoFinal(output, 0, m[m.Length - 1], partialBits);
            }

            if (!Arrays.AreEqual(v.Hash, output))
            {
                Fail(v.Algorithm + " " + v.Bits + "-bit test vector hash mismatch");
            }
        }
        private string ReadLine(StreamReader r)
        {
            string line = r.ReadLine();
            return line == null ? null : StripFromChar(line, '#').Trim();
        }
        private void SkipUntil(StreamReader r, string header)
        {
            string line;
            do
            {
                line = RequireLine(r);
            } while (line.Length == 0);

            if (!line.Equals(header))
            {
                throw new IOException("Expected: " + header);
            }
        }
        private string RequireLine(StreamReader r)
        {
            string line = ReadLine(r);
            if (line == null) throw new EndOfStreamException();
            return line;
        }
        private string ReadBlock(StreamReader r)
        {
            StringBuilder b = new StringBuilder();
            string line;
            while ((line = ReadBlockLine(r)) != null)
            {
                b.Append(line);
            }
            return b.ToString();
        }
        private string ReadBlockLine(StreamReader r)
        {
            string line = ReadLine(r);
            if (line == null || line.Length == 0) return null;
            return line.Replace(" ", "");
        }
        private string[] SplitAround(string s, string separator)
        {
            int i = s.IndexOf(separator);
            if (i < 0) throw new InvalidOperationException();
            return new string[] { s.Substring(0, i), s.Substring(i + separator.Length) };
        }
        private string StripFromChar(string s, char c)
        {
            int i = s.IndexOf(c);
            if (i >= 0) s = s.Substring(0, i);
            return s;
        }
        private string Reverse(string s)
        {
            char[] cs = s.ToCharArray();
            Array.Reverse(cs);
            return new string(cs);
        }
        internal class TestVector
        {
            internal static string SAMPLE_OF = " sample of ";
            internal static string MSG_HEADER = "Msg as bit string";
            internal static string HASH_HEADER = "Hash val is";

            private readonly string algorithm;
            private readonly int bits;
            private readonly byte[] message;
            private readonly byte[] hash;

            internal TestVector(string algorithm, int bits, byte[] message, byte[] hash)
            {
                this.algorithm = algorithm;
                this.bits = bits;
                this.message = message;
                this.hash = hash;
            }
            public string Algorithm => algorithm;
            public int Bits => bits;
            public byte[] Message => message;
            public byte[] Hash => hash;
        }
    }
}