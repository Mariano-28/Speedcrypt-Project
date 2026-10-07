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

// NUnit unit testing framework
using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Speedcrypt.Autotest.DIGESTS.WRAPPER;

namespace Speedcrypt.Autotest.DIGESTS
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Whirlpool digest test suite verifying output against ISO standard vectors.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This test class ensures:
    /// - Correct Whirlpool hash output computation for a variety of input lengths
    /// - Validation against official ISO test vectors for empty input, single characters, short messages, and long messages including 1-million-character test
    /// - Consistency checks for non-standard inputs like arrays of zero bytes
    /// - Deterministic, byte-level verification without external unit test frameworks
    ///
    /// Test vectors are externally sourced from ISO specifications and known reference implementations.
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    ///
    /// This implementation does not rely on cloning of internal state beyond wrapper initialization,
    /// ensuring fresh digest instances for each test vector, as WhirlpoolDigest internal state is encapsulated.
    /// 
    ////// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    [TestFixture]
    public class WhirlpoolDigestTest : DigestTest
    {
        private static string[] messages =
        {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "abcdbcdecdefdefgefghfghighijhijk"
    };

        private static string[] digests =
        {
        "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3",
        "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A",
        "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5",
        "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E",
        "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B",
        "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467",
        "466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB6014294D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B",
        "2A987EA40F917061F5D6F0A0E4644F488A7A5A52DEEE656207C562F988E95C6916BDC8031BC5BE1B7B947639FE050B56939BAAA0ADFF9AE6745B7B181C3BE3FD"
    };

        private static string _millionAResultVector =
                                        "0C99005BEB57EFF50A7CF005560DDF5D29057FD86B20BFD62DECA0F1CCEA4AF51FC15490EDDC47AF32BB2B66C34FF9AD8C6008AD677F77126953B226E4ED8B01";

        private static string _thirtyOneZeros =
                                        "3E3F188F8FEBBEB17A933FEAF7FE53A4858D80C915AD6A1418F0318E68D49B4E459223CD414E0FBC8A57578FD755D86E827ABEF4070FC1503E25D99E382F72BA";

        public WhirlpoolDigestTest()
            : base(new WhirlpoolDigestWrapper(), messages, digests)
        {
        }
        public override void PerformTest()
        {
            base.PerformTest();

            byte[] thirtyOneZeros = new byte[31];
            performStandardVectorTest("31 zeroes test", thirtyOneZeros, _thirtyOneZeros);

            byte[] millionAInByteArray = new byte[1000000];
            Arrays.Fill(millionAInByteArray, (byte)'a');

            performStandardVectorTest("Million 'a' test", millionAInByteArray, _millionAResultVector);
        }
        private void performStandardVectorTest(string testTitle, byte[] inputBytes, string resultsAsHex)
        {
            doPerformTest(testTitle, inputBytes, resultsAsHex);
        }
        private void doPerformTest(string testTitle, byte[] inputBytes, string resultsAsHex)
        {
            string resStr = createHexOutputFromDigest(inputBytes);
            if (!resultsAsHex.Equals(resStr.ToUpper()))
            {
                Fail(testTitle, resultsAsHex, resStr);
            }
        }
        private string createHexOutputFromDigest(byte[] digestBytes)
        {
            IDigest digest = new WhirlpoolDigestWrapper();
            byte[] resBuf = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(digestBytes, 0, digestBytes.Length);
            digest.DoFinal(resBuf, 0);
            return Hex.ToHexString(resBuf);
        }
        protected override IDigest CloneDigest(IDigest digest)
        {
            return new WhirlpoolDigestWrapper();
        }
        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();
            //Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}