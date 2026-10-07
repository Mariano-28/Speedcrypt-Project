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
// https://www.gnu.org/licenses/gpl-3.0.html

using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Autotest.CRYPTO.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// PgpTest: Unit test class for the PGP engine integrated in Speedcrypt.
    /// Validates RSA key generation, key ring handling, and AES-256 encryption/decryption.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    /// 
    /// <remarks>
    /// This class ensures:
    /// - Correct generation of RSA 2048-bit key pairs using SecureRandom
    /// - Proper creation, serialization, and reloading of public and secret key rings
    /// - Correct AES-256 encryption and decryption of test messages
    /// - Validation of decrypted message integrity
    /// - Any mismatch or exception is treated as a critical test failure and logged centrally
    ///  
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    internal class PgpTest : ITest
    {
        public string Name => "PGP ENGINE SELF-TEST";
        public ITestResult Perform()
        {
            try
            {
                // === RSA key generation ===
                RsaKeyPairGenerator kpg = new RsaKeyPairGenerator();
                kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 25));

                AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
                DateTime now = DateTime.UtcNow;

                // === Key ring generation ===
                PgpKeyPair pgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp, now);
                PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                    PgpSignature.DefaultCertification,
                    pgpKeyPair,
                    "Speedcrypt Test <test@speedcrypt.local>",
                    SymmetricKeyAlgorithmTag.Aes256,
                    "testpass".ToCharArray(),
                               true,
                               null,
                               null,
                               new SecureRandom());

                // === Public and secret key rings ===
                PgpPublicKeyRing pubRing = keyRingGen.GeneratePublicKeyRing();
                PgpSecretKeyRing secRing = keyRingGen.GenerateSecretKeyRing();

                // === Serialize and reload ===
                byte[] pubBytes = pubRing.GetEncoded();
                byte[] secBytes = secRing.GetEncoded();

                PgpPublicKeyRing pubReloaded = new PgpPublicKeyRing(pubBytes);
                PgpSecretKeyRing secReloaded = new PgpSecretKeyRing(secBytes);

                // === Encrypt sample data ===
                string message = "Speedcrypt_PGP_SelfTest_OK";
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                MemoryStream outputStream = new MemoryStream();

                PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());
                encGen.AddMethod(pubReloaded.GetPublicKey());

                Stream encOut = encGen.Open(outputStream, messageBytes.Length);
                encOut.Write(messageBytes, 0, messageBytes.Length);
                encOut.Close();

                byte[] encryptedData = outputStream.ToArray();

                // === Decrypt ===
                PgpObjectFactory objFactory = new PgpObjectFactory(encryptedData);
                PgpEncryptedDataList encList = (PgpEncryptedDataList)objFactory.NextPgpObject();
                PgpPublicKeyEncryptedData encPgp = (PgpPublicKeyEncryptedData)encList[0];

                PgpPrivateKey privateKey = secReloaded.GetSecretKey().ExtractPrivateKey("testpass".ToCharArray());
                Stream clear = encPgp.GetDataStream(privateKey);

                byte[] decrypted = Streams.ReadAll(clear);
                string decryptedText = Encoding.UTF8.GetString(decrypted);

                // === Validation ===
                if (!decryptedText.Equals(message))
                    throw new Exception("Decrypted text mismatch.");

                return new SimpleTestResult(true, "PGP engine self-test passed successfully.");
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "PGP ENGINE SELF-TEST", "PGP engine self-test failed: " + ex.Message);
                return new SimpleTestResult(false, "PGP engine self-test failed: " + ex.Message);
            }
        }
    }
}