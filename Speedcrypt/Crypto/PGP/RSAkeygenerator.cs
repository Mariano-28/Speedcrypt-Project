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

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// RSAkeygenerator: Generates a PGP-compatible RSA key pair and exports it to files with optional passphrase protection.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements RSA key generation for PGP with the following key features:
    /// - Generates an RSA key pair of specified key size using BouncyCastle's RsaKeyPairGenerator
    /// - Protects the private key with a passphrase; public key remains safe for distribution
    /// - Saves private key to "PGPPrivateKeyRSA.asc" and public key to "PGPPublicKeyRSA.asc" at the specified key store location
    /// - Supports ASCII-armored output for portability
    /// - Reports progress at key stages via an optional Action<int> delegate
    /// - Non-deterministic key generation using SecureRandom ensures cryptographic security
    /// - Fully compatible with Speedcrypt framework's PgpEncryptor and PgpDecryptor classes
    ///
    /// Technical note:
    /// - Uses standard exponent 65537 for RSA key generation
    /// - Private key export uses PgpSecretKey with Cast5 symmetric encryption for compatibility
    /// - Passphrase arrays are cleared immediately after use to maintain memory safety
    /// - Stream access uses exclusive file locking to avoid concurrent write issues
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public static class RSAkeygenerator
     {
         // Generates an RSA key pair and saves it to specified key store with optional password protection
         public static void GenerateKey(string password, string keyStoreUrl, int keySize, Action<int> reportProgress)
         {
             reportProgress?.Invoke(0); // Start from 0

             // Convert password to char[] once for secure handling
             char[] passwordChars = password.ToCharArray();

             // Clear original string reference (optional, cannot clear string content in .NET)
             password = null;

             // Use standard secure exponent 65537 (0x10001)
             IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
             kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), keySize, 8));
             reportProgress?.Invoke(15);

             AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();
             reportProgress?.Invoke(35);

             // Ensure exclusive file access
             using (FileStream outPrivate = new FileStream($"{keyStoreUrl}PGPPrivateKeyRSA.asc", FileMode.Create, FileAccess.Write, FileShare.None))
             using (FileStream outPublic = new FileStream($"{keyStoreUrl}PGPPublicKeyRSA.asc", FileMode.Create, FileAccess.Write, FileShare.None))
             {
                 reportProgress?.Invoke(50);

                 // Export keys with ASCII armor and password
                 ExportKeyPair(outPrivate, outPublic, kp.Public, kp.Private, passwordChars, true, reportProgress);

                 // Clear password array immediately for security
                 Array.Clear(passwordChars, 0, passwordChars.Length);
             }

             reportProgress?.Invoke(100);
         }
         private static void ExportKeyPair(Stream secretOut, Stream publicOut, AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey, char[] passPhrase, bool armor, Action<int> reportProgress)
         {
             reportProgress?.Invoke(60);

             // Add a simple User ID for better compatibility
             var userId = "generated@local";

             var secretKey = new PgpSecretKey(
                 PgpSignature.DefaultCertification,
                 PublicKeyAlgorithmTag.RsaGeneral,
                 publicKey,
                 privateKey,
                 DateTime.UtcNow,
                 userId,
                 SymmetricKeyAlgorithmTag.Cast5, // Keep Cast5 for compatibility Speedcrypt
                 passPhrase,
                 null,
                 null,
                 new SecureRandom());

             using (Stream secretOutStream = armor ? new ArmoredOutputStream(secretOut) : secretOut)
             {
                 secretKey.Encode(secretOutStream);
             }

             reportProgress?.Invoke(80);

             using (Stream publicOutStream = armor ? new ArmoredOutputStream(publicOut) : publicOut)
             {
                 PgpPublicKey key = secretKey.PublicKey;
                 key.Encode(publicOutStream);
             }

             reportProgress?.Invoke(95);

             // Clear passphrase array (redundant but safe)
             if (passPhrase != null)
                 Array.Clear(passPhrase, 0, passPhrase.Length);
         }
     }
}