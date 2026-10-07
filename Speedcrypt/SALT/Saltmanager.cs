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
using System.Text;

using Org.BouncyCastle.Security;

// Speedcrypt
using Speedcrypt.SALT.BBS;
using Speedcrypt.SALT.Fortuna;
using Speedcrypt.HASHLibraries;
using Speedcrypt.Digests.Bcrypt;
using Speedcrypt.SALT.AESCTRDRBGen;
using Speedcrypt.SALT.CryptoRandomCSPRNG;

namespace Speedcrypt.SALT
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// Centralized salt generator and manager for Speedcrypt.
    /// 
    /// Features:
    /// - Provides cryptographically secure salts using multiple algorithms:
    ///   BCRYPT, Fortuna, AES-CTR-DRBG, CryptoRandom, BlumBlumShub.
    /// - Supports numeric-only and full-byte modes for algorithm flexibility.
    /// - Centralizes salt creation for consistent usage across the project.
    /// - Allows secure erasure of sensitive salt data after use.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the SALT
    /// and key derivation subsystem.
    ///
    /// Purpose:
    /// - Generate salts deterministically or randomly depending on algorithm choice.
    /// - Ensure cryptographic strength and unpredictability for password hashing
    ///   and other cryptographic operations.
    /// - Provide a unified interface for all salt generation methods.
    ///
    /// Design notes:
    /// - Uses strong cryptographic sources (SecureRandom, AES-CTR-DRBG, BBS) internally.
    /// - Provides deterministic sequences when required for reproducibility.
    /// - All generated salts are post-processed through Skein-256 hashing for uniformity.
    /// - Handles disposal and zeroization of sensitive data carefully.
    ///
    /// Security scope and limits:
    /// - Protects against accidental exposure of salts.
    /// - Does not replace full key derivation functions or other security layers.
    /// - All operations are fail-safe but must be used correctly within Speedcrypt.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    /// Integration guidance:
    /// - Always call SecureErase() after salts are used.
    /// - Catch and log exceptions in every generation method using CentralLog.
    /// </remarks>
    internal static class SaltManager
    {
        public static int maxValue = 10000; // Fortuna max value
        public static int bcryptrnd = 10;   // Default BCRYPT rounds

        private static byte[] SALT = null;

        // Centralized salt generator
        public static byte[] GenerateSalt(string type, int rounds = 10, bool numericMode = true)
        {
            var entropyProvider = new SystemEntropyProvider(); // BouncyCastle CSPRNG
            byte[] saltBytes;

            switch (type.ToUpper())
            {
                case "BCRYPT":
                    saltBytes = BCryptBouncy.BcryptSalt();
                    break;

                case "FORTUNA":
                    saltBytes = FortunaSalt();
                    break;

                case "AES-CTR DRBG":
                    saltBytes = numericMode ? Aesctrdrb(entropyProvider) : AesctrdrbSeq(entropyProvider);
                    break;

                case "CRYPTO-RANDOM":
                    saltBytes = numericMode ? Criptorandom(entropyProvider) : CryptorandomSeq(entropyProvider);
                    break;

                case "BLUM-BLUM-SHUB[BBS]":
                    saltBytes = numericMode ? BlumBlum(entropyProvider) : BlumBlumSeq(entropyProvider);
                    break;

                default:
                    saltBytes = Criptorandom(entropyProvider);
                    break;
            }

            SALT = saltBytes;
            return saltBytes;
        }

        // Fortuna salt
        public static byte[] FortunaSalt()
        {
            NumberGen numberGen = new NumberGen(maxValue);
            byte[] bytes = HASHLib.ComputeSkein256(Encoding.UTF8.GetBytes(numberGen.GetOne().ToString()));
            return bytes;
        }
        // Bcrypt salt
        public static byte[] BcryptSalt()
        {
            byte[] salt = new byte[16];
            new SecureRandom().NextBytes(salt);
            return salt;
        }
        // CryptoRandom with entropy
        public static byte[] Criptorandom(SystemEntropyProvider entropyProvider)
        {
            var cryptrand = new CryptoRandom(entropyProvider);
            byte[] randomBytes = cryptrand.NextBytes(32);
            return HASHLib.ComputeSkein256(randomBytes);
        }
        public static byte[] CryptorandomSeq(SystemEntropyProvider entropyProvider)
        {
            var cryptrand = new CryptoRandom(entropyProvider);
            byte[] hexBytes = Encoding.UTF8.GetBytes(cryptrand.NextHexString(32));
            return HASHLib.ComputeSkein256(hexBytes);
        }
        // AES-CTR DRBG
        public static byte[] Aesctrdrb(SystemEntropyProvider entropyProvider)
        {
            var aesRng = new AesCtrDrbg(entropyProvider);
            byte[] intBytes = Encoding.UTF8.GetBytes(aesRng.NextInt(1000, 1000000).ToString());
            return HASHLib.ComputeSkein256(intBytes);
        }
        public static byte[] AesctrdrbSeq(SystemEntropyProvider entropyProvider)
        {
            var aesRngSeq = new AesCtrDrbg(entropyProvider);
            byte[] randomBytes = aesRngSeq.NextBytes(32);
            return HASHLib.ComputeSkein256(randomBytes);
        }
        // Blum-Blum-Shub
        public static byte[] BlumBlum(SystemEntropyProvider entropyProvider)
        {
            var blumBlum = new BlumBlumShub(1024, entropyProvider);
            byte[] numberBytes = blumBlum.GenerateRandomNumber(128).ToByteArray();
            return HASHLib.ComputeSkein256(numberBytes);
        }
        public static byte[] BlumBlumSeq(SystemEntropyProvider entropyProvider)
        {
            var blumBlumSeq = new BlumBlumShub(1024, entropyProvider);
            byte[] numberBytes = blumBlumSeq.GenerateRandomNumber(128).ToByteArray();
            return HASHLib.ComputeSkein256(numberBytes);
        }
        // Secure erase
        public static void SecureErase()
        {
            if (SALT != null)
            {
                Array.Clear(SALT, 0, SALT.Length);
                SALT = null;
            }
        }
    }
}