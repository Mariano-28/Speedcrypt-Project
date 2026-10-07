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

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;

// Speedcrypt
using Speedcrypt.Digests.GOST;
using Speedcrypt.Digests.Blake;
using Speedcrypt.Digests.Blake3;
using Speedcrypt.Digests.Bcrypt;

namespace Speedcrypt.HASHLibraries
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// HASHLib: Central cryptographic hashing library for Speedcrypt.
    /// Provides a unified interface for modern, legacy, and password-based hash algorithms.
    /// </summary>
    ///
    /// <remarks>
    /// This static class acts as the core hashing engine of Speedcrypt and aggregates:
    /// - Cryptographic hash functions (SHA-2, SHA-3, BLAKE, KECCAK, SKEIN, RIPEMD, TIGER, WHIRLPOOL, SM3)
    /// - Memory-hard and password hashing algorithms (Argon2, Scrypt, Bcrypt, PBKDF2)
    /// - HMAC-based constructions using multiple digest families
    ///
    /// The class exposes a unified entry point (ComputeHash) that normalizes algorithm
    /// selection, output formatting (hex/Base64), and compatibility with legacy modules.
    ///
    /// 📒 Security Notes:
    /// - Several algorithms included here (e.g. MD5, RIPEMD-128, TIGER, GOST R 34.11-94)
    ///   are **cryptographically weak or deprecated** by modern standards and are provided
    ///   strictly for legacy compatibility, interoperability, or research purposes.
    /// - This library does **not** enforce policy decisions: algorithm safety depends on
    ///   the caller’s selection and intended use.
    /// - Password-based algorithms rely on external parameters (iterations, memory cost,
    ///   parallelism) that must be chosen responsibly by the integrator.
    ///
    /// 📒 Design Notes:
    /// - The presence of multiple algorithms does not imply equal security guarantees.
    /// - No automatic algorithm upgrading or substitution is performed.
    /// - Sensitive buffers are explicitly cleared where applicable, but complete
    ///   in-memory secrecy cannot be guaranteed by managed runtimes.
    ///
    /// Designed for the Speedcrypt framework with emphasis on completeness,
    /// explicit responsibility, and cryptographic transparency.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class HASHLib
    {
        // Configuration fields (kept as-is)
        public static int memoryCost = 1024, iterations = 3, parallelism = 1, hashSize = 32,
                          srcmem = 16384, scrblksz = 8, scrparal = 1, scrhashsz = 32, // Scrypt Settings
                          pbkdf2iterations = 100000;

         private static string NormalizeHMAC(string raw)
         {
             if (string.IsNullOrWhiteSpace(raw))
                 return string.Empty;

             // canonicalize: trim, uppercase and remove extra underscores/commas/dots but keep for detection
             string v = raw.Trim().ToUpperInvariant();
             v = v.Replace("_", "").Replace(",", "").Replace(".", "");

             // remove spaces so "HMAC SHA-256" -> "HMACSHA-256"
             v = v.Replace(" ", "");

             // Now detect and return the exact token forms expected by the switch below
             // Prefer the hyphenated forms because your ComputeHash switch uses them for many cases.
             if (v.Contains("HMACSHA1") || v.Contains("HMAC-SHA1")) return "HMAC-SHA1";
             if (v.Contains("HMACSHA256") || v.Contains("HMAC-SHA256")) return "HMAC-SHA256";
             if (v.Contains("HMACSHA384") || v.Contains("HMAC-SHA384")) return "HMAC-SHA384";
             if (v.Contains("HMACSHA512") || v.Contains("HMAC-SHA512")) return "HMAC-SHA512";
             if (v.Contains("HMACMD5") || v.Contains("HMAC-MD5")) return "HMAC-MD5";
             if (v.Contains("HMACRIPEMD160") || v.Contains("HMAC-RIPEMD160") || v.Contains("HMACRIPEMD-160"))
                 return "HMAC-RIPEMD160";

             // Not an HMAC we know: return original trimmed input so existing behavior remains unchanged
             return raw.Trim();
         }
 
        // =================================================================================
        // Public unified entry point
        // - input: the input string (password/plaintext)
        // - algorithm: algorithm name (exact strings used in your UI are supported, e.g. "SHA-256", "ARGON2id", "PBKDF2", "HMACSHA256", "SCRYPT", "BCRYPT", etc.)
        // - salt: optional salt string (when required). For algorithms that require bytes you may pass Base64 or raw text depending on your UI.
        // - iterationsParam: optional override for iteration counts (if <=0 the class defaults are used)
        // - toBase64: if true, output is base64; otherwise hex (lower or upper controlled by upperCase)
        // - upperCase: when hex output, produce upper-case hex when true
        // This method centralizes all logic and returns the final formatted string.
        public static string ComputeHash(string input, string algorithm, string salt = "", int iterationsParam = -1, bool toBase64 = false, bool upperCase = false)
        {
            algorithm = NormalizeHMAC(algorithm);
            
            // Normalize algorithm string
            string alg = algorithm?.Trim() ?? string.Empty;

            // Use provided iteration override if given
            if (iterationsParam > 0) { /* local override used where needed below */ }

            // Output holder (byte[] preferred). Some functions return string; we'll convert to bytes when possible.
            byte[] resultBytes = null;
            string interimString = null;

            switch (alg.ToUpperInvariant())
            {
                // BCRYPT
                case "BCRYPT":
                    {
                        int rounds = 10;
                        byte[] saltBytes = string.IsNullOrEmpty(salt) ? BCryptBouncy.BcryptSalt() : Convert.FromBase64String(salt);
                        interimString = ComputeBcrypt(input, saltBytes, rounds);
                        try { resultBytes = Convert.FromBase64String(interimString); }
                        catch { resultBytes = Encoding.UTF8.GetBytes(interimString); }
                        break;
                    }

                // PBKDF2
                case "PBKDF2":
                    {
                        int iters = iterationsParam > 0 ? iterationsParam : pbkdf2iterations;
                        interimString = GeneratePBKDF2Hash(Encoding.UTF8.GetBytes(input), salt, iters, 32, toBase64);
                        resultBytes = toBase64 ? Convert.FromBase64String(interimString) : HexStringToBytes(interimString);
                        break;
                    }

                // HMACs
                case "HMACSHA1":
                case "HMAC-SHA1":
                    resultBytes = HMACSHA1(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(salt));
                    break;
                case "HMAC-MD5":
                    resultBytes = HMACMD5(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(salt));
                    break;
                case "HMAC-SHA256":
                    resultBytes = HMACSHA256(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(salt));
                    break;
                case "HMAC-SHA384":
                    resultBytes = HMACSHA384(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(salt));
                    break;
                case "HMAC-SHA512":
                    resultBytes = HMACSHA512(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(salt));
                    break;
                case "HMAC-RIPEMD160":
                    resultBytes = HMACRIPEMD160(Encoding.UTF8.GetBytes(input), Encoding.UTF8.GetBytes(salt));
                    break;

                // Argon2
                case "ARGON2I":
                    resultBytes = ComputeArgon2i(input);
                    break;
                case "ARGON2D":
                    resultBytes = ComputeArgon2d(input);
                    break;
                case "ARGON2ID":
                    resultBytes = ComputeArgon2id(input);
                    break;

                // Default: fallback su ComputeHashLegacy (Avoid recursion)
                default:
                    {
                        try
                        {
                            string hex = ComputeHashLegacy(input, alg);
                            resultBytes = IsProbablyHex(hex) ? HexStringToBytes(hex) : Encoding.UTF8.GetBytes(hex);
                        }
                        catch (ArgumentException ex)
                        {
                            throw new ArgumentException($"Unknown algorithm: {algorithm}", ex);
                        }
                        break;
                    }
            }
            // Final formatting: if toBase64 true, return base64; else hex according to upperCase
            if (toBase64)
            {
                if (resultBytes == null) resultBytes = Encoding.UTF8.GetBytes(interimString ?? string.Empty);
                return Convert.ToBase64String(resultBytes);
            }
            else
            {
                if (resultBytes == null) resultBytes = Encoding.UTF8.GetBytes(interimString ?? string.Empty);
                string hex = BytesToHex(resultBytes);
                return upperCase ? hex.ToUpperInvariant() : hex.ToLowerInvariant();
            }
        }
        // =================================================================================
        // Keep original ComputeHash signature and implementation for backwards compatibility.
        // It returns hex-lowercase string. This method is used internally by the unified entry.
        public static string ComputeHashLegacy(string input, string algorithm)
        {
            byte[] inputData = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes;

            switch (algorithm)
            {
                case "MD5":
                    hashBytes = ComputeMD5(inputData);
                    break;
                case "ARGON2i":
                    hashBytes = ComputeArgon2i(Encoding.UTF8.GetString(inputData));
                    break;
                case "ARGON2d":
                    hashBytes = ComputeArgon2d(Encoding.UTF8.GetString(inputData));
                    break;
                case "ARGON2id":
                    hashBytes = ComputeArgon2id(Encoding.UTF8.GetString(inputData));
                    break;
                case "SHA-224":
                    hashBytes = ComputeSHA224(inputData);
                    break;
                case "SHA-256":
                    hashBytes = ComputeSHA256(inputData);
                    break;
                case "SHA-384":
                    hashBytes = ComputeSHA384(inputData);
                    break;
                case "SHA-512":
                    hashBytes = ComputeSHA512(inputData);
                    break;
                case "SHA3-256":
                    hashBytes = ComputeSHA3256(inputData);
                    break;
                case "SHA3-384":
                    hashBytes = ComputeSHA3384(inputData);
                    break;
                case "SHA3-512":
                    hashBytes = ComputeSHA3_512(inputData);
                    break;
                case "BLAKE-256":
                    hashBytes = ComputeBlake256(inputData);
                    break;
                case "BLAKE-512":
                    hashBytes = ComputeBlake512(inputData);
                    break;
                case "BLAKE2b":
                    hashBytes = ComputeBlake2b(inputData);
                    break;
                case "BLAKE2s":
                    hashBytes = ComputeBlake2s(inputData);
                    break;
                case "BLAKE3-256":
                    hashBytes = ComputeBlake3256(inputData);
                    break;
                case "BLAKE3-384":
                    hashBytes = ComputeBlake3384(inputData);
                    break;
                case "BLAKE3-512":
                    hashBytes = ComputeBlake3512(inputData);
                    break;
                case "BLAKE3-1024":
                    hashBytes = ComputeBlake31024(inputData);
                    break;
                case "RIPEMD-128":
                    hashBytes = ComputeRIPEMD128(inputData);
                    break;
                case "RIPEMD-160":
                    hashBytes = ComputeRIPEMD160(inputData);
                    break;
                case "RIPEMD-256":
                    hashBytes = ComputeRIPEMD256(inputData);
                    break;
                case "RIPEMD-320":
                    hashBytes = ComputeRIPEMD320(inputData);
                    break;
                case "WHIRLPOOL":
                    hashBytes = ComputeWhirlpool(inputData);
                    break;
                case "SHAKE-128":
                    hashBytes = ComputeSHAKE128(inputData, 32); // default output size 32 bytes
                    break;
                case "SHAKE-256":
                    hashBytes = ComputeSHAKE256(inputData, 64); // default output size 64 bytes
                    break;
                case "TIGER-128,3":
                    hashBytes = ComputeTiger128_3(inputData);
                    break;
                case "TIGER-160,3":
                    hashBytes = ComputeTiger160_3(inputData);
                    break;
                case "TIGER-192,3":
                    hashBytes = ComputeTiger192_3(inputData);
                    break;
                case "GOST R 34.11-94 Standard of Russian Federation":
                    hashBytes = ComputeGOST94(inputData);
                    break;
                case "STREEBOG-256 R 34.11-2012 Russian Federation":
                    hashBytes = ComputeStreebog256(inputData);
                    break;
                case "STREEBOG-512 R 34.11-2012 Russian Federation":
                    hashBytes = ComputeStreebog512(inputData);
                    break;
                case "KECCAK-224":
                    hashBytes = ComputeKeccak224(inputData);
                    break;
                case "KECCAK-256":
                    hashBytes = ComputeKeccak256(inputData);
                    break;
                case "KECCAK-384":
                    hashBytes = ComputeKeccak384(inputData);
                    break;
                case "KECCAK-512":
                    hashBytes = ComputeKeccak512(inputData);
                    break;
                case "SKEIN-256":
                    hashBytes = ComputeSkein256(inputData);
                    break;
                case "SKEIN-512":
                    hashBytes = ComputeSkein512(inputData);
                    break;
                case "SKEIN-1024":
                    hashBytes = ComputeSkein1024(inputData);
                    break;
                case "SM3 Standard of China Republic":
                    hashBytes = ComputeSM3(inputData);
                    break;
                default:
                    throw new ArgumentException("Unknown algorithm: " + algorithm);
            }
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }

        // =================================================================================
        // Helper converters and small utilities (private)
        private static string BytesToHex(byte[] data)
        {
            StringBuilder sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
        private static byte[] HexStringToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return new byte[0];
            if (hex.Length % 2 == 1) hex = "0" + hex;
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }
        private static bool IsProbablyHex(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            // simple heuristic: only hex chars and even length
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!ok) return false;
            }
            return (s.Length % 2) == 0;
        }

        public static readonly byte[] fixedPassword = Encoding.UTF8.GetBytes("Speedcrypt");        
        public static string GeneratePBKDF2Hash(byte[] passwordBytes, string salt, int iterations = 100000, int length = 32, bool toBase64 = false)
        {
            // Choose password: real one or fixedPassword
            byte[] key = (passwordBytes == null || passwordBytes.Length == 0)
                ? (byte[])fixedPassword.Clone()
                : (byte[])passwordBytes.Clone();

            // Convert salt string to bytes
            byte[] saltBytes = salt == null ? new byte[0] : Encoding.UTF8.GetBytes(salt);
            byte[] saltClone = (byte[])saltBytes.Clone();

            try
            {
                var pbkdf2 = new Pkcs5S2ParametersGenerator(
                    new Sha256Digest());

                pbkdf2.Init(key, saltClone, iterations);

                var keyParam = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)
                    pbkdf2.GenerateDerivedMacParameters(length * 8);

                byte[] keyBytes = keyParam.GetKey();

                return toBase64
                    ? Convert.ToBase64String(keyBytes)
                    : BitConverter.ToString(keyBytes).Replace("-", "").ToLower();
            }
            finally
            {
                // Clear temporary sensitive buffers
                Array.Clear(key, 0, key.Length);
                if (passwordBytes != null) Array.Clear(passwordBytes, 0, passwordBytes.Length);
                if (saltBytes != null) Array.Clear(saltBytes, 0, saltBytes.Length);
                if (saltClone != null) Array.Clear(saltClone, 0, saltClone.Length);
            }
        }
         public static byte[] HMACSHA1(byte[] password, byte[] salt)
         {
             byte[] key = (password == null || password.Length == 0) ? (byte[])fixedPassword.Clone() : (byte[])password.Clone();
             try
             {
                 var generator = new Pkcs5S2ParametersGenerator(
                     new Sha1Digest());

                 generator.Init(key, salt, pbkdf2iterations);
                 var derivedKey = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)generator.GenerateDerivedMacParameters(160);

                 return derivedKey.GetKey();
             }
             finally
             {
                 Array.Clear(key, 0, key.Length);
                 if (password != null) Array.Clear(password, 0, password.Length);
             }
         }        
        public static byte[] HMACMD5(byte[] password, byte[] salt)
        {
            byte[] key = (password == null || password.Length == 0) ? (byte[])fixedPassword.Clone() : (byte[])password.Clone();
            try
            {
                var generator = new Pkcs5S2ParametersGenerator(
                    new MD5Digest());
                generator.Init(key, salt, pbkdf2iterations);
                var derivedKey = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)generator.GenerateDerivedMacParameters(128);
                return derivedKey.GetKey();
            }
            finally
            {
                // Clear sensitive buffers immediately
                Array.Clear(key, 0, key.Length);
                if (password != null) Array.Clear(password, 0, password.Length);
            }
        }
        public static byte[] HMACSHA256(byte[] password, byte[] salt)
        {
            byte[] key = (password == null || password.Length == 0) ? (byte[])fixedPassword.Clone() : (byte[])password.Clone();
            try
            {
                var generator = new Pkcs5S2ParametersGenerator(
                    new Sha256Digest());
                generator.Init(key, salt, pbkdf2iterations);
                var derivedKey = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)generator.GenerateDerivedMacParameters(256);
                return derivedKey.GetKey();
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                if (password != null) Array.Clear(password, 0, password.Length);
            }
        }
        public static byte[] HMACSHA384(byte[] password, byte[] salt)
        {
            byte[] key = (password == null || password.Length == 0) ? (byte[])fixedPassword.Clone() : (byte[])password.Clone();
            try
            {
                var generator = new Pkcs5S2ParametersGenerator(
                    new Sha384Digest());
                generator.Init(key, salt, pbkdf2iterations);
                var derivedKey = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)generator.GenerateDerivedMacParameters(384);
                return derivedKey.GetKey();
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                if (password != null) Array.Clear(password, 0, password.Length);
            }
        }
        public static byte[] HMACSHA512(byte[] password, byte[] salt)
        {
            byte[] key = (password == null || password.Length == 0) ? (byte[])fixedPassword.Clone() : (byte[])password.Clone();
            try
            {
                var generator = new Pkcs5S2ParametersGenerator(
                    new Sha512Digest());
                generator.Init(key, salt, pbkdf2iterations);
                var derivedKey = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)generator.GenerateDerivedMacParameters(512);
                return derivedKey.GetKey();
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                if (password != null) Array.Clear(password, 0, password.Length);
            }
        }
        public static byte[] HMACRIPEMD160(byte[] password, byte[] salt)
        {
            byte[] key = (password == null || password.Length == 0) ? (byte[])fixedPassword.Clone() : (byte[])password.Clone();
            try
            {
                var generator = new Pkcs5S2ParametersGenerator(
                    new RipeMD160Digest());
                generator.Init(key, salt, pbkdf2iterations);
                var derivedKey = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)generator.GenerateDerivedMacParameters(160);
                return derivedKey.GetKey();
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                if (password != null) Array.Clear(password, 0, password.Length);
            }
        }
        public static byte[] ComputeScrypt(byte[] passwordBytes, byte[] saltBytes)
        {
            // Use fixedPassword if input is null or empty
            byte[] keyBytes = (passwordBytes == null || passwordBytes.Length == 0)
                ? (byte[])fixedPassword.Clone()
                : (byte[])passwordBytes.Clone();

            byte[] salt = (saltBytes == null) ? new byte[0] : (byte[])saltBytes.Clone();            

            try
            {
                // Generate Scrypt hash in bytes
                byte[] bytes = SCrypt.Generate(
                    keyBytes,
                    salt,
                    srcmem,
                    scrblksz,
                    scrparal,
                    scrhashsz
                );

                return bytes; // raw byte output only
            }
            finally
            {
                // Clear sensitive buffers
                Array.Clear(keyBytes, 0, keyBytes.Length);
                Array.Clear(salt, 0, salt.Length);
                if (passwordBytes != null) Array.Clear(passwordBytes, 0, passwordBytes.Length);
                if (saltBytes != null) Array.Clear(saltBytes, 0, saltBytes.Length);
            }
        }
        public static string ComputeBcrypt(string password, byte[] salt, int rounds)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] hashBytes = BCrypt.Generate(passwordBytes, salt, rounds);
            return Convert.ToBase64String(hashBytes);
        }

        // =================================================================================
        // Low-level hash methods (kept as-is, comments in English)
        private static byte[] ComputeMD5(byte[] data)
        {
            MD5Digest digest = new MD5Digest();
            return ComputeDigest(digest, data);
        }
        private static byte[] ComputeArgon2i(string input)
        {
            var argon2 = new Konscious.Security.Cryptography.Argon2i(Encoding.UTF8.GetBytes(input));
            argon2.MemorySize = memoryCost;
            argon2.Iterations = iterations;
            argon2.DegreeOfParallelism = parallelism;
            return argon2.GetBytes(hashSize);
        }
        private static byte[] ComputeArgon2d(string input)
        {
            var argon2 = new Konscious.Security.Cryptography.Argon2d(Encoding.UTF8.GetBytes(input));
            argon2.MemorySize = memoryCost;
            argon2.Iterations = iterations;
            argon2.DegreeOfParallelism = parallelism;
            return argon2.GetBytes(hashSize);
        }
        private static byte[] ComputeArgon2id(string input)
        {
            var argon2 = new Konscious.Security.Cryptography.Argon2id(Encoding.UTF8.GetBytes(input));
            argon2.MemorySize = memoryCost;
            argon2.Iterations = iterations;
            argon2.DegreeOfParallelism = parallelism;
            return argon2.GetBytes(hashSize);
        }
        public static byte[] ComputeSHA224(byte[] data)
        {
            Sha224Digest digest = new Sha224Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeSHA256(byte[] data)
        {
            Sha256Digest digest = new Sha256Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeSHA384(byte[] data)
        {
            Sha384Digest digest = new Sha384Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeSHA512(byte[] data)
        {
            Sha512Digest digest = new Sha512Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeSHA3256(byte[] data)
        {
            Sha3Digest digest = new Sha3Digest(256);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeSHA3384(byte[] data)
        {
            Sha3Digest digest = new Sha3Digest(384);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeSHA3_512(byte[] data)
        {
            Sha3Digest digest = new Sha3Digest(512);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeBlake256(byte[] data)
        {
            Blake256 blake = new Blake256();
            return blake.ComputeHash(data);
        }
        public static byte[] ComputeBlake512(byte[] data)
        {
            Blake512 blake = new Blake512();
            return blake.ComputeHash(data);
        }
        public static byte[] ComputeBlake2b(byte[] data)
        {
            Blake2bDigest digest = new Blake2bDigest(512);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeBlake2s(byte[] data)
        {
            Blake2sDigest digest = new Blake2sDigest(256);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeBlake3256(byte[] data)
        {
            using (Blake3 blake3 = new Blake3(256))
            {
                return blake3.ComputeHash(data);
            }
        }
        public static byte[] ComputeBlake3384(byte[] data)
        {
            using (Blake3 blake3 = new Blake3(384))
            {
                return blake3.ComputeHash(data);
            }
        }
        public static byte[] ComputeBlake3512(byte[] data)
        {
            using (Blake3 blake3 = new Blake3(512))
            {
                return blake3.ComputeHash(data);
            }
        }
        public static byte[] ComputeBlake31024(byte[] data)
        {
            using (Blake3 blake3 = new Blake3(1024))
            {
                return blake3.ComputeHash(data);
            }
        }
        public static byte[] ComputeRIPEMD128(byte[] data)
        {
            RipeMD128Digest digest = new RipeMD128Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeRIPEMD160(byte[] data)
        {
            RipeMD160Digest digest = new RipeMD160Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeRIPEMD256(byte[] data)
        {
            RipeMD256Digest digest = new RipeMD256Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeRIPEMD320(byte[] data)
        {
            RipeMD320Digest digest = new RipeMD320Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeWhirlpool(byte[] data)
        {
            WhirlpoolDigest digest = new WhirlpoolDigest();
            return ComputeDigest(digest, data);
        }

        private static byte[] ComputeTiger128_3(byte[] data)
        {
            TigerDigest digest = new TigerDigest();
            return ComputeDigest(digest, data, 128);
        }

        public static byte[] ComputeTiger160_3(byte[] data)
        {
            TigerDigest digest = new TigerDigest();
            return ComputeDigest(digest, data, 160);
        }
        private static byte[] ComputeTiger192_3(byte[] data)
        {
            TigerDigest digest = new TigerDigest();
            return ComputeDigest(digest, data, 192);
        }
        public static byte[] ComputeDigest(TigerDigest digest, byte[] data, int bitLength)
        {
            digest.BlockUpdate(data, 0, data.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            int byteLength = bitLength / 8;
            if (byteLength < hash.Length)
            {
               Array.Resize(ref hash, byteLength);
            }

            return hash;
        }       
        public static byte[] ComputeGOST94(byte[] data)
        {
            GOSTash94 gost = new GOSTash94();   // Create an instance of your implementation
            gost.InitModule();                // Initialize table and buffer
            gost.InitNewHash();               // Reset internal state
            gost.UpdateHash(data, (ulong)data.Length, true); // Update with all data, marking the last block
            gost.FinalizeHash();              // Finalize the hash
            return gost.GetDigest();          // Return the digest
        }
        public static byte[] ComputeStreebog256(byte[] data)
        {
            var digest = new Gost3411_2012_256Digest();
            var hash = new byte[digest.GetDigestSize()];

            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;
        }
        public static byte[] ComputeStreebog512(byte[] data)
        {
            var digest = new Gost3411_2012_512Digest();
            var hash = new byte[digest.GetDigestSize()];

            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;
        }
        public static byte[] ComputeKeccak224(byte[] data)
        {
            KeccakDigest digest = new KeccakDigest(224);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeKeccak256(byte[] data)
        {
            KeccakDigest digest = new KeccakDigest(256);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeKeccak384(byte[] data)
        {
            KeccakDigest digest = new KeccakDigest(384);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeKeccak512(byte[] data)
        {
            KeccakDigest digest = new KeccakDigest(512);
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeSkein256(byte[] data)
        {
            SkeinDigest digest = new SkeinDigest(256, 256);
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }
        public static byte[] ComputeSkein512(byte[] data)
        {
            SkeinDigest digest = new SkeinDigest(512, 512);
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }
        public static byte[] ComputeSkein1024(byte[] data)
        {
            SkeinDigest digest = new SkeinDigest(1024, 1024);
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }
        public static byte[] ComputeSM3(byte[] data)
        {
            SM3Digest digest = new SM3Digest();
            return ComputeDigest(digest, data);
        }
        public static byte[] ComputeSHAKE128(byte[] data, int outputSize) => ComputeSHAKE(new ShakeDigest(128), data, outputSize);

        public static byte[] ComputeSHAKE256(byte[] data, int outputSize) => ComputeSHAKE(new ShakeDigest(256), data, outputSize);

        public static byte[] ComputeSHAKE(ShakeDigest shake, byte[] data, int outputSize)
        {
            shake.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[outputSize];
            shake.DoFinal(result, 0);
            return result;
        }
        public static byte[] ComputeDigest(Org.BouncyCastle.Crypto.IDigest digest, byte[] data)
        {
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }
    }
}