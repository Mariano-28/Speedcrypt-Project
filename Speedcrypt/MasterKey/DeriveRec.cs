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

// Speedcrypt
using Speedcrypt.HASHLibraries;

namespace Speedcrypt.MasterKey
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// DeriverRec: Key derivation class for Speedcrypt supporting multiple algorithms.
    /// </summary>
    ///
    /// <remarks>
    /// This class is NOT performing encryption/decryption itself.
    /// It derives cryptographic keys from a combined password||salt buffer, producing byte arrays
    /// for subsequent use in encryption engines.
    ///
    /// Responsibilities:
    /// - Extract password bytes from combined buffer.
    /// - Derive keys for Argon2, Scrypt, PBKDF2, HMACs, and direct hashes.
    /// - Clear sensitive buffers to avoid memory leakage.
    ///
    /// 📒 Security Note:
    /// The derived key bytes must be used only with approved encryption engines.
    /// Misuse or exposure of Hashrec can compromise security.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>
    public class DeriverRec
    {
        internal byte[] Hashrec { get; private set; }
        public byte[] Salt { get; private set; }

        // Derive the key from a combined byte array (password || salt already included)
        // 'salt' is the real salt bytes
        // 'algorithm' is the chosen algorithm from UI
        public void Derive(byte[] combined, byte[] salt, string algorithm)
        {
            if (combined == null || combined.Length == 0)
                throw new ArgumentException("Combined buffer cannot be null or empty.");
            if (salt == null || salt.Length == 0)
                throw new ArgumentException("Salt cannot be null or empty.");
            if (string.IsNullOrWhiteSpace(algorithm))
                throw new ArgumentException("Algorithm cannot be null or empty.");

            Salt = (byte[])salt.Clone(); // important: set Salt

            byte[] inputBytes = (byte[])combined.Clone();
            string canonicalAlg = MapAlgorithmNameForHASHLib(algorithm);

            switch (canonicalAlg.ToUpperInvariant())
            {
                case "ARGON2I":
                case "ARGON2D":
                case "ARGON2ID":
                    {
                        string hexInput = BytesToHex(inputBytes);
                        string hexOut = HASHLib.ComputeHash(hexInput, canonicalAlg, "", -1, false, false);
                        Hashrec = HexStringToBytes(hexOut);
                        hexInput = null;
                        hexOut = null;
                        break;
                    }

                case "SCRYPT":
                    {
                        // Extract password bytes from combined buffer using the provided salt
                        byte[] passwordBytes = ExtractPasswordFromCombined(inputBytes, Salt);
                        byte[] saltBytes = Salt;

                        Hashrec = HASHLib.ComputeScrypt(passwordBytes, saltBytes);

                        Array.Clear(passwordBytes, 0, passwordBytes.Length);
                        Array.Clear(saltBytes, 0, saltBytes.Length);
                        break;
                    }

                case "PBKDF2-HASH":
                    {
                        Hashrec = PBKDF2_SHA256_Bytes(inputBytes, inputBytes, HASHLib.pbkdf2iterations, 32);
                        break;
                    }

                case "HMAC-SHA1":
                case "HMAC-SHA256":
                case "HMAC-SHA384":
                case "HMAC-SHA512":
                case "HMAC-MD5":
                case "HMAC-RIPEMD160":
                    {
                        switch (canonicalAlg.ToUpperInvariant())
                        {
                            case "HMAC-SHA1": Hashrec = HASHLib.HMACSHA1(inputBytes, inputBytes); break;
                            case "HMAC-SHA256": Hashrec = HASHLib.HMACSHA256(inputBytes, inputBytes); break;
                            case "HMAC-SHA384": Hashrec = HASHLib.HMACSHA384(inputBytes, inputBytes); break;
                            case "HMAC-SHA512": Hashrec = HASHLib.HMACSHA512(inputBytes, inputBytes); break;
                            case "HMAC-MD5": Hashrec = HASHLib.HMACMD5(inputBytes, inputBytes); break;
                            case "HMAC-RIPEMD160": Hashrec = HASHLib.HMACRIPEMD160(inputBytes, inputBytes); break;
                            default: throw new ArgumentException("Unsupported HMAC algorithm: " + algorithm);
                        }
                        break;
                    }

                default:
                    {
                        string hexInput = BytesToHex(inputBytes);
                        string hexOut = HASHLib.ComputeHash(hexInput, canonicalAlg, "", -1, false, false);
                        Hashrec = HexStringToBytes(hexOut);
                        hexInput = null;
                        hexOut = null;
                        break;
                    }
            }

            Array.Clear(inputBytes, 0, inputBytes.Length);
            Array.Clear(combined, 0, combined.Length);
        }

        // -------------------------
        // PBKDF2-SHA256 producing raw bytes
        // -------------------------
        private static byte[] PBKDF2_SHA256_Bytes(byte[] password, byte[] salt, int iterations, int outputBytes)
        {
            var generator = new Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator(
                new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
            generator.Init(password ?? new byte[0], salt ?? new byte[0], iterations);
            var keyParam = (Org.BouncyCastle.Crypto.Parameters.KeyParameter)
                generator.GenerateDerivedMacParameters(outputBytes * 8);
            return keyParam.GetKey();
        }

        // -------------------------
        // Map UI algorithm names to canonical HASHLib names
        // -------------------------
        private static string MapAlgorithmNameForHASHLib(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                return algorithm;

            string a = algorithm.Trim().ToUpperInvariant();
            string compact = a.Replace(" ", "").Replace("-", "").Replace("_", "");

            if (compact.StartsWith("HMAC"))
            {
                string h = compact.Substring(4);

                if (h.StartsWith("SHA1")) return "HMACSHA1";
                if (h.StartsWith("SHA256")) return "HMACSHA256";
                if (h.StartsWith("SHA384")) return "HMACSHA384";
                if (h.StartsWith("SHA512")) return "HMACSHA512";
                if (h.StartsWith("MD5")) return "HMACMD5";
                if (h.StartsWith("RIPEMD160")) return "HMACRIPEMD160";

                return "HMAC" + h;
            }

            if (a.StartsWith("BCRYPT")) return "BCRYPT";
            if (a.StartsWith("ARGON2ID")) return "ARGON2ID";
            if (a == "ARGON2I" || a.StartsWith("ARGON2I ")) return "ARGON2I";
            if (a == "ARGON2D" || a.StartsWith("ARGON2D ")) return "ARGON2D";
            if (a == "SCRYPT") return "SCRYPT";
            if (a == "PBKDF2" || a == "PBKDF2-HASH") return "PBKDF2";

            return algorithm.Trim();
        }

        // -------------------------
        // Utility: bytes to hex
        // -------------------------
        private static string BytesToHex(byte[] data)
        {
            if (data == null || data.Length == 0) return string.Empty;
            var sb = new System.Text.StringBuilder(data.Length * 2);
            foreach (byte b in data) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        // -------------------------
        // Utility: hex to bytes
        // -------------------------
        private static byte[] HexStringToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return new byte[0];
            if (hex.Length % 2 == 1) hex = "0" + hex;
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = System.Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }

        // -------------------------
        // Helper: extract password bytes from combined buffer (password || salt)
        // -------------------------
        private static byte[] ExtractPasswordFromCombined(byte[] combined, byte[] salt)
        {
            if (combined == null) return new byte[0];
            if (salt == null) return (byte[])combined.Clone();

            int saltLen = salt.Length;
            if (combined.Length < saltLen)
                throw new System.ArgumentException("Combined buffer shorter than salt length.");

            int passLen = combined.Length - saltLen;
            byte[] password = new byte[passLen];
            System.Array.Copy(combined, 0, password, 0, passLen);
            return password;
        }
    }
}