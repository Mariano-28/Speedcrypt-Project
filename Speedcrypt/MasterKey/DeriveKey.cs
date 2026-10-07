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

using Org.BouncyCastle.Crypto.Parameters;

// Speedcrypt
using Speedcrypt.HASHLibraries;

namespace Speedcrypt.MasterKey
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// DeriveKey: Key derivation class for Speedcrypt supporting multiple algorithms.
    /// </summary>
    ///
    /// <remarks>
    /// This class is NOT performing encryption/decryption itself.
    /// It derives cryptographic keys from password and salt, producing byte arrays for
    /// subsequent use in encryption engines.
    ///
    /// Responsibilities:
    /// - Extract password bytes from combined filepass||salt buffer.
    /// - Derive keys for Argon2, Scrypt, PBKDF2, HMACs, and direct hashes.
    /// - Clear temporary sensitive buffers to prevent leakage.
    ///
    /// 📒 Security Note:
    /// The derived key bytes must be used only with approved encryption engines.
    /// Misuse or exposure of Hashpass can compromise security.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>
    public class DeriveKey
     {
         public byte[] Hashpass { get; private set; }
         public byte[] Salt { get; private set; }
         public int Rounds { get; set; } = 12;

         // Derive: main entry. 'filepass' is the combined bytes (password || salt) as in your Keymaterial.
         // 'salt' is the salt bytes (raw).
         // 'algorithm' is the algorithm name chosen in the UI.
         public void Derive(byte[] filepass, byte[] salt, string algorithm)
         {
             if (filepass == null || filepass.Length == 0)
                 throw new ArgumentException("Filepass cannot be null or empty.");
             if (salt == null || salt.Length == 0)
                 throw new ArgumentException("Salt cannot be null or empty.");
             if (string.IsNullOrWhiteSpace(algorithm))
                 throw new ArgumentException("Algorithm cannot be null or empty.");

             Salt = (byte[])salt.Clone();

             // For Argon2 only we use a truncated salt (16 bytes). For all others keep full salt.
             byte[] truncatedSalt =
                 (algorithm.StartsWith("ARGON2", StringComparison.OrdinalIgnoreCase) && Salt.Length > 16)
                 ? SubArray(Salt, 0, 16)
                 : (byte[])Salt.Clone();

             // Clone input buffer to avoid modifying caller data
             byte[] inputBytes = (byte[])filepass.Clone();

             // canonical algorithm name for internal decisions (we do not change HASHLib)
             string canonicalAlg = MapAlgorithmNameForHASHLib(algorithm);

             switch (canonicalAlg.ToUpperInvariant())
             {

                 case "ARGON2I":
                 case "ARGON2D":
                 case "ARGON2ID":
                     {
                         // Argon2 path in your HASHLib expects HEX inputs
                         string passHex = BytesToHex(inputBytes);
                         string saltHex = BytesToHex(truncatedSalt);
                         string hexOut = HASHLib.ComputeHash(passHex, canonicalAlg, saltHex, -1, false, false);
                         Hashpass = HexStringToBytes(hexOut);

                         passHex = null;
                         saltHex = null;
                         hexOut = null;
                         break;
                     }

              case "SCRYPT":
                  {
                      // Extract the real password bytes from combined buffer (password || salt)
                      byte[] passwordBytes = ExtractPasswordFromCombined(inputBytes, Salt);

                      // Use the real salt bytes
                      byte[] saltBytes = Salt;

                      // Compute Scrypt hash
                      Hashpass = HASHLib.ComputeScrypt(passwordBytes, saltBytes);

                      // Clear sensitive temporary buffers
                      Array.Clear(passwordBytes, 0, passwordBytes.Length);
                      Array.Clear(saltBytes, 0, saltBytes.Length);

                      break;
                  }

              case "PBKDF2-HASH":
                     {
                         // PBKDF2 must use the raw bytes as password and raw bytes as salt.
                         // The KeyMaterial builds 'filepass' as password||salt so extract password bytes.
                         byte[] passwordBytes = ExtractPasswordFromCombined(inputBytes, Salt);
                         byte[] saltBytes = Salt; 

                         // Use PBKDF2 with SHA-256 exactly like HASHLib.GeneratePBKDF2Hash but with byte[] input
                         Hashpass = PBKDF2_SHA256_Bytes(passwordBytes, saltBytes, HASHLib.pbkdf2iterations, 32);

                         // clear temporaries
                         Array.Clear(passwordBytes, 0, passwordBytes.Length);
                         break;
                     }

                 // HMAC algorithms: MUST be calculated on raw bytes: key = password bytes, data = salt bytes
                   case "HMAC-SHA1":
                   case "HMAC-SHA256":
                   case "HMAC-SHA384":
                   case "HMAC-SHA512":
                   case "HMAC-MD5":
                   case "HMAC-RIPEMD160":
                       {
                         // Extract password bytes from combined buffer (password || salt)
                         byte[] passwordBytes = ExtractPasswordFromCombined(inputBytes, Salt);
                         byte[] saltBytes = Salt; // use the full salt (not truncated) for HMACs

                           // Route to low-level HASHLib HMAC functions that accept byte[] and return byte[]
                           switch (canonicalAlg.ToUpperInvariant())
                           {
                               case "HMAC-SHA1":
                                   Hashpass = HASHLib.HMACSHA1(passwordBytes, saltBytes);

                                  break;
                               case "HMAC-SHA256":
                                   Hashpass = HASHLib.HMACSHA256(passwordBytes, saltBytes);
                                   break;
                               case "HMAC-SHA384":
                                   Hashpass = HASHLib.HMACSHA384(passwordBytes, saltBytes);
                                   break;
                               case "HMAC-SHA512":
                                   Hashpass = HASHLib.HMACSHA512(passwordBytes, saltBytes);
                                   break;
                               case "HMAC-MD5":
                                   Hashpass = HASHLib.HMACMD5(passwordBytes, saltBytes);
                                   break;
                               case "HMAC-RIPEMD160":
                                   Hashpass = HASHLib.HMACRIPEMD160(passwordBytes, saltBytes);
                                   break;
                               default:
                                   // Should not happen due to MapAlgorithmNameForHASHLib
                                   throw new System.ArgumentException("Unsupported HMAC algorithm: " + algorithm);

                           }

                           // clear temporaries
                           Array.Clear(passwordBytes, 0, passwordBytes.Length);
                           break;
                       }

                 default:
                         {
                             // Default for direct hash algorithms: HASHLib historically expects HEX input
                             // and returns HEX string. Keep previous behavior for compatibility.
                             string hexInput = BytesToHex(inputBytes);
                             string hexOut = HASHLib.ComputeHash(hexInput, canonicalAlg, "", -1, false, false);
                             Hashpass = HexStringToBytes(hexOut);

                             hexInput = null;
                             hexOut = null;
                             break;
                         }
             }

             // Clear sensitive buffers
             Array.Clear(inputBytes, 0, inputBytes.Length);
             Array.Clear(filepass, 0, filepass.Length);
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
                 throw new ArgumentException("Combined buffer shorter than salt length.");

             int passLen = combined.Length - saltLen;
             byte[] password = new byte[passLen];
             System.Array.Copy(combined, 0, password, 0, passLen);
             return password;
         }

         // -------------------------
         // PBKDF2-SHA256 producing raw bytes (mirrors HASHLib.GeneratePBKDF2Hash but using byte[] inputs)
         // -------------------------
         private static byte[] PBKDF2_SHA256_Bytes(byte[] password, byte[] salt, int iterations, int outputBytes)
         {
             // Use BouncyCastle Pkcs5S2ParametersGenerator with Sha256Digest (same as HASHLib)
             var generator = new Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
             generator.Init(password ?? new byte[0], salt ?? new byte[0], iterations);
             KeyParameter keyParam = (KeyParameter)generator.GenerateDerivedMacParameters(outputBytes * 8);
             byte[] keyBytes = keyParam.GetKey();
             return keyBytes;
         }

        // -------------------------
        // Map various UI algorithm names into canonical HASHLib names
        // -------------------------
        private static string MapAlgorithmNameForHASHLib(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                return algorithm;

            // Normalize: uppercase, remove spaces, hyphens, underscores
            string a = algorithm.Trim().ToUpperInvariant();
            string compact = a.Replace(" ", "").Replace("-", "").Replace("_", "");

            // --- HMAC NORMALIZATION (safe, isolated, non-invasive) ---
            if (compact.StartsWith("HMAC"))
            {
                // Extract the part after HMAC
                string h = compact.Substring(4);

                if (h.StartsWith("SHA1")) return "HMACSHA1";
                if (h.StartsWith("SHA256")) return "HMACSHA256";
                if (h.StartsWith("SHA384")) return "HMACSHA384";
                if (h.StartsWith("SHA512")) return "HMACSHA512";
                if (h.StartsWith("MD5")) return "HMACMD5";
                if (h.StartsWith("RIPEMD160")) return "HMACRIPEMD160";

                // Unknown HMAC → return canonical HMAC prefix anyway
                return "HMAC" + h;
            }

            // --- NON-HMAC ALGORITHMS (untouched) ---
            if (a.StartsWith("BCRYPT")) return "BCRYPT";
            if (a.StartsWith("ARGON2ID")) return "ARGON2ID";
            if (a == "ARGON2I" || a.StartsWith("ARGON2I ")) return "ARGON2I";
            if (a == "ARGON2D" || a.StartsWith("ARGON2D ")) return "ARGON2D";
            if (a == "SCRYPT")  return "SCRYPT";
            if (a == "PBKDF2" || a == "PBKDF2-HASH") return "PBKDF2";

            // Fallback to original trimmed name (HASHLib will validate)
            return algorithm.Trim();
        }

        // -------------------------
        // Utilities
        // -------------------------
        private byte[] NormalizeTo16Bytes(byte[] data)
         {
             byte[] tmp = new byte[16];
             if (data.Length >= 16)
                 Array.Copy(data, 0, tmp, 0, 16);
             else
                 Array.Copy(data, 0, tmp, 0, data.Length);
             return tmp;
         }
         private byte[] SubArray(byte[] data, int index, int length)
         {
             byte[] result = new byte[length];
             Array.Copy(data, index, result, 0, length);
             return result;
         }
         private static string BytesToHex(byte[] data)
         {
             if (data == null || data.Length == 0) return string.Empty;
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
     }
}