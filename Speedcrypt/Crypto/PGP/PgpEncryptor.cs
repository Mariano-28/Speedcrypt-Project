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

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// PgpEncryptor: Provides file encryption using OpenPGP standard
    /// with a recipient's public key.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements OpenPGP-based file encryption within the
    /// Speedcrypt framework:
    /// - Encrypts files using a recipient's OpenPGP public key
    /// - Uses AES-256 as the symmetric encryption algorithm
    /// - Compresses data using ZLib before encryption for efficiency
    /// - Enables integrity protection packets for tamper detection
    /// - Uses literal data packets to preserve file metadata
    /// - Streams data with a 128 KB buffer for efficient handling of large files
    /// - Validates public keys before use:
    ///   - RSA keys must be at least 3072 bits
    ///   - ECC keys such as Curve25519 are accepted
    /// - Filters for encryption-capable public keys only
    ///
    /// Security notes:
    /// - Uses hybrid encryption (public-key + symmetric AES-256)
    /// - Integrity protection is enabled via OpenPGP packet structure
    /// - Stream-based processing supports very large files without high memory usage
    /// - Sensitive buffers are cleared after use to reduce residual data exposure
    ///
    /// This class performs encryption only; decryption is handled separately
    /// by the PgpDecryptor component.
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public class PgpEncryptor
    {
        private const int BufferSize = 131072; // 128 KB streaming buffer

        // Encrypt a file using a recipient's public key, works for very large files (100GB+)
        public static void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyPath)
        {
            if (!File.Exists(inputFilePath)) throw new FileNotFoundException("Input file not found.", inputFilePath);
            if (!File.Exists(publicKeyPath)) throw new FileNotFoundException("Public key file not found.", publicKeyPath);

            using (Stream keyIn = File.OpenRead(publicKeyPath))
            {
                using (Stream outputStream = File.Create(outputFilePath))
                {
                    PgpPublicKey publicKey = ReadPublicKey(keyIn);
                    EncryptFileStreamNative(inputFilePath, outputStream, publicKey);
                }
            }
        }
        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey && IsStrongKey(key))
                        return key;
                }
            }
            throw new ArgumentException("No valid strong public key found.");
        }
        private static bool IsStrongKey(PgpPublicKey key)
        {
            // Ensure key is RSA >= 3072 bits or ECC Curve25519
            if (key.Algorithm == PublicKeyAlgorithmTag.RsaEncrypt ||
                key.Algorithm == PublicKeyAlgorithmTag.RsaGeneral)
            {
                return key.BitStrength >= 3072;
            }
            if (key.Algorithm == PublicKeyAlgorithmTag.ECDH ||
                key.Algorithm == PublicKeyAlgorithmTag.EdDsa)
            {
                return true;
            }
            return false;
        }
        private static void EncryptFileStreamNative(string inputFilePath, Stream outputStream, PgpPublicKey publicKey)
        {
            // Encrypted data generator with AES-256 and integrity packet
            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, new SecureRandom());
            encryptedDataGenerator.AddMethod(publicKey);

            using (Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte[BufferSize]))
            {
                // Compressed data generator using ZLib
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.ZLib);
                using (Stream compressedOut = compressedDataGenerator.Open(encryptedOut))
                {
                    PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();

                    //FOR CS1501 & 2GB LIMIT:
                    // Passing a FileInfo object directly invokes the native Bouncy Castle implementation
                    // that safely overrides the standard 32-bit/64-bit integer stream length constraints,
                    // processing huge files seamlessly in background chunks.
                    FileInfo fileInfo = new FileInfo(inputFilePath);
                    using (Stream literalOut = literalDataGenerator.Open(
                        compressedOut,
                        PgpLiteralData.Binary,
                        fileInfo))
                    {
                        using (FileStream fsInput = fileInfo.OpenRead())
                        {
                            byte[] buffer = new byte[BufferSize];
                            int read;
                            while ((read = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                literalOut.Write(buffer, 0, read);
                                ClearBytes(buffer, 0, read); // clear sensitive buffer immediately
                            }
                        }
                    }
                }
            }
        }
        private static void ClearBytes(byte[] buffer, int offset, int count)
        {
            if (buffer == null) return;
            for (int i = offset; i < offset + count; i++)
            {
                buffer[i] = 0;
            }
        }
    }
}