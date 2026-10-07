/// Speedcrypt software - The Open-Source for encrypt and decrypt files
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

using Org.BouncyCastle.Bcpg.OpenPgp;

// Speedcrypt
using Speedcrypt.UI;

namespace Speedcrypt.Crypto.PGP
{
    /// <summary>
    /// Created by Mariano Ortu
    /// PgpDecryptor: Provides functionality to decrypt OpenPGP-encrypted files
    /// using a recipient's private key and passphrase.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements OpenPGP decryption within the Speedcrypt framework:
    /// - Decrypts files encrypted with a corresponding OpenPGP public key
    /// - Supports AES encryption, ZLib compression, and integrity-protected messages
    /// - Resolves the correct private key from a secret key ring using the key ID
    /// - Handles compressed and literal data packets transparently
    /// - Streams decrypted output to disk using a 128 KB buffer for large files
    /// - Verifies integrity protection packets when present
    /// - Clears sensitive buffers and passphrases after use
    /// - Delegates decryption failures to Passwerr.HandleDecryptionFailure()
    ///
    /// Security notes:
    /// - Uses hybrid OpenPGP security model (public-key + symmetric encryption)
    /// - Integrity-protected packets are verified when available
    /// - Sensitive password material is zeroed after decryption
    /// - Stream-based processing supports very large files without high memory usage
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public class PgpDecryptor
    {
        private const int BufferSize = 131072; // 128 KB buffer for streaming

        // Decrypt a PGP-encrypted file using private key and password, works for very large files (100GB+)
        public static void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyPath, char[] password)
        {
            if (!File.Exists(inputFilePath)) throw new FileNotFoundException("Input file not found.", inputFilePath);
            if (!File.Exists(privateKeyPath)) throw new FileNotFoundException("Private key file not found.", privateKeyPath);

            try
            {
                using (FileStream fileStream = File.OpenRead(inputFilePath))
                {
                    using (Stream inputStream = PgpUtilities.GetDecoderStream(fileStream))
                    {
                        using (Stream keyIn = File.OpenRead(privateKeyPath))
                        {
                            PgpObjectFactory objFactory = new PgpObjectFactory(inputStream);
                            PgpEncryptedDataList encDataList = GetEncryptedDataList(objFactory);

                            PgpPrivateKey privateKey = null;
                            PgpPublicKeyEncryptedData encryptedData = null;

                            foreach (PgpPublicKeyEncryptedData pked in encDataList.GetEncryptedDataObjects())
                            {
                                privateKey = FindPrivateKey(keyIn, pked.KeyId, password);
                                if (privateKey != null)
                                {
                                    encryptedData = pked;
                                    break;
                                }
                            }

                            if (privateKey == null)
                                throw new ArgumentException("Private key not found.");

                            using (Stream clearStream = encryptedData.GetDataStream(privateKey))
                            {
                                PgpObjectFactory plainFactory = new PgpObjectFactory(clearStream);
                                PgpObject message = plainFactory.NextPgpObject();

                                PgpCompressedData compressedData = message as PgpCompressedData;
                                if (compressedData != null)
                                {
                                    Stream compDataStream = compressedData.GetDataStream();
                                    plainFactory = new PgpObjectFactory(compDataStream);
                                    message = plainFactory.NextPgpObject();
                                }

                                PgpLiteralData literalData = message as PgpLiteralData;
                                if (literalData != null)
                                {
                                    using (Stream uncStream = literalData.GetInputStream())
                                    {
                                        using (FileStream outputFile = File.Create(outputFilePath))
                                        {
                                            byte[] buffer = new byte[BufferSize];
                                            int read;
                                            while ((read = uncStream.Read(buffer, 0, buffer.Length)) > 0)
                                            {
                                                outputFile.Write(buffer, 0, read);
                                                ClearBytes(buffer, 0, read);
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    throw new ArgumentException("Invalid PGP message. Literal data packet expected.");
                                }

                                //FOR 2GB+ FILE INTEGRITY:
                                // We must completely exhaust the remaining bytes in the cleartext stream 
                                // to force the underlying Bouncy Castle SHA-1 / MDC engine to flush its final blocks.
                                // Without this manual drainage, large file verification returns a false negative (HMAC Failed).
                                byte[] drainBuffer = new byte[BufferSize];
                                while (clearStream.Read(drainBuffer, 0, drainBuffer.Length) > 0)
                                {
                                    // Intentionally draining the stream to compute the trailing validation padding
                                }

                                // Verify integrity protection packet if present
                                if (encryptedData.IsIntegrityProtected())
                                {
                                    if (!encryptedData.Verify())
                                    {
                                        throw new PgpException("PGP message integrity check failed. Data corruption detected.");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                ForAllUnits.DecSett = 1;
                Passwerr.HandleDecryptionFailure();
            }
            finally
            {
                // Always clear the password from memory securely
                if (password != null)
                {
                    for (int i = 0; i < password.Length; i++)
                    {
                        password[i] = '\0';
                    }
                }
            }
        }
        private static PgpEncryptedDataList GetEncryptedDataList(PgpObjectFactory objFactory)
        {
            PgpObject obj = objFactory.NextPgpObject();
            PgpEncryptedDataList encList = obj as PgpEncryptedDataList;
            if (encList != null)
            {
                return encList;
            }
            return (PgpEncryptedDataList)objFactory.NextPgpObject();
        }
        private static PgpPrivateKey FindPrivateKey(Stream privateKeyStream, long keyId, char[] password)
        {
            using (Stream decoderStream = PgpUtilities.GetDecoderStream(privateKeyStream))
            {
                PgpSecretKeyRingBundle keyRingBundle = new PgpSecretKeyRingBundle(decoderStream);
                foreach (PgpSecretKeyRing keyRing in keyRingBundle.GetKeyRings())
                {
                    foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                    {
                        if (key.KeyId == keyId)
                        {
                            return key.ExtractPrivateKey(password);
                        }
                    }
                }
            }
            return null;
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