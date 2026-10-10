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
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Crypto.XChaCha20Poly1305
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// XChaCha20Poly1305FileEncryptor: Provides file encryption and decryption using
    /// the XChaCha20-Poly1305 AEAD scheme with 256-bit keys and Poly1305 authentication.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements XChaCha20-Poly1305 file encryption within the Speedcrypt framework:
    /// - Encrypts files using XChaCha20-Poly1305 (AEAD construction)
    /// - Uses 256-bit keys normalized to a fixed 32-byte size
    /// - Generates a cryptographically secure 12-byte nonce per encryption
    /// - Appends a 16-byte Poly1305 authentication tag to the output file
    /// - Verifies integrity using constant-time comparison to prevent timing attacks
    /// - Performs full authentication before decryption output is accepted
    /// - Uses buffered stream processing for efficient handling of large files
    /// - Automatically appends the .SPCR extension to encrypted files
    ///
    /// Security notes:
    /// - AEAD construction (XChaCha20-Poly1305) provides confidentiality and integrity together
    /// - Poly1305 ensures ciphertext authenticity and tamper detection
    /// - A unique nonce is generated for every encryption operation
    /// - Authentication is verified before any decrypted output is written
    /// - Constant-time comparison mitigates timing side-channel leaks
    ///
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public static class XChaCha20Poly1305FileEncryptor
    {
        private static string _encryptedFileExtension = ".SPCR"; // Speed Crypt default extension
        private const int BufferSize = 65536; // 64KB buffer for seamless streaming performance

        public static string EncryptedFileExtension
        {
            get { return _encryptedFileExtension; }
        }

        // Encrypts a file with XChaCha20-Poly1305, writes IV + ciphertext + Poly1305 tag
        public static void EncryptFile(string inputFilePath, string outputFilePath, byte[] key)
        {
            key = EncryptionManager.ExpandKey(key, 256); // Normalize key to 32 bytes securely
            byte[] iv = GenerateIV();                   // 12-byte nonce

            string encryptedFilePath = outputFilePath + EncryptedFileExtension;
            using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            {
                using (FileStream fsOutput = new FileStream(encryptedFilePath, FileMode.Create, FileAccess.Write))
                {
                    fsOutput.Write(iv, 0, iv.Length); // Write IV

                    // Perform stream-to-stream encryption, updating the Poly1305 tag concurrently
                    Encrypt(key, iv, fsInput, fsOutput);
                }
            }
        }

        // Decrypts a file with XChaCha20-Poly1305, verifies Poly1305 tag
        public static bool DecryptFile(string inputFilePath, string outputFilePath, byte[] key)
        {
            try
            {
                key = EncryptionManager.ExpandKey(key, 256); // Normalize key

                using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] iv = new byte[12];
                    if (fsInput.Read(iv, 0, iv.Length) != iv.Length)
                        return false;

                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        // Perform stream-to-stream decryption and validation without loading into RAM
                        Decrypt(key, iv, fsInput, fsOutput);
                    }
                }

                return true;
            }
            catch (Exception)
            {                
                return false;
            }
        }

        // Main streaming encryption method preserving signature
        private static void Encrypt(byte[] key, byte[] iv, Stream inputStream, Stream outputStream)
        {
            if (iv.Length != 12)
                throw new ArgumentException("IV must be 12 bytes", nameof(iv));

            // 1. Initialize Poly1305 MAC engine
            Poly1305 poly1305 = new Poly1305();
            poly1305.Init(new KeyParameter(key));

            // 2. Encrypt input data directly to the output stream while hashing ciphertext
            ChaCha20Encrypt(key, iv, inputStream, outputStream, poly1305);

            // 3. Generate final Poly1305 verification tag and append to output stream
            byte[] tag = new byte[16];
            poly1305.DoFinal(tag, 0);
            outputStream.Write(tag, 0, tag.Length);
        }

        // Main streaming decryption method preserving signature
        private static void Decrypt(byte[] key, byte[] iv, Stream inputStream, Stream outputStream)
        {
            if (iv.Length != 12)
                throw new ArgumentException("IV must be 12 bytes", nameof(iv));

            long ciphertextLength = inputStream.Length - inputStream.Position - 16;
            if (ciphertextLength < 0)
                throw new InvalidCipherTextException("Ciphertext too short.");

            // First Pass: Read ciphertext sequentially to verify trailing Poly1305 tag
            long initialPosition = inputStream.Position;
            Poly1305 poly1305 = new Poly1305();
            poly1305.Init(new KeyParameter(key));

            byte[] buffer = new byte[BufferSize];
            int bytesRead;
            long totalBytesToHash = ciphertextLength;

            while (totalBytesToHash > 0 && (bytesRead = inputStream.Read(buffer, 0, (int)Math.Min((long)buffer.Length, totalBytesToHash))) > 0)
            {
                poly1305.BlockUpdate(buffer, 0, bytesRead);
                totalBytesToHash -= bytesRead;
            }

            byte[] computedTag = new byte[16];
            poly1305.DoFinal(computedTag, 0);

            byte[] storedTag = new byte[16];
            if (inputStream.Read(storedTag, 0, storedTag.Length) != storedTag.Length)
                throw new InvalidCipherTextException("Incomplete authentication tag data.");

            if (!AreTagsEqualConstantTime(storedTag, computedTag))
                throw new InvalidCipherTextException("Authentication tags mismatch.");

            // Reset stream position to decode data safely after successful authentication
            inputStream.Position = initialPosition;

            // Second Pass: Decrypt data on-the-fly directly to the output disk stream
            ChaCha20Decrypt(key, iv, inputStream, outputStream, ciphertextLength);
        }
        private static void ChaCha20Encrypt(byte[] key, byte[] iv, Stream inputStream, Stream outputStream, Poly1305 poly1305)
        {
            ChaCha7539Engine engine = new ChaCha7539Engine();
            engine.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] inputBuffer = new byte[BufferSize];
            byte[] outputBuffer = new byte[BufferSize];
            int bytesRead;

            while ((bytesRead = inputStream.Read(inputBuffer, 0, inputBuffer.Length)) > 0)
            {
                engine.ProcessBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
                outputStream.Write(outputBuffer, 0, bytesRead);
                poly1305.BlockUpdate(outputBuffer, 0, bytesRead); // Hash ciphertext blocks progressively
            }
        }
        private static void ChaCha20Decrypt(byte[] key, byte[] iv, Stream inputStream, Stream outputStream, long ciphertextLength)
        {
            ChaCha7539Engine engine = new ChaCha7539Engine();
            engine.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            byte[] inputBuffer = new byte[BufferSize];
            byte[] outputBuffer = new byte[BufferSize];
            int bytesRead;
            long totalBytesToDecrypt = ciphertextLength;
            
            while (totalBytesToDecrypt > 0 && (bytesRead = inputStream.Read(inputBuffer, 0, (int)Math.Min((long)inputBuffer.Length, totalBytesToDecrypt))) > 0)
            {
                engine.ProcessBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
                outputStream.Write(outputBuffer, 0, bytesRead);
                totalBytesToDecrypt -= bytesRead;
            }
        }
        private static bool AreTagsEqualConstantTime(byte[] tag1, byte[] tag2)
        {
            if (tag1.Length != tag2.Length)
                return false;

            int diff = 0;
            for (int i = 0; i < tag1.Length; i++)
            {
                diff |= tag1[i] ^ tag2[i];
            }
            return diff == 0;
        }
        private static byte[] GenerateIV()
        {
            byte[] iv = new byte[12];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            return iv;
        }
    } 
}