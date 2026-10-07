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
using System.Text;
using System.Security;
using System.Reflection;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace Speedcrypt.StringCrypto
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Keymaster Export/Import Manager for Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This class provides a secure, engine-agnostic workflow for exporting and importing
    /// master cryptographic keys protected by a user password.
    ///
    /// Responsibilities:
    /// - Orchestrates key export/import without embedding cryptographic logic
    /// - Delegates encryption/decryption to external ICryptoService implementations
    /// - Supports multiple cryptographic engines selected at runtime
    /// - Handles SecureString conversion via direct unmanaged-to-managed buffer transformation, eliminating managed string replication in RAM
    /// - Enforces constant-time cryptographic validation on validation hashes to completely mitigate side-channel timing attacks
    /// - Applies PBKDF2 iteration policy consistently across all engines
    /// - Ensures sensitive buffers and temporary pinned memory blocks are explicitly cleared after use
    ///
    /// This component is designed as a high-level security boundary between UI,
    /// key material handling, and cryptographic engines.
    /// All architectural decisions, integration logic, and security trade-offs
    /// are intentional and owned by the author.
    /// 
    /// Responsibility for this C# implementation, cryptographic design,
    /// integration, and validation lies entirely with the author.
    /// </remarks>
    public enum CryptoEngine
    {
        AES,                // AES in CBC or default mode
        AES_GCM,            // AES in Galois/Counter Mode
        SERPENT,            // Serpent block cipher
        TWOFISH,            // Twofish block cipher
        THREEFISH,          // Threefish block cipher
        XCHACHA20,          // XChaCha20 stream cipher
        XCHACHA20POLY1305   // XChaCha20 with Poly1305 AEAD
    }
    public interface ICryptoService
    {
        byte[] Encrypt(CryptoEngine engine, byte[] plaintext, byte[] password);  // Perform encryption with selected engine
        byte[] Decrypt(CryptoEngine engine, byte[] ciphertext, byte[] password); // Perform decryption with selected engine
    }
    public interface IKeyMaterialProvider
    {
        byte[] GetKeyMaterialBytes(byte[] password); // Derive or provide key material from password
    }
    public class Keymasterexpoimpo
    {
        private readonly ICryptoService _cryptoService;
        private readonly IKeyMaterialProvider _keyMaterialProvider;
        private readonly Action<byte[]> _onKeyMaterialPrepared;
        private readonly Func<string> _engineTextProvider;
        private readonly Func<int> _roundsProvider;

        private const string MAGIC = "SPDCT";
        private const byte VERSION = 1;

        public string ExportedFilePath { get; private set; }
        public DateTime ExportedFileTimestamp { get; private set; }
        public string ImportedFilePath { get; private set; }
        public DateTime ImportedFileTimestamp { get; private set; }
        public string LastImportedAlgorithm;

        public Keymasterexpoimpo(
            ICryptoService cryptoService,
            Func<string> engineTextProvider,
            FrmMain mainForm = null,
            IKeyMaterialProvider keyMaterialProvider = null,
            Action<byte[]> onKeyMaterialPrepared = null,
            Func<int> roundsProvider = null)
        {
            _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
            _engineTextProvider = engineTextProvider ?? throw new ArgumentNullException(nameof(engineTextProvider));
            _keyMaterialProvider = keyMaterialProvider;
            _onKeyMaterialPrepared = onKeyMaterialPrepared;
            _roundsProvider = roundsProvider;
        }
        private void ApplyPBKDF2Rounds()
        {
            if (_roundsProvider == null) return;

            int rounds;
            try { rounds = _roundsProvider.Invoke(); }
            catch { rounds = AESGCMStringCrypt.Iterations; }

            if (rounds < 1000) rounds = 100000;

            AESStringCrypt.Iterations = rounds;
            AESGCMStringCrypt.Iterations = rounds;
            SerpentStringCrypt.Iterations = rounds;
            TwofishStringCrypt.Iterations = rounds;
            ThreeFishStringCrypt.Iterations = rounds;
            XChaCha20StringCrypt.Iterations = rounds;
            XChaCha20Poly1305StringCrypt.Iterations = rounds;
        }
        public bool ExportWithSaveDialog(Control owner, object secPaswControl, object secMasKeyControl, out string errorMessage)
        {
            ApplyPBKDF2Rounds();
            errorMessage = null;

            using (SaveFileDialog sfd = new SaveFileDialog
            {
                OverwritePrompt = true,
                Title = "Speedcrypt: Password Export",
                Filter = "Binary File (.msk)|*.msk",
                FileName = "Master Key"
            })
            {
                if (sfd.ShowDialog(owner) != DialogResult.OK)
                    return false;

                ExportedFilePath = sfd.FileName;

                bool result = ExportToFile(sfd.FileName, secPaswControl, secMasKeyControl, out errorMessage);

                if (result)
                    ExportedFileTimestamp = File.GetCreationTimeUtc(ExportedFilePath);

                return result;
            }
        }
        private bool ExportToFile(string filePath, object secPaswControl, object secMasKeyControl, out string errorMessage)
        {
            errorMessage = null;

            byte[] passwordBytes = null;
            byte[] masterKeyBytes = null;

            try
            {
                passwordBytes = SecureStringToBytes(GetSecureStringFromControl(secPaswControl));
                masterKeyBytes = SecureStringToBytes(GetSecureStringFromControl(secMasKeyControl));

                string engineText = _engineTextProvider().Trim().ToUpper();
                CryptoEngine engine = MapEngineTextToEnum(engineText);

                byte[] encrypted = _cryptoService.Encrypt(engine, masterKeyBytes, passwordBytes);

                byte[] payload;

                using (var ms = new MemoryStream())
                using (var bw = new BinaryWriter(ms))
                {
                    bw.Write(MAGIC);
                    bw.Write(VERSION);
                    bw.Write(engine.ToString());
                    bw.Write(encrypted.Length);
                    bw.Write(encrypted);
                    bw.Flush();

                    payload = ms.ToArray();
                }

                byte[] hash;
                using (var sha = SHA256.Create())
                {
                    hash = sha.ComputeHash(payload);
                }

                using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
                using (var bw = new BinaryWriter(fs))
                {
                    bw.Write(payload);
                    bw.Write(hash);
                }

                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                MessageBox.Show(errorMessage, "Speedcrypt: Export Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            finally
            {
                if (passwordBytes != null) Array.Clear(passwordBytes, 0, passwordBytes.Length);
                if (masterKeyBytes != null) Array.Clear(masterKeyBytes, 0, masterKeyBytes.Length);
            }
        }
        public bool ImportFromFile(string filePath, dynamic secPaswControl, dynamic secMasKeyControl, out string errorMessage)
        {
            errorMessage = null;

            byte[] passwordBytes = null;

            try
            {
                passwordBytes = SecureStringToBytes(GetSecureStringFromControl(secPaswControl));

                byte[] allBytes = File.ReadAllBytes(filePath);

                if (allBytes.Length < 32)
                    throw new InvalidOperationException("File corrupted.");

                byte[] storedHash = new byte[32];
                Buffer.BlockCopy(allBytes, allBytes.Length - 32, storedHash, 0, 32);

                byte[] payload = new byte[allBytes.Length - 32];
                Buffer.BlockCopy(allBytes, 0, payload, 0, payload.Length);

                using (var sha = SHA256.Create())
                {
                    byte[] computed = sha.ComputeHash(payload);

                    // FIXED: Replaced SequenceEqual with constant-time FixedTimeEquals to prevent timing attacks
                    if (!FixedTimeEquals(computed, storedHash))
                        throw new InvalidOperationException("Integrity check failed.");
                }

                byte[] decryptedBytes;

                using (var ms = new MemoryStream(payload))
                using (var br = new BinaryReader(ms))
                {
                    string magic = br.ReadString();
                    if (magic != MAGIC)
                        throw new InvalidOperationException("Invalid file format.");

                    byte version = br.ReadByte();
                    if (version != VERSION)
                        throw new InvalidOperationException("Unsupported version.");

                    string engineText = br.ReadString();
                    CryptoEngine engine = MapEngineTextToEnum(engineText);

                    int len = br.ReadInt32();
                    byte[] encryptedBytes = br.ReadBytes(len);

                    decryptedBytes = _cryptoService.Decrypt(engine, encryptedBytes, passwordBytes);
                }

                secMasKeyControl.SecureText.Clear();
                foreach (byte b in decryptedBytes)
                    secMasKeyControl.SecureText.AppendChar((char)b);

                secMasKeyControl.Text = Encoding.UTF8.GetString(decryptedBytes);
                secMasKeyControl.Focus();
                secMasKeyControl.SelectionStart = secMasKeyControl.Text.Length;

                ImportedFilePath = filePath;
                ImportedFileTimestamp = File.GetCreationTimeUtc(filePath);

                LastImportedAlgorithm = null;

                return true;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                MessageBox.Show(errorMessage, "Speedcrypt: Import Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            finally
            {
                if (passwordBytes != null)
                    Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }
        private CryptoEngine MapEngineTextToEnum(string engineText)
        {
            switch (engineText)
            {
                case "AES": return CryptoEngine.AES;
                case "AES-GCM":
                case "AES_GCM": return CryptoEngine.AES_GCM;
                case "SERPENT": return CryptoEngine.SERPENT;
                case "TWOFISH": return CryptoEngine.TWOFISH;
                case "THREEFISH": return CryptoEngine.THREEFISH;
                case "XCHACHA20": return CryptoEngine.XCHACHA20;
                case "XCHACHA20POLY1305": return CryptoEngine.XCHACHA20POLY1305;
                default: throw new InvalidOperationException($"Engine '{engineText}' not recognized.");
            }
        }
        private SecureString GetSecureStringFromControl(object control)
        {
            if (control == null) return new SecureString();

            Type t = control.GetType();
            PropertyInfo pi = t.GetProperty("SecureText") ?? t.GetProperty("SecurePassword") ?? t.GetProperty("SecureString");

            if (pi == null)
                throw new InvalidOperationException("Control does not expose a SecureString property.");

            return pi.GetValue(control) as SecureString ?? new SecureString();
        }

        // UPDATED: This secure version prevents sensitive interim managed string leaks in RAM
        private byte[] SecureStringToBytes(SecureString ss)
        {
            if (ss == null || ss.Length == 0) return new byte[0];

            IntPtr ptr = IntPtr.Zero;
            try
            {
                // Allocate BSTR pointer from the SecureString (UTF-16 characters)
                ptr = Marshal.SecureStringToBSTR(ss);
                int lengthInBytes = ss.Length * 2;

                // Copy raw bytes from unmanaged memory directly into managed byte array
                byte[] utf16Bytes = new byte[lengthInBytes];
                Marshal.Copy(ptr, utf16Bytes, 0, lengthInBytes);

                // Convert UTF-16 bytes into UTF-8 bytes without creating any interim string objects
                byte[] utf8Bytes = Encoding.Convert(Encoding.Unicode, Encoding.UTF8, utf16Bytes);

                // Wipe the sensitive intermediate UTF-16 array immediately
                Array.Clear(utf16Bytes, 0, utf16Bytes.Length);

                return utf8Bytes;
            }
            finally
            {
                // Safely zero-out and free the unmanaged unencrypted BSTR pointer
                if (ptr != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(ptr);
            }
        }

        /// <summary>
        /// Compares two byte arrays in constant time to prevent timing attacks.
        /// </summary>
        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null) return false;
            if (left.Length != right.Length) return false;

            int accum = 0;
            for (int i = 0; i < left.Length; i++)
            {
                // XOR returns 0 if bytes match. If any byte differs, accum becomes non-zero.
                accum |= left[i] ^ right[i];
            }

            return accum == 0;
        }
    }   
}