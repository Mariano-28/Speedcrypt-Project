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

namespace Speedcrypt.Crypto
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// EncryptionIdentifier: Provides utilities for managing file headers with encryption algorithm identifiers.
    /// </summary>
    /// 
    /// <remarks>
    /// This static class is responsible for handling the file headers, which include the encryption algorithm used.
    /// Features:
    /// - Writing and reading headers with the algorithm identifier for files
    /// - Supports various algorithms (AES, PGP, IDEA, etc.)
    /// - Handles header formatting with a fixed prefix and suffix for consistency
    /// - Reads and verifies algorithm names from the header, throwing an exception if invalid
    /// 
    /// Technical note:
    /// - Algorithms are represented in the `HeaderAlgo` enum, with names formatted as `ALGO=AlgorithmName`.
    /// - The header is written to the file as the first line, ensuring easy identification of the encryption method.
    /// - Uses UTF-8 encoding for header storage and parsing.
    /// - Handles cases where the algorithm name uses underscores (e.g., AES_GCM becomes AES-GCM in the file).
    /// 
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public enum HeaderAlgo
    {
        AES,
        PGP,
        IDEA,
        GOST,
        AES_GCM,
        SERPENT,
        TWOFISH,
        CAMELLIA,
        THREEFISH,
        KUZNYECHIK,
        XCHACHA20_POLY1305,
        UNKNOWN
    }
    public static class EncryptionIdentifier
    {
        private const string HeaderPrefix = "[ALGO=";
        private const string HeaderSuffix = "]";

        // Write the file header
        public static void WriteHeader(Stream outputStream, HeaderAlgo algorithm)
        {
            string algoName = algorithm.ToString().Replace("_", "-");
            string header = $"{HeaderPrefix}{algoName}{HeaderSuffix}\n";
            byte[] headerBytes = Encoding.UTF8.GetBytes(header);
            outputStream.Write(headerBytes, 0, headerBytes.Length);
        }

        // Read the file header
        public static HeaderAlgo ReadHeader(Stream inputStream)
        {
            using (StreamReader reader = new StreamReader(inputStream, Encoding.UTF8, true, 1024, true))
            {
                string line = reader.ReadLine();
                if (!string.IsNullOrWhiteSpace(line) && line.StartsWith(HeaderPrefix) && line.EndsWith(HeaderSuffix))
                {
                    string algoName = line.Substring(HeaderPrefix.Length, line.Length - HeaderPrefix.Length - HeaderSuffix.Length);
                    if (Enum.TryParse(algoName.Replace("-", "_"), ignoreCase: true, out HeaderAlgo algorithm))
                    {
                        return algorithm;
                    }
                    else
                    {
                        throw new InvalidDataException($"Invalid algorithm in the file: {algoName}");
                    }
                }
            }
            return HeaderAlgo.UNKNOWN;
        }

        // Get the header row for a given algorithm
        public static string GetHeaderLine(HeaderAlgo algorithm)
        {
            return $"{HeaderPrefix}{algorithm.ToString().Replace("_", "-")}{HeaderSuffix}";
        }
    }
}