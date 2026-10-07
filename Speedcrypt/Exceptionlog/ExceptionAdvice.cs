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
using System.Threading;
using System.Reflection;
using System.Net.Sockets;
using System.ComponentModel;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Speedcrypt.Exceptionlog
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ExceptionAdvice: Utility class providing human-readable guidance
    /// based on captured exception types and messages.
    /// </summary>
    ///
    /// <remarks>
    /// This class maps common .NET exception types and message patterns
    /// to concise, user-friendly diagnostic advice.
    /// It is intended to improve log readability and assist troubleshooting
    /// without exposing internal implementation details.
    ///
    /// Features:
    /// - Direct mapping for frequent exception types (IO, Crypto, Format, Runtime)
    /// - Keyword-based fallback analysis on exception messages
    /// - Safe behavior: never throws, always returns a string
    ///
    /// 📒 Security Notes:
    /// - Advice strings are **informational only** and must not be interpreted
    ///   as automated recovery instructions.
    /// - No sensitive data is processed or stored.
    /// - Message keyword analysis is heuristic and must not be relied upon
    ///   for security-critical decisions.
    ///
    /// Designed for Speedcrypt logging framework with focus on clarity,
    /// robustness, and operator assistance.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>

    public static class ExceptionAdvice
    {
        // Returns a user-friendly advice message based on the exception type or message
        public static string GetAdvice(Exception ex)
        {
            if (ex == null) return string.Empty;

            // ===== Specific exception types =====
            if (ex is FileNotFoundException)
                return "Verify file path or check if file exists.";

            if (ex is DirectoryNotFoundException)
                return "Verify directory path or check if directory exists.";

            if (ex is UnauthorizedAccessException)
                return "Check file or directory permissions.";

            if (ex is CryptographicException)
                return "Check if key or SALT is incorrectly loaded.";

            if (ex is IOException)
                return "Check disk status, network access, or file locks.";

            if (ex is FormatException)
                return "Verify input format or data integrity.";

            if (ex is NullReferenceException)
                return "Ensure object is initialized before use.";

            if (ex is ArgumentException)
                return "Verify the argument values passed to the method.";

            if (ex is OverflowException)
                return "Check for numeric overflows or invalid calculations.";

            if (ex is DivideByZeroException)
                return "Avoid division by zero; verify input values.";

            if (ex is Win32Exception)
                return "Check external process execution and system resources.";

            if (ex is SocketException)
                return "Check network connection and endpoint availability.";

            if (ex is ThreadAbortException)
                return "Thread was aborted unexpectedly; check for premature termination.";

            if (ex is OutOfMemoryException)
                return "Insufficient memory to complete operation.";

            if (ex is StackOverflowException)
                return "Stack overflow occurred; check recursion or loops.";

            if (ex is AccessViolationException)
                return "Memory access violation; check pointers or unsafe code.";

            if (ex is NotSupportedException)
                return "Operation is not supported; check method usage.";

            if (ex is NotImplementedException)
                return "Method not implemented; verify code logic.";

            if (ex is InvalidOperationException)
                return "Operation is invalid in the current state; check flow.";

            if (ex is IndexOutOfRangeException)
                return "Array or collection index is out of bounds; check loops and indices.";

            if (ex is KeyNotFoundException)
                return "Key not found in dictionary or collection.";

            if (ex is TargetInvocationException)
                return "Check underlying method called via reflection.";

            if (ex is AggregateException)
                return "Multiple exceptions occurred; inspect InnerExceptions for details.";

            // ===== Generic handling based on keywords =====
            string msg = ex.Message?.ToLower() ?? string.Empty;

            if (msg.Contains("import master key failed"))
                return "Check the master key file, password, or configuration; ensure the file is valid and accessible.";

            if (msg.Contains("encrypt") || msg.Contains("decryption") || msg.Contains("pgp"))
                return "Verify encryption keys, input files, or encryption module configuration.";

            if (msg.Contains("file"))
                return "Check file path, existence, and permissions.";

            if (msg.Contains("directory"))
                return "Check directory path, existence, and permissions.";

            if (msg.Contains("network") || msg.Contains("disk") || msg.Contains("socket"))
                return "Verify disk status, network connectivity, or endpoint availability.";

            if (msg.Contains("update") || msg.Contains("key"))
                return "Check key update process or relevant configuration.";

            if (msg.Contains("permission") || msg.Contains("access"))
                return "Verify user permissions and access rights.";

            if (msg.Contains("timeout"))
                return "Operation timed out; check resources and network conditions.";

            if (msg.Contains("null"))
                return "A null object was used; ensure proper initialization.";

            if (msg.Contains("overflow") || msg.Contains("underflow"))
                return "Check for numeric overflows or invalid calculations.";

            // ===== Generic fallback for unhandled exceptions =====
            return "See stack trace for details or consult Speedcrypt logs.";
        }
    }
}