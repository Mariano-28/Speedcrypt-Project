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
using System.Globalization;

#if SILVERLIGHT || PORTABLE
using System.Collections.Generic;
#else
using System.Collections;
#endif

namespace Speedcrypt.Autotest
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Platform: Cross-platform abstraction utilities for runtime compatibility.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This class provides a collection of low-level helper methods
    /// used to abstract platform and framework differences across
    /// multiple .NET targets (Full Framework, Compact Framework,
    /// Silverlight, Portable profiles).
    ///
    /// The design and structure are directly derived from the
    /// Bouncy Castle Platform utility class, which represents
    /// a rigorous and battle-tested solution for cross-runtime
    /// compatibility in cryptographic libraries.
    ///
    /// Original reference:
    /// - Bouncy Castle Cryptography Library
    /// - org.bouncycastle.util.Platform
    ///
    /// This C# adaptation preserves the original intent:
    /// - Deterministic behavior across runtimes
    /// - Explicit handling of platform limitations
    /// - Avoidance of reflection-heavy or fragile constructs
    ///
    /// Minor adaptations were applied only where required
    /// to integrate cleanly with the Speedcrypt architecture
    /// and naming conventions, without altering semantics.
    ///
    /// Grateful acknowledgment is given to the Bouncy Castle
    /// authors for their exceptional work and long-standing
    /// contribution to applied cryptography and secure software.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    internal abstract class Platform
    {
        private static readonly CompareInfo InvariantCompareInfo = CultureInfo.InvariantCulture.CompareInfo;

#if NETCF_1_0 || NETCF_2_0
        private static string GetNewLine()
        {
            MemoryStream buf = new MemoryStream();
            StreamWriter w = new StreamWriter(buf, Encoding.UTF8);
            w.WriteLine();
            Dispose(w);
            byte[] bs = buf.ToArray();
            return Encoding.UTF8.GetString(bs, 0, bs.Length);
        }
#else
        private static string GetNewLine()
        {
            return Environment.NewLine;
        }
#endif
        internal static bool EqualsIgnoreCase(string a, string b)
        {
#if PORTABLE
            return String.Equals(a, b, StringComparison.OrdinalIgnoreCase);
#else
            return ToUpperInvariant(a) == ToUpperInvariant(b);
#endif
        }

#if NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || (PORTABLE && !DOTNET)
        internal static string GetEnvironmentVariable(
            string variable)
        {
            return null;
        }
#else
        internal static string GetEnvironmentVariable(
            string variable)
        {
            try
            {
                return Environment.GetEnvironmentVariable(variable);
            }
            catch (System.Security.SecurityException)
            {
                // We don't have the required permission to read this environment variable,
                // which is fine, just act as if it's not set
                return null;
            }
        }
#endif

#if NETCF_1_0
        internal static Exception CreateNotImplementedException(
            string message)
        {
            return new Exception("Not implemented: " + message);
        }

        internal static bool Equals(
            object	a,
            object	b)
        {
            return a == b || (a != null && b != null && a.Equals(b));
        }
#else
        internal static Exception CreateNotImplementedException(
            string message)
        {
            return new NotImplementedException(message);
        }
#endif

#if SILVERLIGHT || PORTABLE
        internal static System.Collections.IList CreateArrayList()
        {
            return new List<object>();
        }
        internal static System.Collections.IList CreateArrayList(int capacity)
        {
            return new List<object>(capacity);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            System.Collections.IList result = new List<object>(collection.Count);
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            System.Collections.IList result = new List<object>();
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Dictionary<object, object>();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Dictionary<object, object>(capacity);
        }
        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            System.Collections.IDictionary result = new Dictionary<object, object>(dictionary.Count);
            foreach (System.Collections.DictionaryEntry entry in dictionary)
            {
                result.Add(entry.Key, entry.Value);
            }
            return result;
        }
#else
        internal static System.Collections.IList CreateArrayList()
        {
            return new ArrayList();
        }
        internal static System.Collections.IList CreateArrayList(int capacity)
        {
            return new ArrayList(capacity);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.ICollection collection)
        {
            return new ArrayList(collection);
        }
        internal static System.Collections.IList CreateArrayList(System.Collections.IEnumerable collection)
        {
            ArrayList result = new ArrayList();
            foreach (object o in collection)
            {
                result.Add(o);
            }
            return result;
        }
        internal static System.Collections.IDictionary CreateHashtable()
        {
            return new Hashtable();
        }
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Hashtable(capacity);
        }
        internal static System.Collections.IDictionary CreateHashtable(System.Collections.IDictionary dictionary)
        {
            return new Hashtable(dictionary);
        }
#endif

        internal static string ToLowerInvariant(string s)
        {
#if PORTABLE
            return s.ToLowerInvariant();
#else
            return s.ToLower(CultureInfo.InvariantCulture);
#endif
        }

        internal static string ToUpperInvariant(string s)
        {
#if PORTABLE
            return s.ToUpperInvariant();
#else
            return s.ToUpper(CultureInfo.InvariantCulture);
#endif
        }

        internal static readonly string NewLine = GetNewLine();

#if PORTABLE
        internal static void Dispose(IDisposable d)
        {
            d.Dispose();
        }
#else
        internal static void Dispose(Stream s)
        {
            s.Close();
        }
        internal static void Dispose(TextWriter t)
        {
            t.Close();
        }
#endif

        internal static int IndexOf(string source, string value)
        {
            return InvariantCompareInfo.IndexOf(source, value, CompareOptions.Ordinal);
        }

        internal static int LastIndexOf(string source, string value)
        {
            return InvariantCompareInfo.LastIndexOf(source, value, CompareOptions.Ordinal);
        }

        internal static bool StartsWith(string source, string prefix)
        {
            return InvariantCompareInfo.IsPrefix(source, prefix, CompareOptions.Ordinal);
        }

        internal static bool EndsWith(string source, string suffix)
        {
            return InvariantCompareInfo.IsSuffix(source, suffix, CompareOptions.Ordinal);
        }

        internal static string GetTypeName(object obj)
        {
            return obj.GetType().FullName;
        }
    }
}