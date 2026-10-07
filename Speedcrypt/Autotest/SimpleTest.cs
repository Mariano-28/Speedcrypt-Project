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
using System.Reflection;
using System.Collections;

using Org.BouncyCastle.Utilities;

namespace Speedcrypt.Autotest
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SimpleTest: Base class for deterministic cryptographic self-tests.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This abstract class provides the core execution and assertion
    /// framework for cryptographic self-tests within Speedcrypt.
    ///
    /// The design and structure are directly derived from the
    /// Bouncy Castle org.bouncycastle.util.test.SimpleTest class,
    /// which defines a minimal, deterministic, and framework-independent
    /// approach to cryptographic validation.
    ///
    /// Core responsibilities:
    /// - Execution control and result normalization
    /// - Assertion helpers for equality and boolean conditions
    /// - Controlled conversion of test failures into structured results
    /// - Safe isolation of unexpected exceptions
    ///
    /// Exception handling within Perform() is intentional:
    /// - TestFailedException is converted into a failed ITestResult
    /// - Any other exception is treated as a critical test failure
    ///
    /// The class avoids reliance on external unit test frameworks
    /// to guarantee deterministic behavior and immediate failure
    /// semantics, which are essential in cryptographic validation.
    ///
    /// This C# adaptation preserves the original behavior and intent,
    /// while integrating with the Speedcrypt autotest infrastructure
    /// and .NET runtime environment.
    ///
    /// Grateful acknowledgment is given to the Bouncy Castle authors
    /// for providing a clear and robust testing foundation
    /// for cryptographic implementations.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public abstract class SimpleTest : ITest
    {
        public abstract string Name { get; }
        private ITestResult Success()
        {
            return SimpleTestResult.Successful(this, "Okay");
        }
        public void Fail(string message)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }
        public void Fail(string message, Exception throwable)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message, throwable));
        }
        public void Fail(string message, object expected, object found)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message, expected, found));
        }
        public void IsTrue(bool value)
        {
            if (!value)
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }
        public void IsTrue(string message, bool value)
        {
            if (!value)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }
        public void IsEquals(object a, object b)
        {
            if (!a.Equals(b))
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }
        public void IsEquals(int a, int b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }
        public void IsEquals(string message, bool a, bool b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }
        public void IsEquals(string message, long a, long b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }
        public void IsEquals(string message, object a, object b)
        {
            if (a == null && b == null)
                return;
            if (a == null || b == null || !a.Equals(b))
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }
        public bool AreEqual(byte[] a, byte[] b)
        {
            return Arrays.AreEqual(a, b);
        }
        public bool AreEqual(byte[] a, int aFromIndex, int aToIndex, byte[] b, int bFromIndex, int bToIndex)
        {
            return Arrays.AreEqual(a, aFromIndex, aToIndex, b, bFromIndex, bToIndex);
        }
        public virtual ITestResult Perform()
        {
            try
            {
                PerformTest();
                return Success();
            }
            catch (TestFailedException e)
            {
                return e.GetResult();
            }
            catch (Exception e)
            {
                return SimpleTestResult.Failed(this, "Exception: " + e, e);
            }
        }
        public static void RunTest(ITest test)
        {
            RunTest(test, Console.Out);
        }
        public static void RunTest(ITest test, TextWriter outStream)
        {
            ITestResult result = test.Perform();
            outStream.WriteLine(result.ToString());
            if (result.GetException() != null)
            {
                outStream.WriteLine(result.GetException().StackTrace);
            }
        }
        public static Stream GetTestDataAsStream(string name)
        {
            string fullName = GetFullName(name);
            return Assembly.GetExecutingAssembly().GetManifestResourceStream(fullName);
        }
        public static string[] GetTestDataEntries(string prefix)
        {
            string fullPrefix = GetFullName(prefix);
            ArrayList result = new ArrayList();
            string[] fullNames = Assembly.GetExecutingAssembly().GetManifestResourceNames();
            foreach (string fullName in fullNames)
            {
                if (fullName.StartsWith(fullPrefix))
                {
                    string name = GetShortName(fullName);
                    result.Add(name);
                }
            }
            return (string[])result.ToArray(typeof(String));
        }
        private static string GetFullName(string name)
        {
#if SEPARATE_UNIT_TESTS
        return "UnitTests.data." + name;
#elif PORTABLE
        return "crypto.tests." + name;
#else
            return "crypto.test.data." + name;
#endif
        }

        private static string GetShortName(string fullName)
        {
#if SEPARATE_UNIT_TESTS
        return fullName.Substring("UnitTests.data.".Length);
#elif PORTABLE
        return fullName.Substring("crypto.tests.".Length);
#else
            return fullName.Substring("crypto.test.data.".Length);
#endif
        }
        private static string GetNewLine()
        {
            return Environment.NewLine;
        }

        public static readonly string NewLine = GetNewLine();
        public abstract void PerformTest();
        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second)
        {
            return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
        }
        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second, int millisecond)
        {
            return new DateTime(year, month, day, hour, minute, second, millisecond, DateTimeKind.Utc);
        }
        // Compatibilità legacy
        public void AssertEquals(string message, object expected, object actual)
        {
            IsEquals(message, expected, actual);
        }
        public void AssertEquals(object expected, object actual)
        {
            IsEquals(expected, actual);
        }
        public void AssertTrue(string message, bool value)
        {
            IsTrue(message, value);
        }
        public void AssertTrue(bool value)
        {
            IsTrue(value);
        }
    }
}