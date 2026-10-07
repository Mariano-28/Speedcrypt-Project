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

namespace Speedcrypt.Autotest
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// SimpleTestResult: Encapsulates the result of a cryptographic self-test.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This class provides a structured container for the outcome of tests
    /// executed within the Speedcrypt autotest framework.
    ///
    /// It is conceptually inspired by the CryptSharp project by
    /// James F. Bellinger, which offers a pragmatic and robust approach
    /// to cryptographic validation result management.
    ///
    /// Original project:
    /// - CryptSharp
    /// - Copyright (c) 2010, 2013 James F. Bellinger
    /// - http://www.zer7.com/software/cryptsharp
    ///
    /// Core responsibilities:
    /// - Represent success/failure of a test
    /// - Provide optional exception details for diagnostic purposes
    /// - Generate standardized messages for expected vs. actual comparisons
    ///
    /// This C# implementation preserves the spirit and behavior of the
    /// original design while integrating with Speedcrypt:
    /// - Fully compatible with the ITestResult interface
    /// - Deterministic output formatting
    /// - Immediate availability of exception information
    ///
    /// Grateful acknowledgment is given to James F. Bellinger
    /// for his invaluable contribution to the cryptographic open-source ecosystem.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class SimpleTestResult : ITestResult
    {
        private static readonly string Separator = SimpleTest.NewLine;

        private bool success;
        private string message;
        private Exception exception;

        public SimpleTestResult(
			bool	success,
			string	message)
        {
            this.success = success;
            this.message = message;
        }
        public SimpleTestResult(
			bool		success,
			string		message,
			Exception	exception)
        {
            this.success = success;
            this.message = message;
            this.exception = exception;
        }
		public static ITestResult Successful(
            ITest	test,
            string	message)
        {
            return new SimpleTestResult(true, test.Name + ": " + message);
        }
        public static ITestResult Failed(
            ITest	test,
            string	message)
        {
            return new SimpleTestResult(false, test.Name + ": " + message);
        }
        public static ITestResult Failed(
            ITest		test,
            string		message,
            Exception	t)
        {
            return new SimpleTestResult(false, test.Name + ": " + message, t);
        }
        public static ITestResult Failed(
            ITest	test,
            string	message,
            object	expected,
            object	found)
        {
            return Failed(test, message + Separator + "Expected: " + expected + Separator + "Found   : " + found);
        }
        public static string FailedMessage(
			string	algorithm,
			string	testName,
			string	expected,
            string	actual)
        {
            StringBuilder sb = new StringBuilder(algorithm);
            sb.Append(" failing ").Append(testName);
            sb.Append(Separator).Append("    expected: ").Append(expected);
            sb.Append(Separator).Append("    got     : ").Append(actual);
            return sb.ToString();
        }
		public bool IsSuccessful()
        {
            return success;
        }
        public override string ToString()
        {
            return message;
        }
		public Exception GetException()
        {
            return exception;
        }
    }
}