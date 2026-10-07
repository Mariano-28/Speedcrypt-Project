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

// NUnit unit testing framework
using NUnit.Framework;

// Basic test interface
 
namespace Speedcrypt.Autotest
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ITest: Minimal interface for executable cryptographic self-tests.
    /// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This interface defines the contract for a single executable test
    /// within the Speedcrypt autotest framework.
    ///
    /// The design is conceptually derived from the Bouncy Castle testing model
    /// (org.bouncycastle.util.test.Test / TestResult),
    /// adapted to:
    /// - Explicit naming via the Name property
    /// - Deterministic execution through the Perform() method
    /// - Structured result reporting via ITestResult
    ///
    /// The [Test] attribute allows integration with external
    /// test runners while preserving full independence of
    /// the core validation logic.
    ///
    /// This interface intentionally:
    /// - Contains no exception handling
    /// - Delegates all failure semantics to the returned ITestResult
    /// - Enforces a clear separation between execution and reporting
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public interface ITest
    {
        string Name { get; }

		[Test]
        ITestResult Perform();
    }
}