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

/// <summary>
/// Created by Mariano Ortu
/// 
/// ITestResult: Result contract for cryptographic self-tests.
/// Designed for Speedcrypt Autotest framework with centralized logging.
/// </summary>
///
/// <remarks>
/// This interface defines the minimal result contract for a test execution
/// within the Speedcrypt autotest framework.
///
/// The conceptual structure is inspired by the CryptSharp project
/// by James F. Bellinger, whose work provided a clear, pragmatic,
/// and robust approach to cryptographic validation utilities.
///
/// Original project:
/// - CryptSharp
/// - Copyright (c) 2010, 2013 James F. Bellinger
/// - http://www.zer7.com/software/cryptsharp
///
/// This C# interface preserves the spirit of the original design:
/// - Explicit success/failure reporting
/// - Optional exception exposure for diagnostic purposes
/// - Human-readable result description
///
/// The structure has been adapted to integrate cleanly with
/// the Speedcrypt autotest architecture while maintaining
/// simplicity, determinism, and transparency.
///
/// Grateful acknowledgment is given to James F. Bellinger
/// for his valuable contribution to the cryptographic
/// open-source ecosystem.
///
////// Responsibility for integration, testing, and any minor adaptation within
/// lies entirely with the author.
/// </remarks>


namespace Speedcrypt.Autotest
{
#if !(NETCF_1_0 || NETCF_2_0 || SILVERLIGHT || PORTABLE)
    [Serializable]
#endif
    public class TestFailedException
        : Exception
    {
        private ITestResult _result;
        public TestFailedException(ITestResult result)
        {
            _result = result;
        }
        public ITestResult GetResult()
        {
            return _result;
        }
    }
}