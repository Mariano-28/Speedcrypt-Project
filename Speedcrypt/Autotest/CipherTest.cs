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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Speedcrypt.Autotest
{
    /// <summary>
    /// Created by Mariano Ortu
	/// 
    /// CipherTest: Base class for block cipher validation tests.
	/// Designed for Speedcrypt Autotest framework with centralized logging.
    /// </summary>
    ///
    /// <remarks>
    /// This abstract test class provides a structured validation framework
    /// for IBlockCipher implementations.
    ///
    /// The design is derived from the original Bouncy Castle
    /// org.bouncycastle.crypto.test.CipherTest reference,
    /// adapted to the .NET environment and integrated into
    /// the Speedcrypt autotest architecture.
    ///
    /// Core responsibilities:
    /// - Execution of nested SimpleTest instances
    /// - Verification of correct cipher initialization state handling
    /// - Validation of input and output buffer size enforcement
    /// - Confirmation that invalid usage produces the expected exceptions
    ///
    /// All exception handling within this class is intentional and required:
    /// intercepted exceptions represent expected and validated behavior,
    /// not operational failures.
    ///
    /// Any unexpected condition triggers an immediate test failure
    /// via the SimpleTest.Fail mechanism.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public abstract class CipherTest
		: SimpleTest
	{
		private SimpleTest[]      _tests;
		private IBlockCipher _engine;
		private KeyParameter _validKey;

//		protected CipherTest(
//			SimpleTest[]	tests)
//		{
//			_tests = tests;
//		}
		protected CipherTest(
			SimpleTest[]	tests,
			IBlockCipher	engine,
			KeyParameter	validKey)
		{
			_tests = tests;
			_engine = engine;
			_validKey = validKey;
		}
		public override void PerformTest()
		{
			for (int i = 0; i != _tests.Length; i++)
			{
				_tests[i].PerformTest();
			}

			if (_engine != null)
			{
				//
				// state tests
				//
				byte[] buf = new byte[_engine.GetBlockSize()];

				try
				{
					_engine.ProcessBlock(buf, 0, buf, 0);

					Fail("failed initialisation check");
				}
				catch (InvalidOperationException)
				{
					// expected
				}

				bufferSizeCheck((_engine));
			}
		}
		private void bufferSizeCheck(
			IBlockCipher engine)
		{
			byte[] correctBuf = new byte[engine.GetBlockSize()];
			byte[] shortBuf = new byte[correctBuf.Length / 2];

			engine.Init(true, _validKey);

			try
			{
				engine.ProcessBlock(shortBuf, 0, correctBuf, 0);

				Fail("failed short input check");
			}
			catch (DataLengthException)
			{
				// expected
			}

			try
			{
				engine.ProcessBlock(correctBuf, 0, shortBuf, 0);

				Fail("failed short output check");
			}
			catch (DataLengthException)
			{
				// expected
			}

			engine.Init(false, _validKey);

			try
			{
				engine.ProcessBlock(shortBuf, 0, correctBuf, 0);

				Fail("failed short input check");
			}
			catch (DataLengthException)
			{
				// expected
			}

			try
			{
				engine.ProcessBlock(correctBuf, 0, shortBuf, 0);

				Fail("failed short output check");
			}
			catch (DataLengthException)
			{
				// expected
			}
		}
	}
}