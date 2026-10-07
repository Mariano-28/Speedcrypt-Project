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

namespace Speedcrypt.Digests.GOST
{
    /// <summary>
    /// Created by Mariano Ortu
	/// 
    /// ReHashModule: Abstract base class for cryptographic hash modules.
    /// Provides common interface and helper functions for all hash implementations in Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This abstract class defines the structure and workflow for hash modules, including:
    /// - Initialization and release of module resources
    /// - Hash computation workflow: InitNewHash, UpdateHash, FinalizeHash
    /// - Test function to verify correctness of hash implementation
    /// - Utilities for memory handling, byte storage, ASCII conversion, and hash formatting
    ///
    /// 📒 Security Note:
    /// This is a **framework class** and does not implement any specific hashing algorithm. 
    /// Security depends entirely on the derived module. Only use modern, secure hash functions
    /// (e.g., SHA‑256, SHA‑3, BLAKE2/BLAKE3, Argon2) in security-sensitive applications.
    /// Avoid legacy or weak hashes (MD5, SHA‑1, GOST R 34.11‑94) unless needed for legacy 
    /// compatibility. Refer to official cryptographic assessments and RFCs for module security:
    /// - NIST: SHA‑2 and SHA‑3 standards (FIPS 180‑4)
	/// 
    ///   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    /// - RFC 7693: BLAKE2 specification
    ///   https://www.rfc-editor.org/rfc/rfc7693.html
    /// - Argon2 password hashing
    ///   https://www.cryptolux.org/index.php/Argon2
    /// - GOST R 34.11‑94 cryptanalysis (for weak/legacy hashes)
    ///   https://en.wikipedia.org/wiki/GOST_(hash_function)
    ///
    /// Designed for Speedcrypt hashing framework with focus on safety, correctness, and clarity.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public abstract class ReHashModule
	{
		public string strName = "";
		public string strShortName = "";
		public string strRef = "";

		public ulong uHashSize = 0; // Hash length in bits
		public ulong uInternalBufferSize = 0; // In bits

		public bool bEnabled = true;

		protected byte[] pbFinalHash;
		public abstract bool InitModule();
		public abstract void ReleaseModule();
		public abstract void InitNewHash();
		public abstract void UpdateHash(byte[] pbData, ulong uLength, bool bIsLastBlock);
		public abstract void FinalizeHash();
		public abstract uint Test();
		public byte[] GetFinalHash()
		{
			return pbFinalHash;
		}

		// Flags for the FormatHash function:
		public const uint HASHFMT_LOWERCASE = 0;
		public const uint HASHFMT_UPPERCASE = 1;
		public const uint HASHFMT_WINDOWSNEWLINE = 0;
		public const uint HASHFMT_UNIXNEWLINE = 2;
		public static string FormatHash(byte[] pbHash, uint uBytesInGroup, uint uGroupsPerLine, uint uIndentCount, uint uFlags)
		{
			StringBuilder sb = new StringBuilder();
			byte bt;
			int i;
			uint uCurGroup = 0;
			char[] aChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'a', 'b', 'c', 'd', 'e', 'f' };
			string strNewlineSequence = "\r\n";

			if(pbHash == null) return @"";
			if(pbHash.Length == 0) return @"";

			if(uBytesInGroup == 0) uBytesInGroup = 0xffffffffu;
			if((uFlags & HASHFMT_UPPERCASE) > 0)
			{
				aChars[10] = 'A'; aChars[11] = 'B'; aChars[12] = 'C';
				aChars[13] = 'D'; aChars[14] = 'E'; aChars[15] = 'F';
			}
			if((uFlags & HASHFMT_UNIXNEWLINE) > 0) strNewlineSequence = "\n";

			bt = pbHash[0];
			sb.Append(aChars[bt >> 4]);
			sb.Append(aChars[bt & 0x0F]);

			for(i = 1; i < pbHash.Length; i++)
			{
				bt = pbHash[i];

				if((i % uBytesInGroup) == 0)
				{
					uCurGroup++;
					if((uCurGroup % uGroupsPerLine) == 0)
					{
						sb.Append(strNewlineSequence);
						if(uIndentCount != 0) sb.Append(' ', (int)uIndentCount);
					}
					else sb.Append(' ');
				}

				sb.Append(aChars[bt >> 4]);
				sb.Append(aChars[bt & 0x0F]);
			}

			return sb.ToString();
		}
		protected static void SecureZeroArray(byte[] pbArray)
		{
			if(pbArray == null) return;

			for(int i = 0; i < pbArray.Length; i++)
				pbArray[i] = 0;
		}

#if REHASH_UNSAFE
		protected static unsafe void CopyMemoryEx(byte[] aDst, uint dstIndex, byte[] aSrc, uint srcIndex, uint nCount)
		{
			if((aSrc == null) || (aDst == null))
			{
				throw new ArgumentException();
			}
			if(((uint)aSrc.Length < (nCount + srcIndex)) ||
				((uint)aDst.Length < (nCount + dstIndex)))
			{
				throw new ArgumentException();
			}

			// The following fixed statement pins the location of
			// the aSrc and aDst objects in memory so that they will
			// not be moved by garbage collection.
			fixed(byte* pSrc = aSrc, pDst = aDst)
			{
				byte* ps = pSrc, pd = pDst;

				// Loop over the count in blocks of 4 bytes, copying an
				// unsigned integer (4 bytes) at a time:
				for(uint n = 0; n < (nCount / 4); n++)
				{
					*((uint*)pd) = *((uint*)ps);
					pd += 4; ps += 4; // Advance
				}

				// Complete the copy by moving any bytes that weren't
				// moved in blocks of 4:
				for(uint n = 0; n < (nCount % 4); n++)
				{
					*pd = *ps;
					pd++; ps++;
				}
			}
		}
#else
		protected static void CopyMemoryEx(byte[] aDst, uint dstIndex, byte[] aSrc, uint srcIndex, uint nCount)
		{
			if((aSrc == null) || (aDst == null))
			{
				throw new ArgumentException();
			}
			if(((uint)aSrc.Length < (nCount + srcIndex)) ||
				((uint)aDst.Length < (nCount + dstIndex)))
			{
				throw new ArgumentException();
			}

			uint j = dstIndex;
			for(uint i = srcIndex; i < (srcIndex + nCount); i++)
			{
				aDst[j] = aSrc[i];
				j++;
			}
		}
#endif
		protected static void Store16H(byte[] pbBuffer, ushort uToStore)
		{
			pbBuffer[0] = (byte)(uToStore >> 8);
			pbBuffer[1] = (byte)(uToStore & 0xff);
		}
		protected static void Store32H(byte[] pbBuffer, uint uToStore)
		{
			pbBuffer[0] = (byte)(uToStore >> 24);
			pbBuffer[1] = (byte)((uToStore >> 16) & 0xff);
			pbBuffer[2] = (byte)((uToStore >>  8) & 0xff);
			pbBuffer[3] = (byte)(uToStore & 0xff);
		}
		protected static void Store64H(byte[] pbBuffer, ulong uToStore)
		{
			pbBuffer[0] = (byte)(uToStore >> 56);
			pbBuffer[1] = (byte)((uToStore >> 48) & 0xff);
			pbBuffer[2] = (byte)((uToStore >> 40) & 0xff);
			pbBuffer[3] = (byte)((uToStore >> 32) & 0xff);
			pbBuffer[4] = (byte)((uToStore >> 24) & 0xff);
			pbBuffer[5] = (byte)((uToStore >> 16) & 0xff);
			pbBuffer[6] = (byte)((uToStore >>  8) & 0xff);
			pbBuffer[7] = (byte)(uToStore & 0xff);
		}		
		protected static byte[] StringToAsciiEx(string str)
		{
			if(str == null)
			{
				throw new ArgumentException();
			}

			ASCIIEncoding asciiCoder = new ASCIIEncoding();
			return asciiCoder.GetBytes(str);
		}
		protected static bool CompareByteArraysEx(byte[] a1, byte[] a2)
		{
			if(a1.Length != a2.Length) return false;

			for(int i = 0; i < a1.Length; i++)
				if(a1[i] != a2[i]) return false;

			return true;
		}
		protected bool HashAndCompare(byte[] aSourceBytes, byte[] aRefDigest)
		{
			InitNewHash();
			UpdateHash(aSourceBytes, (ulong)aSourceBytes.Length, true);
			FinalizeHash();
			
			return CompareByteArraysEx(pbFinalHash, aRefDigest);
		}
	}
}