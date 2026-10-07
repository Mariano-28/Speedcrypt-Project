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

namespace Speedcrypt.Digests.GOST
{
    /// <summary>
    /// Created by Mariano Ortu
	/// 
    /// GOSTash94: Implementation of the GOST R 34.11‑94 cryptographic hash algorithm.
    /// Processes message blocks, maintains control sum and length, and produces a 256‑bit digest.
    /// Designed for Speedcrypt hashing framework.
    /// </summary>
    ///
    /// <remarks>
    /// This class implements the GOST R 34.11‑94 hash function, defined in the Russian national
    /// standard and described in RFC 5831 / RFC 4357. The algorithm is based on the GOST block
    /// cipher and uses S‑boxes and LFSR mixing. Public implementations of this algorithm exist
    /// in C (e.g., nettle's gosthash94.c) and other languages as reference sources.
    ///
    /// 📒 Security Note:
    /// GOST R 34.11‑94 is considered **cryptographically weak by modern standards** and should 
    /// not be used for new security-sensitive applications. Official documents estimate its
    /// resistance at ~2^128 operations, with known theoretical reduction to ~2^105 operations
    /// against collisions (RFC 5831, RFC 5933). Research has demonstrated practical collision
    /// attacks on the compression function and methods to construct second preimages with
    /// complexity below ideal 2^256 security margins.
    ///
    /// References and inspiration:
    /// - RFC 5831 Security Considerations (cryptographic resistance estimate)
    ///   https://pike.lysator.liu.se/docs/ietf/rfc/58/rfc5831.xml?utm_source=chatgpt.com
    /// - RFC 5933 Security Considerations (GOST hash resistance)
    ///   https://pike.lysator.liu.se/docs/ietf/rfc/59/rfc5933.xml?utm_source=chatgpt.com
    /// - Wikipedia summary (attack results ~2^105)
    ///   https://en.wikipedia.org/wiki/GOST_%28hash_function%29?utm_source=chatgpt.com
    /// - Cryptanalysis research on second preimage attacks (FSE 2008)
    ///   https://graz.elsevierpure.com/en/publications/a-second-preimage-attack-on-the-gost-hash-function?utm_source=chatgpt.com
    /// - Black‑box collision analysis (SECRYPT 2011)
    ///   https://www.scitepress.org/Papers/2011/35251/?utm_source=chatgpt.com
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class GOSTash94 : ReHashModule
	{
		private uint[] m_sum = new uint[8];
		private uint[] m_hash = new uint[8];
		private uint[] m_len = new uint[8];
		private byte[] m_partial = new byte[32];
		private uint m_partial_bytes;
		private static uint[] pSBox1 = new uint[256];
		private static uint[] pSBox2 = new uint[256];
		private static uint[] pSBox3 = new uint[256];
		private static uint[] pSBox4 = new uint[256];

		private static void EncryptRound(uint k1, uint k2, ref uint l, ref uint r)
		{
			uint t = k1 + r;
			l ^= pSBox1[t & 0xff] ^ pSBox2[(t >> 8) & 0xff] ^
				pSBox3[(t >> 16) & 0xff] ^ pSBox4[t >> 24];

			t = k2 + l;
			r ^= pSBox1[t & 0xff] ^ pSBox2[(t >> 8) & 0xff] ^
				pSBox3[(t >> 16) & 0xff] ^ pSBox4[t >> 24];
		}
		private static void Encrypt(uint[] k0, ref uint l, ref uint r)
		{
			EncryptRound(k0[0], k0[1], ref l, ref r);
			EncryptRound(k0[2], k0[3], ref l, ref r);
			EncryptRound(k0[4], k0[5], ref l, ref r);
			EncryptRound(k0[6], k0[7], ref l, ref r);
			EncryptRound(k0[0], k0[1], ref l, ref r);
			EncryptRound(k0[2], k0[3], ref l, ref r);
			EncryptRound(k0[4], k0[5], ref l, ref r);
			EncryptRound(k0[6], k0[7], ref l, ref r);
			EncryptRound(k0[0], k0[1], ref l, ref r);
			EncryptRound(k0[2], k0[3], ref l, ref r);
			EncryptRound(k0[4], k0[5], ref l, ref r);
			EncryptRound(k0[6], k0[7], ref l, ref r);
			EncryptRound(k0[7], k0[6], ref l, ref r);
			EncryptRound(k0[5], k0[4], ref l, ref r);
			EncryptRound(k0[3], k0[2], ref l, ref r);
			EncryptRound(k0[1], k0[0], ref l, ref r);

			// Swap sides
			uint t = r; r = l; l = t;
		}
		private void MakeTables()
		{
			int a, b, i;
			uint ax, bx, cx, dx;

			uint[,] uStdSBox = // 4-bit SBox
			{
				{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
				{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
				{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
				{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
				{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
				{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
				{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
				{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
			};
		
			i = 0;
			for(a = 0; a < 16; a++)
			{
				ax = uStdSBox[1,a] << 15;
				bx = uStdSBox[3,a] << 23;
				cx = uStdSBox[5,a];
				cx = (cx >> 1) | (cx << 31);
				dx = uStdSBox[7,a] << 7;
		
				for(b = 0; b < 16; b++)
				{
					pSBox1[i  ] = ax | (uStdSBox[0,b] << 11);
					pSBox2[i  ] = bx | (uStdSBox[2,b] << 19);
					pSBox3[i  ] = cx | (uStdSBox[4,b] << 27);
					pSBox4[i++] = dx | (uStdSBox[6,b] <<  3);
				}
			}
		}
		private static void Compress(uint[] h, uint[] m)
		{
			int i;
			uint l, r;
			uint[] k0 = new uint[8];
			uint[] u = new uint[8];
			uint[] v = new uint[8];
			uint[] w = new uint[8];
			uint[] s = new uint[8];

			for(i = 0; i < 8; i++) u[i] = h[i];
			for(i = 0; i < 8; i++) v[i] = m[i];

			for(i = 0; i < 8; i += 2)
			{
				w[0] = u[0] ^ v[0]; // w = u XOR v
				w[1] = u[1] ^ v[1];
				w[2] = u[2] ^ v[2];
				w[3] = u[3] ^ v[3];
				w[4] = u[4] ^ v[4];
				w[5] = u[5] ^ v[5];
				w[6] = u[6] ^ v[6];
				w[7] = u[7] ^ v[7];

				// P transformation
				k0[0] = (w[0] & 0x000000FFu) | ((w[2] & 0x000000FFu) << 8) |
					((w[4] & 0x000000FFu) << 16) | ((w[6] & 0x000000FFu) << 24);
				k0[1] = ((w[0] & 0x0000FF00u) >> 8)  | (w[2] & 0x0000FF00u) |
					((w[4] & 0x0000FF00u) << 8) | ((w[6] & 0x0000FF00u) << 16);
				k0[2] = ((w[0] & 0x00FF0000u) >> 16) | ((w[2] & 0x00FF0000u) >> 8) |
					(w[4] & 0x00FF0000u) | ((w[6] & 0x00FF0000u) << 8);
				k0[3] = ((w[0] & 0xFF000000u) >> 24) | ((w[2] & 0xFF000000u) >> 16) |
					((w[4] & 0xFF000000u) >> 8) | (w[6] & 0xFF000000u);
				k0[4] = (w[1] & 0x000000FFu) | ((w[3] & 0x000000FFu) << 8) |
					((w[5] & 0x000000FFu) << 16) | ((w[7] & 0x000000FFu) << 24);
				k0[5] = ((w[1] & 0x0000FF00u) >> 8) | (w[3] & 0x0000FF00u) |
					((w[5] & 0x0000FF00u) << 8) | ((w[7] & 0x0000FF00u) << 16);
				k0[6] = ((w[1] & 0x00FF0000u) >> 16) | ((w[3] & 0x00FF0000u) >> 8) |
					(w[5] & 0x00FF0000u) | ((w[7] & 0x00FF0000u) << 8);
				k0[7] = ((w[1] & 0xFF000000u) >> 24) | ((w[3] & 0xFF000000u) >> 16) |
					((w[5] & 0xFF000000u) >> 8) | (w[7] & 0xFF000000u);

				r = h[i];
				l = h[i + 1];
				Encrypt(k0, ref l, ref r);

				s[i] = r;
				s[i + 1] = l;

				if(i == 6) break;
		
				l = u[0] ^ u[2]; // U = A(U)
				r = u[1] ^ u[3];
				u[0] = u[2]; u[1] = u[3]; u[2] = u[4];
				u[3] = u[5]; u[4] = u[6]; u[5] = u[7];
				u[6] = l; u[7] = r;

				if(i == 2) // Constant C_3
				{
					u[0] ^= 0xFF00FF00; u[1] ^= 0xFF00FF00;
					u[2] ^= 0x00FF00FF; u[3] ^= 0x00FF00FF;
					u[4] ^= 0x00FFFF00; u[5] ^= 0xFF0000FF;
					u[6] ^= 0x000000FF; u[7] ^= 0xFF00FFFF;
				}

				l = v[0]; // V = A(A(V))
				r = v[2];
				v[0] = v[4];
				v[2] = v[6];
				v[4] = l ^ r;
				v[6] = v[0] ^ r;
				l = v[1];
				r = v[3];
				v[1] = v[5];
				v[3] = v[7];
				v[5] = l ^ r;
				v[7] = v[1] ^ r;
			}

			// 12 rounds of the LFSR (computed from a product matrix) and XOR in M
			u[0] = m[0] ^ s[6];
			u[1] = m[1] ^ s[7];
			u[2] = m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0x0000FFFFu) ^
				(s[1] & 0x0000FFFFu) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^
				(s[6] << 16) ^ (s[7] & 0xFFFF0000u) ^ (s[7] >> 16);
			u[3] = m[3] ^ (s[0] & 0x0000FFFFu) ^ (s[0] << 16) ^ (s[1] & 0x0000FFFFu) ^
				(s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^
				(s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^
				(s[7] & 0x0000FFFFu) ^ (s[7] << 16) ^ (s[7] >> 16);
			u[4] = m[4] ^ (s[0] & 0xFFFF0000u) ^ (s[0] << 16) ^ (s[0] >> 16) ^
				(s[1] & 0xFFFF0000u) ^ (s[1] >> 16) ^ (s[2] << 16) ^
				(s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^
				(s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0x0000FFFFu) ^ (s[7] << 16) ^
				(s[7] >> 16);
			u[5] = m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF0000u) ^
				(s[1] & 0x0000FFFFu) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^
				(s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^  (s[6] << 16) ^
				(s[6] >> 16) ^ (s[7] & 0xFFFF0000u) ^ (s[7] << 16) ^ (s[7] >> 16);
			u[6] = m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16) ^
				(s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^
				(s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16);
			u[7] = m[7] ^ (s[0] & 0xFFFF0000u) ^ (s[0] << 16) ^ (s[1] & 0x0000FFFFu) ^
				(s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16) ^
				(s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0x0000FFFFu) ^
				(s[7] << 16) ^ (s[7] >> 16);

			// 16 * 1 round of the LFSR and XOR in H
			v[0] = h[0] ^ (u[1] << 16) ^ (u[0] >> 16);
			v[1] = h[1] ^ (u[2] << 16) ^ (u[1] >> 16);
			v[2] = h[2] ^ (u[3] << 16) ^ (u[2] >> 16);
			v[3] = h[3] ^ (u[4] << 16) ^ (u[3] >> 16);
			v[4] = h[4] ^ (u[5] << 16) ^ (u[4] >> 16);
			v[5] = h[5] ^ (u[6] << 16) ^ (u[5] >> 16);
			v[6] = h[6] ^ (u[7] << 16) ^ (u[6] >> 16);
			v[7] = h[7] ^ (u[0] & 0xFFFF0000u) ^ (u[0] << 16) ^ (u[7] >> 16) ^
				(u[1] & 0xFFFF0000u) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xFFFF0000u);
		
			// 61 rounds of LFSR, mixing up h (computed from a product matrix)
			h[0] = (v[0] & 0xFFFF0000u) ^ (v[0] << 16) ^ (v[0] >> 16) ^ (v[1] >> 16) ^
				(v[1] & 0xFFFF0000u) ^ (v[2] << 16) ^ (v[3] >> 16) ^ (v[4] << 16) ^
				(v[5] >> 16) ^ v[5] ^ (v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16) ^
				(v[7] & 0x0000FFFFu);
			h[1] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xFFFF0000u) ^ (v[1] & 0x0000FFFFu) ^
				v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^ (v[4] >> 16) ^ (v[5] << 16) ^
				(v[6] << 16) ^ v[6] ^ (v[7] & 0xFFFF0000u) ^ (v[7] >> 16);
			h[2] = (v[0] & 0x0000FFFFu) ^ (v[0] << 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^
				(v[1] & 0xFFFF0000u) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^
				(v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^ (v[7] & 0x0000FFFFu) ^ (v[7] << 16) ^
				(v[7] >> 16);
			h[3] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xFFFF0000u) ^
				(v[1] & 0xFFFF0000u) ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[2] >> 16) ^ v[2] ^
				(v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^
				(v[7] & 0x0000FFFFu) ^ (v[7] >> 16);
			h[4] = (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2] ^
				(v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^
				v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16);
			h[5] = (v[0] << 16) ^ (v[0] & 0xFFFF0000u) ^ (v[1] << 16) ^ (v[1] >> 16) ^
				(v[1] & 0xFFFF0000u) ^ (v[2] << 16) ^ v[2] ^ (v[3] >> 16) ^ v[3] ^
				(v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^
				(v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xFFFF0000u);
			h[6] = v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^
				(v[4] >> 16) ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^
				(v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ v[7];
			h[7] = v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[2] << 16) ^
				(v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^ (v[5] >> 16) ^ v[5] ^
				(v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7];
		}
		private void ProcessBytes(byte[] pBuf, uint uBufferOffset, uint uBits)
		{
			int i;
			uint a, c = 0, j = uBufferOffset;
			uint[] m = new uint[8];

			// Convert bytes to 32-bit words and compute the sum
			for(i = 0; i < 8; i++)
			{
				a = ((uint)pBuf[j]) | (((uint)pBuf[j + 1]) << 8) |
					(((uint)pBuf[j + 2]) << 16) | (((uint)pBuf[j + 3]) << 24);

				j += 4;
				m[i] = a;

				// Bugfix July 23, 2002 mjos@iki.fi. Thanks to Kaluzhinsky Anatoly.
				if(c != 0)
				{
					c = a + m_sum[i] + 1;
					m_sum[i] = c;
					c = (c <= a) ? 1u : 0u;
				}
				else
				{
					c = a + m_sum[i];
					m_sum[i] = c;
					c = (c < a) ? 1u : 0u;
				}
			}

			Compress(m_hash, m);
		
			// A 64-bit counter should be sufficient
			m_len[0] += uBits;
			if(m_len[0] < uBits) m_len[1]++;
		}
		public GOSTash94()
		{
		}
		public override bool InitModule()
		{
			pbFinalHash = new byte[32];
			MakeTables();
			return true;
		}
		public override void ReleaseModule()
		{
			SecureZeroArray(pbFinalHash);
			pbFinalHash = null;
		}
		public override void InitNewHash()
		{
			int i;
			for(i = 0; i < m_sum.Length; i++) m_sum[i] = 0;
			for(i = 0; i < m_hash.Length; i++) m_hash[i] = 0;
			for(i = 0; i < m_len.Length; i++) m_len[i] = 0;
			for(i = 0; i < m_partial.Length; i++) m_partial[i] = 0;
			m_partial_bytes = 0;
		}
		public override void UpdateHash(byte[] pbData, ulong uLength, bool bIsLastBlock)
		{
			uint i = m_partial_bytes, j = 0;

			while((i < 32) && (j < uLength))
				m_partial[i++] = pbData[j++];

			if(i < 32)
			{
				m_partial_bytes = i;
				return;
			}
			ProcessBytes(m_partial, 0, 256);
		
			while((j + 32) < uLength)
			{
				ProcessBytes(pbData, j, 256);
				j += 32;
			}

			i = 0;
			while(j < uLength)
				m_partial[i++] = pbData[j++];

			m_partial_bytes = i;
		}
		public override void FinalizeHash()
		{
			int i, j = 0;
			uint a;

			if(m_partial_bytes > 0)
			{
				for(a = m_partial_bytes; a < 32; a++) m_partial[a] = 0;
				ProcessBytes(m_partial, 0, m_partial_bytes << 3);
			}

			Compress(m_hash, m_len);
			Compress(m_hash, m_sum);

			for(i = 0; i < 8; i++)
			{
				a = m_hash[i];
				pbFinalHash[j] = (byte)(a & 0xff);
				pbFinalHash[j + 1] = (byte)((a >> 8) & 0xff);
				pbFinalHash[j + 2] = (byte)((a >> 16) & 0xff);
				pbFinalHash[j + 3] = (byte)(a >> 24);
				j += 4;
			}
		}
        public byte[] GetDigest()
        {
            byte[] copy = new byte[pbFinalHash.Length];
            Array.Copy(pbFinalHash, copy, pbFinalHash.Length);
            return copy;
        }
        public override uint Test()
		{
			byte[] pb;
			byte[] r1 = { 0x92, 0xF5, 0x5D, 0xE3, 0xCF, 0x41, 0x36, 0x31,
				0x8A, 0x63, 0xC4, 0x37, 0x1E, 0x28, 0xD4, 0xAE,
				0x56, 0xB7, 0xB1, 0x3A, 0x00, 0x80, 0x71, 0x2A,
				0xE6, 0x9B, 0x53, 0x25, 0x84, 0x2D, 0xB2, 0x5B };
			byte[] r2 = { 0x47, 0x1a, 0xba, 0x57, 0xa6, 0x0a, 0x77, 0x0d,
				0x3a, 0x76, 0x13, 0x06, 0x35, 0xc1, 0xfb, 0xea,
				0x4e, 0xf1, 0x4d, 0xe5, 0x1f, 0x78, 0xb4, 0xae,
				0x57, 0xdd, 0x89, 0x3b, 0x62, 0xf5, 0x52, 0x08 };
			byte[] r3 = { 0xb1, 0xc4, 0x66, 0xd3, 0x75, 0x19, 0xb8, 0x2e,
				0x83, 0x19, 0x81, 0x9f, 0xf3, 0x25, 0x95, 0xe0,
				0x47, 0xa2, 0x8c, 0xb6, 0xf8, 0x3e, 0xff, 0x1c,
				0x69, 0x16, 0xa8, 0x15, 0xa6, 0x37, 0xff, 0xfa };

			pb = StringToAsciiEx("abcabcabcabcabcabcabcabcabcabcabcabcabcabcabc");
			if(!HashAndCompare(pb, r1)) return 1;

			pb = StringToAsciiEx("Suppose the original message has length = 50 bytes");
			if(!HashAndCompare(pb, r2)) return 2;

			pb = StringToAsciiEx("This is message, length=32 bytes");
			if(!HashAndCompare(pb, r3)) return 3;
			
			return 0;
		}
	}
}