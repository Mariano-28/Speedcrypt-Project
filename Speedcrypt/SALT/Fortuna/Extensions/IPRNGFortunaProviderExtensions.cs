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
using System.Linq;
using System.Collections;

namespace Speedcrypt.SALT.Fortuna.Extensions
{
    public static class IPRNGFortunaProviderExtensions
    {
        /// <summary>
        /// Selects a random number between 0 and an upper-bound
        /// </summary>
        /// <param name="provider">Random Number Generator to use</param>
        /// <param name="upperBound">The upper-bound (exclusive) of random number selection</param>
        /// <returns>A random number between 0 (inclusive) and the given upper-bound (exclusive)</returns>
        public static int RandomNumber(this IPRNGFortunaProvider provider, int upperBound)
        {
            int numBits = PowUpperBound(upperBound);
            var numBytes = (int) Math.Ceiling(numBits / 8d);

            var offset = numBits % 8;
            int retVal;

            var bytes = new byte[numBytes];

            do
            {
                provider.GetBytes(bytes);

                // Now we need to conditionally dispose of any extra bits
                if (offset != 0)
                {
                    var bits = new BitArray(bytes);

                    // Truncate (zero-out) high-order bits, if necessary
                    if (BitConverter.IsLittleEndian)
                    {
                        for (var i = bits.Length - 1; i > numBits; i--)
                        {
                            bits.Set(i, false);
                        }
                    }
                    else
                    {
                        for (var i = 0; i < bits.Length - numBits; i++)
                        {
                            bits.Set(i, false);
                        }
                    }

                    var truncatedBytes = new byte[numBytes];
                    ((ICollection)bits).CopyTo(truncatedBytes, 0);
                    bytes = truncatedBytes;
                }

                var prepostFix = Enumerable.Repeat((byte)0, sizeof(int) - bytes.Length);
                var intBytes = BitConverter.IsLittleEndian
                    ? bytes.Concat(prepostFix)
                    : prepostFix.Concat(bytes);

                retVal = BitConverter.ToInt32(intBytes.ToArray(), 0);
            } while (retVal != 0 && retVal >= upperBound);

            return Math.Abs(retVal);
        }
        private static int PowUpperBound(int count, int pow = 1)
        {
            if (count < 2) return 1;

            var value = Math.Pow(2, pow);
            if (value >= count) return pow;

            return PowUpperBound(count, pow + 1);
        }
    }
}
