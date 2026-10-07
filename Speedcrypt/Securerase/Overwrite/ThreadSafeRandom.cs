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
using System.Threading;
using System.Collections.Generic;

namespace Speedcrypt.Secureerase.Overwrite
{
    /// <summary>
    /// Created by Josip Habjan
    /// 
    /// Integrated into Speedcrypt framework by Mariano Ortu, who thanks the author for this valuable implementation.
    /// ThreadSafeRandom: provides a thread-safe pseudo-random number generator and Fisher-Yates shuffle algorithm.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Thread-safe random number generation for all threads
    /// - Secure and unbiased shuffle of list elements
    ///
    /// Responsibility for integration and validation within Speedcrypt
    /// lies entirely with Mariano Ortu, while respecting the original author's work.
    /// </remarks>
    public static class ThreadSafeRandom
    {
        [ThreadStatic]
        private static Random _random;

        /// <summary>
        /// Represents a thread safe pseudo-random number generator, a device that produces a sequence
        /// of numbers that meet certain statistical requirements for randomness.
        /// </summary>
        public static Random @Random
        {
            get { return _random ?? (_random = new Random(Environment.TickCount * Thread.CurrentThread.ManagedThreadId)); }
        }

        /// <summary>
        /// Randomize list element order using Fisher-Yates shuffle algorithm.
        /// </summary>
        /// <typeparam name="T">Element type.</typeparam>
        /// <param name="list">List to shuffle.</param>
        public static void Shuffle<T>(IList<T> list)
        {
            for (int pass = list.Count - 1; pass > 1; pass--)
            {
                int index = ThreadSafeRandom.Random.Next(pass + 1);
                T value = list[index];
                list[index] = list[pass];
                list[pass] = value;
            }
        }
    }
}