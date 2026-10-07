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
using System.Collections.Generic;

namespace Speedcrypt.EstimMST
{
    /// <summary>
    /// Useful shared Linq extensions
    /// </summary>
    static class LinqExtensions
    {
        /// <summary>
        /// Used to group elements by a key function, but only where elements are adjacent
        /// </summary>
        /// <param name="keySelector">Function used to choose the key for grouping</param>
        /// <param name="source">THe enumerable being grouped</param>
        /// <returns>An enumerable of <see cref="AdjacentGrouping{TKey, TElement}"/> </returns>
        /// <typeparam name="TKey">Type of key value used for grouping</typeparam>
        /// <typeparam name="TSource">Type of elements that are grouped</typeparam>
        public static IEnumerable<AdjacentGrouping<TKey, TSource>> GroupAdjacent<TKey, TSource>(this IEnumerable<TSource> source, Func<TSource, TKey> keySelector)
        {
            var prevKey = default(TKey);
            var prevStartIndex = 0;
            var prevInit = false;
            var itemsList = new List<TSource>();

            var i = 0;
            foreach (var item in source)
            {
                var key = keySelector(item);
                if (prevInit)
                {
                    if (!prevKey.Equals(key))
                    {
                        yield return new AdjacentGrouping<TKey, TSource>(key, itemsList, prevStartIndex, i - 1);

                        prevKey = key;
                        itemsList = new List<TSource>();
                        itemsList.Add(item);
                        prevStartIndex = i;
                    }
                    else
                    {
                        itemsList.Add(item);
                    }
                }
                else
                {
                    prevKey = key;
                    itemsList.Add(item);
                    prevInit = true;
                }

                i++;
            }

            if (prevInit) yield return new AdjacentGrouping<TKey, TSource>(prevKey, itemsList, prevStartIndex, i - 1); ;
        }

        /// <summary>
        /// A single grouping from the GroupAdjacent function, includes start and end indexes for the grouping in addition to standard IGrouping bits
        /// </summary>
        /// <typeparam name="TElement">Type of grouped elements</typeparam>
        /// <typeparam name="TKey">Type of key used for grouping</typeparam>
        public class AdjacentGrouping<TKey, TElement> :  IGrouping<TKey, TElement>, IEnumerable<TElement>
        {
            /// <summary>
            /// The key value for this grouping
            /// </summary>
            public TKey Key
            {
                get;
                private set;
            }

            /// <summary>
            /// The start index in the source enumerable for this group (i.e. index of first element)
            /// </summary>
            public int StartIndex
            {
                get;
                private set;
            }

            /// <summary>
            /// The end index in the enumerable for this group (i.e. the index of the last element)
            /// </summary>
            public int EndIndex
            {
                get;
                private set;
            }

            private IEnumerable<TElement> m_groupItems;

            internal AdjacentGrouping(TKey key, IEnumerable<TElement> groupItems, int startIndex, int endIndex)
            {
                this.Key = key;
                this.StartIndex = startIndex;
                this.EndIndex = endIndex;
                m_groupItems = groupItems;
            }
            private AdjacentGrouping() { }

            IEnumerator<TElement> IEnumerable<TElement>.GetEnumerator()
            {
                return m_groupItems.GetEnumerator();
            }

            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
            {
                return m_groupItems.GetEnumerator();
            }
        }
    }
}