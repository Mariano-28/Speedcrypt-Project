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
using System.Drawing;
using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ListViewRowAlternator: Provides a deterministic way to alternate the background color
    /// of rows in a ListView for improved readability, while allowing safe enable/disable
    /// control and immediate restoration of the default appearance.
    ///
    /// This class ensures:
    /// - Safe and deterministic alternation of row colors in a given ListView.
    /// - Ability to enable or disable alternation at any time without residual effects.
    /// - Colors are fully configurable via constructor parameters, with sensible defaults.
    /// - Alternation respects the current visual order of ListViewItems.
    /// - Disabling restores all rows to the ListView's default BackColor immediately.
    /// - Designed for WinForms, compatible with multiple ListViews in a single form.
    /// - Stateless design: each ListView requires its own instance of the class.
    /// - No static or global state is used, avoiding cross-control side effects.
    /// - Minimal, clear, and production-ready implementation aligned with Speedcrypt's coding standards.
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </summary>
    public class ListViewRowAlternator
    {
        private readonly ListView _listView;
        private readonly Color _evenColor;
        private readonly Color _oddColor;

        /// <summary>
        /// Initializes a new instance of the ListViewRowAlternator class.
        /// </summary>
        /// <param name="listView">The ListView to apply row alternation to.</param>
        /// <param name="evenRowColor">Optional color for even rows (default: OldLace).</param>
        /// <param name="oddRowColor">Optional color for odd rows (default: White).</param>
        public ListViewRowAlternator(
            ListView listView,
            Color? evenRowColor = null,
            Color? oddRowColor = null)
        {
            _listView = listView ?? throw new ArgumentNullException(nameof(listView));
            _evenColor = evenRowColor ?? Color.OldLace;
            _oddColor = oddRowColor ?? Color.White;
        }

        /// <summary>
        /// Enables row alternation on the ListView.
        /// Call this after adding or modifying items to update colors.
        /// </summary>
        public void Enable()
        {
            ApplyAlternation();
        }

        /// <summary>
        /// Disables row alternation and restores default background colors.
        /// </summary>
        public void Disable()
        {
            RestoreDefault();
        }

        /// <summary>
        /// Applies alternating colors to all rows in the ListView.
        /// Colors are applied to all subitems, not only the first column.
        /// </summary>
        private void ApplyAlternation()
        {
            for (int i = 0; i < _listView.Items.Count; i++)
            {
                Color rowColor = (i % 2 == 0) ? _evenColor : _oddColor;
                ListViewItem item = _listView.Items[i];

                // First column
                item.BackColor = rowColor;

                // All other columns
                for (int s = 1; s < item.SubItems.Count; s++)
                {
                    item.SubItems[s].BackColor = rowColor;
                }
            }
        }

        /// <summary>
        /// Restores the default background color for all items and subitems.
        /// Useful to temporarily disable alternation.
        /// </summary>
        private void RestoreDefault()
        {
            foreach (ListViewItem item in _listView.Items)
            {
                item.BackColor = _listView.BackColor;

                for (int s = 1; s < item.SubItems.Count; s++)
                {
                    item.SubItems[s].BackColor = _listView.BackColor;
                }
            }
        }
    }
    
    
     // ================================================ Usage ======================================================== 
     
     // In your form constructor:
     // _logAlternator = new ListViewRowAlternator(listLog); // default colors
     // _resultAlternator = new ListViewRowAlternator(listResults, Color.LightGray, Color.WhiteSmoke); // custom colors
     
     // Enable row alternation
     // _logAlternator.Enable();
     // _resultAlternator.Enable();
     // Disable row alternation if needed
     // _logAlternator.Disable();
     // _resultAlternator.Disable();       
}