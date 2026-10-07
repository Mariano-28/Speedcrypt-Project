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
    /// KeyarrowManager provides strict and reusable management logic
    /// for positioning an indicator PictureBox within a set of algorithms
    /// on a Windows Form interface.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Linear or custom Y-position calculation for algorithm indicators.
    /// - Proper association with a PictureBox representing the indicator.
    /// - Optional control over a GroupBox (e.g., PGP settings) based on selection.
    /// - Safe handling of out-of-range indices through exceptions.
    /// - Encapsulation of position logic, preventing duplication across Forms.
    /// - Support for both fixed-step and fully custom layouts.
    /// - Immediate UI updates in a deterministic, predictable manner.
    /// - Independence from specific ComboBox implementations, making it reusable.
    /// - Clear separation of concerns: Form layout vs. indicator logic.
    /// - Complete exception safety during updates and queries.
    /// - Optionally allows retrieval of Y positions for any algorithm.
    ///
    /// - The class is UI-aware only to the extent of moving PictureBox and enabling/disabling GroupBox,
    /// -  but contains no unrelated form logic, ensuring modularity and reusability.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class KeyarrowManager
    {
        /// <summary>Fixed X position for the indicator PictureBox.</summary>
        private readonly int baseX = 338;

        /// <summary>Base Y position for the first algorithm indicator.</summary>
        private readonly int baseY = 19;

        /// <summary>Vertical step between each algorithm indicator for linear layouts.</summary>
        private readonly int step = 24;

        /// <summary>Array of Y positions for all algorithms (linear or custom).</summary>
        private readonly int[] yPositions;

        /// <summary>The PictureBox used as the algorithm selection indicator.</summary>
        private readonly PictureBox picKeisize;

        /// <summary>The GroupBox (e.g., PGP settings) optionally enabled for a specific algorithm.</summary>
        private readonly GroupBox grbPgp;

        /// <summary>
        /// Constructor for linear step layout.
        /// </summary>
        /// <param name="indicator">The PictureBox indicator.</param>
        /// <param name="pgpGroup">The GroupBox optionally enabled for a specific algorithm.</param>
        /// <param name="totalAlgorithms">Total number of algorithms to calculate positions for.</param>
        public KeyarrowManager(PictureBox indicator, GroupBox pgpGroup, int totalAlgorithms)
        {
            picKeisize = indicator ?? throw new ArgumentNullException(nameof(indicator));
            grbPgp = pgpGroup ?? throw new ArgumentNullException(nameof(pgpGroup));

            yPositions = new int[totalAlgorithms];
            for (int i = 0; i < totalAlgorithms; i++)
                yPositions[i] = baseY + step * i;
        }

        /// <summary>
        /// Constructor for custom Y positions.
        /// </summary>
        /// <param name="indicator">The PictureBox indicator.</param>
        /// <param name="pgpGroup">The GroupBox optionally enabled for a specific algorithm.</param>
        /// <param name="customPositions">Array of Y positions for the indicators.</param>
        public KeyarrowManager(PictureBox indicator, GroupBox pgpGroup, int[] customPositions)
        {
            if (customPositions == null || customPositions.Length == 0)
                throw new ArgumentException("Custom positions array cannot be null or empty.", nameof(customPositions));

            picKeisize = indicator ?? throw new ArgumentNullException(nameof(indicator));
            grbPgp = pgpGroup ?? throw new ArgumentNullException(nameof(pgpGroup));

            yPositions = customPositions;
        }

        /// <summary>
        /// Updates the indicator position based on the selected algorithm index.
        /// </summary>
        /// <param name="selectedIndex">Index of the selected algorithm.</param>
        public void UpdateIndicator(int selectedIndex)
        {
            if (selectedIndex < 0 || selectedIndex >= yPositions.Length)
                throw new ArgumentOutOfRangeException(nameof(selectedIndex), "Selected index is out of range.");

            picKeisize.Location = new Point(baseX, yPositions[selectedIndex]);
            grbPgp.Enabled = (selectedIndex == 1);
        }

        /// <summary>
        /// Returns the Y position of the indicator for a given algorithm index.
        /// </summary>
        /// <param name="index">Algorithm index.</param>
        /// <returns>Y coordinate of the indicator.</returns>
        public int GetYPosition(int index)
        {
            if (index < 0 || index >= yPositions.Length)
                throw new ArgumentOutOfRangeException(nameof(index), "Index is out of range.");

            return yPositions[index];
        }
    }
    /// <summary>
    /// Alternative legacy method for linear indicator positioning.
    /// 
    /// This method replicates the behavior of KeyarrowManager using
    /// fixed baseY and step values directly in the Form.
    /// 
    /// Kept for reference only; usage is <b>not recommended</b>.
    /// Prefer using KeyarrowManager for all indicator updates.
    /// </summary>
    /// 
    // In alternative into the form
    /* void Keyarrow()
     {

         // Base Y position for the first algorithm
         int baseY = 19;

         // Vertical step between each algorithm (all equal now)
         int step = 24;

         int selectedIndex = cmbCrypteng.SelectedIndex;

         // Set the picture location based on the selected algorithm
         picKeisize.Location = new Point(338, baseY + step * selectedIndex);

         // Enable PGP settings only for the second algorithm (index 1)
         grbPgp.Enabled = (selectedIndex == 1);
     }*/
}