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
using System.Collections.Generic;
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.UI;

namespace Speedcrypt.Securerase.CustomPasses
{
    // CustomPassEvaluator - Secure Pass Evaluation Class
    // Copyright (C) 2023–2026 Mariano Ortu <https://www.sicurpas.it/>
    //
    // This class is free software: you can redistribute it and/or modify
    // it under the terms of the GNU General Public License as published by
    // the Free Software Foundation, either version 3 of the License, or
    // (at your option) any later version.
    //
    // This class is distributed in the hope that it will be useful,
    // but WITHOUT ANY WARRANTY; without even the implied warranty of
    // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    // GNU General Public License for more details.
    //
    // You should have received a copy of the GNU General Public License
    // along with this class. If not, see <https://www.gnu.org/licenses/gpl-3.0.html>.

    //*************************************************************************************

    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// CustomPassEvaluator: Enterprise-grade execution sequence analysis and security strength evaluation engine.
    /// Dynamically processes user-defined token entries to compute sequence entropy metrics and drive presentation indicators.
    /// Fully integrated into the Speedcrypt framework to guarantee safe multi-threaded UI interaction under WinForms layers.
    /// </summary>
    ///
    /// <remarks>
    /// This architecture ensures:
    /// - Dynamic sequence string parsing to map textual execution tokens directly into structural runtime execution models.
    /// - Hardened mathematical weight distribution evaluating entropy variation metrics (Random sweep noise vs homogeneous allocations).
    /// - Comprehensive penalty metrics applied to monotonic or low-entropy configurations to restrict classification ceiling scales.
    /// - Linear mapping interpolation translating raw architectural scores into precise percentage bounds for user UI representation.
    /// - Safe WinForms control management engineered to systematically neutralize rendering stuttering anomalies during real-time updates.
    /// - Complete computational decoupling allowing immediate evaluation without altering underlying data stream configurations.
    ///
    /// Responsibility for this C# production implementation, structural design, integration layer, and runtime validation 
    /// lies entirely with the author.
    /// </remarks>
    /// 
    //*************************************************************************************

    // NOTE FOR INTEGRATION:
    // CustomPassEvaluator originates from Mariano Ortu's "Custom Erase Algorithm" project:
    // - Technical documentation: https://www.sicurpas.it/my-algorithms.html
    // - Official GitHub repository: https://github.com/Mariano-28/CustomEraseAlgorithm
    // - SourceForge download: https://sourceforge.net/projects/custom-erase-algorithm/
    //
    // Integrated into Speedcrypt SecureErase module for advanced file deletion.
    // All original licensing, authorship, and functionality fully preserved.

    public class CustomPassEvaluator
    {
        private readonly ListBox _listBox;
        private readonly QualityProgressBar _progressBar;
        private readonly Label _label;

        /// <summary>
        /// Initializes a new instance of the <see cref="CustomPassEvaluator"/> class mapping tracking interfaces to targeted UI indicators.
        /// </summary>
        /// <param name="listBox">The source interface listing execution pass tokens.</param>
        /// <param name="progressBar">The targeted custom presentation progress layout component.</param>
        /// <param name="label">The descriptive text notification control for strength levels.</param>
        public CustomPassEvaluator(ListBox listBox, QualityProgressBar progressBar, Label label)
        {
            _listBox = listBox ?? throw new ArgumentNullException(nameof(listBox));
            _progressBar = progressBar ?? throw new ArgumentNullException(nameof(progressBar));
            _label = label ?? throw new ArgumentNullException(nameof(label));
        }

        /// <summary>
        /// Updates the visual strength indicators (ProgressBar and Label) based on the current ListBox selection of passes.
        /// Evaluates sequence metrics dynamically and performs layout refresh sequences safely.
        /// </summary>
        public void UpdateStrength()
        {
            var passes = new List<CustomPassType>();

            // Iterate through items to parse underlying layout configuration structural models
            foreach (object item in _listBox.Items)
            {
                if (item is string text)
                {
                    string sanitizedText = text.Trim();

                    if (sanitizedText.StartsWith("Zero", StringComparison.OrdinalIgnoreCase))
                    {
                        passes.Add(CustomPassType.Zeros);
                    }
                    else if (sanitizedText.StartsWith("One", StringComparison.OrdinalIgnoreCase))
                    {
                        passes.Add(CustomPassType.Ones);
                    }
                    else if (sanitizedText.StartsWith("Random", StringComparison.OrdinalIgnoreCase))
                    {
                        passes.Add(CustomPassType.Random);
                    }
                    else
                    {
                        // Execute fallback enum resolution if token structures diverge from default naming strings
                        if (Enum.TryParse(sanitizedText, true, out CustomPassType parsed))
                        {
                            passes.Add(parsed);
                        }
                    }
                }
            }

            // Compute localized entropy score metrics based on structural variety rules
            int score = CalculateScore(passes);

            _progressBar.Minimum = 0;
            _progressBar.Maximum = 100;

            // Perform linear mapping interpolation from raw score scale [0-20] to precise UI progress percentage bounds [0-100]
            int visualValue = (int)Math.Round((score / 20.0) * 100.0);

            // Assign categorical classification parameters to the presentation label configuration
            if (score <= 4)
            {
                _label.Text = "Weak";
            }
            else if (score <= 8)
            {
                _label.Text = "Moderate";
            }
            else if (score <= 14)
            {
                _label.Text = "Strong";
            }
            else
            {
                _label.Text = "Very Strong";
                visualValue = 100; // Enforce absolute ceiling scaling for top tier classifications
            }

            // Neutralize rendering stuttering anomalies under WinForms thread context layers
            if (_progressBar.Value == visualValue)
            {
                _progressBar.Value = Math.Max(visualValue - 1, 0);
            }

            _progressBar.Value = visualValue;
            _progressBar.Refresh();
        }

        /// <summary>
        /// Calculates a numeric score for the given list of passes.
        /// Apply programmatic penalties and rewards based on diversity indices and structural repetition vectors.
        /// </summary>
        private int CalculateScore(List<CustomPassType> passes)
        {
            if (passes == null || passes.Count == 0)
                return 0;

            int score = 0;
            int weakCount = 0;
            int mediumCount = 0;
            int strongCount = 0;

            var distinctPasses = new HashSet<CustomPassType>();

            foreach (CustomPassType pass in passes)
            {
                distinctPasses.Add(pass);

                // Establish weight metrics: Random equals 3 units, homogeneous patterns equal 1 unit
                if (pass == CustomPassType.Random)
                {
                    score += 3;
                    strongCount++;
                }
                else if (pass == CustomPassType.Zeros || pass == CustomPassType.Ones)
                {
                    score += 1;
                    weakCount++;
                }
                else
                {
                    score += 2;
                    mediumCount++;
                }
            }

            int total = passes.Count;

            // Penalize structural monotonicity where configuration lacks entropy variation
            if (distinctPasses.Count == 1)
                return Math.Min(score, 4);

            // Inject configuration variety coefficients up to maximum threshold adjustments
            score += Math.Min(distinctPasses.Count, 3);

            // Distribute completion bonus matrices for high complexity sequences
            if (strongCount >= 2 && distinctPasses.Count >= 3)
                return Math.Min(score + 2, 20);

            // Safeguard tracking bounds if adequate entropy thresholds are maintained
            if (strongCount >= 1)
                return Math.Min(score, 20);

            // Restrict classification limits if baseline patterns dominate data streams (>60%)
            if ((double)weakCount / total > 0.6)
                return Math.Min(score, 8);

            return Math.Min(score, 20);
        }
    }
}