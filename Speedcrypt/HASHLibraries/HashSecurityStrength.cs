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
using System.Collections.Generic;

namespace Speedcrypt.HASHLibraries
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// HashSecurityStrength provides a structured evaluation of the security
    /// level of hashing algorithms and password-derivation functions used in Speedcrypt.
    /// It offers both programmatic access to algorithm strength values and direct integration
    /// with user interface elements for visual feedback.
    ///
    /// This allows developers to quickly determine which algorithms are recommended
    /// and reflect these recommendations in Labels, ProgressBars, or custom UI controls.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized definition of hashing algorithm security scores (1-100).
    /// - Clear distinction between recommended and non-recommended algorithms.
    /// - Dynamic update of UI elements such as Label and ProgressBar to reflect security strength.
    /// - Support for standard ProgressBar as well as any dynamic/custom control
    ///   exposing Minimum, Maximum, and Value properties.
    /// - Case-insensitive lookup of algorithms by name.
    /// - Safe handling of UI updates, including color coding for recommended vs. non-recommended algorithms.
    /// - Direct integration with ComboBox selections to reflect algorithm choice in real time.
    ///
    /// All security scores are realistic estimates to guide user choice.
    /// 
    /// Responsibility for implementation, correctness, and UI integration
    /// lies entirely with the author.
    /// </remarks>
    public static class HashSecurityStrength
    {
        // =================================================================================
        // Represents the security level of a hashing algorithm.
        public class AlgorithmStrength
        {
            public string Name { get; set; }        // Algorithm name
            public int Value { get; set; }          // Security score 1-100
            public bool Recommended { get; set; }   // Is algorithm recommended?
            public string Label => Recommended ? "Recommended" : "Not Recommended"; // Label for UI

            // =================================================================================
            // Apply values to standard ProgressBar
            public void ApplyToControls(Label lblValue, Label lblRecommended, ProgressBar progressBar)
            {
                
                if (lblValue != null) lblValue.Text =  Value.ToString();
                if (lblRecommended != null) lblRecommended.Text = Label;
                if (progressBar != null)
                {
                    progressBar.Minimum = 0;
                    progressBar.Maximum = 100;
                    progressBar.Value = Value;
                }
            }

            // =================================================================================
            // Apply values safely to any control with Minimum, Maximum, Value
            public void ApplyToControls(Label lblValue, Label lblRecommended, dynamic progressBar)
            {
                if (lblValue != null)
                {
                    lblValue.Text = Value.ToString();
                    lblValue.ForeColor = Recommended ? Color.DarkGreen : Color.Red;
                }

                if (lblRecommended != null)
                {
                    lblRecommended.Text = Name == "BCRYPT"
                        ? Label + " [SALT Only]"
                        : Label;

                    lblRecommended.ForeColor = Recommended ? Color.DarkGreen : Color.Red;
                }
                if (lblValue != null) lblValue.Text =Value.ToString();
                if (lblRecommended != null && Name == "BCRYPT") lblRecommended.Text = Label + " [SALT Only]";
                else  lblRecommended.Text = Label;

                if (progressBar == null) return;

                try
                {
                    // Check if control has Minimum, Maximum, Value properties
                    var type = progressBar.GetType();
                    var propMin = type.GetProperty("Minimum");
                    var propMax = type.GetProperty("Maximum");
                    var propValue = type.GetProperty("Value");

                    if (propMin != null && propMax != null && propValue != null)
                    {
                        propMin.SetValue(progressBar, 0);
                        propMax.SetValue(progressBar, 100);
                        propValue.SetValue(progressBar, Value);
                    }
                }
                catch
                {
                    // Silently skip if properties not present
                }
            }
        }

        // =================================================================================

        // Complete list of algorithms with realistic security scores
        public static readonly List<AlgorithmStrength> Algorithms = new List<AlgorithmStrength>
    {
        new AlgorithmStrength { Name = "BCRYPT", Value = 95, Recommended = true },
        new AlgorithmStrength { Name = "SCRYPT", Value = 90, Recommended = true },
        new AlgorithmStrength { Name = "MD5", Value = 10, Recommended = false },
        new AlgorithmStrength { Name = "ARGON2i", Value = 98, Recommended = true },
        new AlgorithmStrength { Name = "ARGON2d", Value = 97, Recommended = true },
        new AlgorithmStrength { Name = "ARGON2id", Value = 99, Recommended = true },
        new AlgorithmStrength { Name = "SHA-224", Value = 60, Recommended = false },
        new AlgorithmStrength { Name = "SHA-256", Value = 85, Recommended = true },
        new AlgorithmStrength { Name = "SHA-384", Value = 88, Recommended = true },
        new AlgorithmStrength { Name = "SHA-512", Value = 90, Recommended = true },
        new AlgorithmStrength { Name = "SHA3-256", Value = 92, Recommended = true },
        new AlgorithmStrength { Name = "SHA3-384", Value = 94, Recommended = true },
        new AlgorithmStrength { Name = "SHA3-512", Value = 95, Recommended = true },
        new AlgorithmStrength { Name = "BLAKE-256", Value = 85, Recommended = true },
        new AlgorithmStrength { Name = "BLAKE-512", Value = 88, Recommended = true },
        new AlgorithmStrength { Name = "BLAKE2b", Value = 93, Recommended = true },
        new AlgorithmStrength { Name = "BLAKE2s", Value = 90, Recommended = true },
        new AlgorithmStrength { Name = "BLAKE3-256", Value = 96, Recommended = true },
        new AlgorithmStrength { Name = "BLAKE3-384", Value = 97, Recommended = true },
        new AlgorithmStrength { Name = "BLAKE3-512", Value = 98, Recommended = true },
        new AlgorithmStrength { Name = "BLAKE3-1024", Value = 99, Recommended = true },
        new AlgorithmStrength { Name = "RIPEMD-128", Value = 30, Recommended = false },
        new AlgorithmStrength { Name = "RIPEMD-160", Value = 50, Recommended = false },
        new AlgorithmStrength { Name = "RIPEMD-256", Value = 65, Recommended = true },
        new AlgorithmStrength { Name = "RIPEMD-320", Value = 70, Recommended = true },
        new AlgorithmStrength { Name = "WHIRLPOOL", Value = 85, Recommended = true },
        new AlgorithmStrength { Name = "SHAKE-128", Value = 80, Recommended = true },
        new AlgorithmStrength { Name = "SHAKE-256", Value = 90, Recommended = true },
        new AlgorithmStrength { Name = "TIGER-128,3", Value = 40, Recommended = false },
        new AlgorithmStrength { Name = "TIGER-160,3", Value = 55, Recommended = false },
        new AlgorithmStrength { Name = "TIGER-192,3", Value = 65, Recommended = true },
        new AlgorithmStrength { Name = "GOST R 34.11-94 Standard of Russian Federation", Value = 50, Recommended = false },
        new AlgorithmStrength { Name = "STREEBOG-256 R 34.11-2012 Russian Federation", Value = 85, Recommended = true },
        new AlgorithmStrength { Name = "STREEBOG-512 R 34.11-2012 Russian Federation", Value = 90, Recommended = true },
        new AlgorithmStrength { Name = "KECCAK-224", Value = 60, Recommended = false },
        new AlgorithmStrength { Name = "KECCAK-256", Value = 85, Recommended = true },
        new AlgorithmStrength { Name = "KECCAK-384", Value = 88, Recommended = true },
        new AlgorithmStrength { Name = "KECCAK-512", Value = 90, Recommended = true },
        new AlgorithmStrength { Name = "SKEIN-256", Value = 70, Recommended = true },
        new AlgorithmStrength { Name = "SKEIN-512", Value = 85, Recommended = true },
        new AlgorithmStrength { Name = "SKEIN-1024", Value = 95, Recommended = true },
        new AlgorithmStrength { Name = "HMACSHA1", Value = 60, Recommended = false },
        new AlgorithmStrength { Name = "HMACMD5", Value = 20, Recommended = false },
        new AlgorithmStrength { Name = "HMACSHA-256", Value = 90, Recommended = true },
        new AlgorithmStrength { Name = "HMACSHA-384", Value = 92, Recommended = true },
        new AlgorithmStrength { Name = "HMACSHA-512", Value = 95, Recommended = true },
        new AlgorithmStrength { Name = "HMACRIPEMD-160", Value = 55, Recommended = false },
        new AlgorithmStrength { Name = "PBKDF2-HASH", Value = 85, Recommended = true },
        new AlgorithmStrength { Name = "SM3 Standard of China Republic", Value = 70, Recommended = true }
    };

        // =================================================================================
        // Get AlgorithmStrength by name
        public static AlgorithmStrength GetAlgorithmStrength(string name)
        {
            foreach (var alg in Algorithms)
            {
                if (string.Equals(alg.Name, name, StringComparison.OrdinalIgnoreCase))
                    return alg;
            }
            return null;
        }

        // =================================================================================
        // Update UI directly from ComboBox selection with standard ProgressBar
        public static void UpdateUIFromCombo(ComboBox combo, Label lblValue, Label lblRecommended, ProgressBar progressBar)
        {
            if (combo?.SelectedItem == null) return;
            var alg = GetAlgorithmStrength(combo.SelectedItem.ToString());
            alg?.ApplyToControls(lblValue, lblRecommended, progressBar);
        }

        // =================================================================================
        // Update UI from ComboBox with any ProgressBar/custom control
        public static void UpdateUIFromCombo(ComboBox combo, Label lblValue, Label lblRecommended, dynamic progressBar)
        {
            if (combo?.SelectedItem == null) return;
            var alg = GetAlgorithmStrength(combo.SelectedItem.ToString());
            alg?.ApplyToControls(lblValue, lblRecommended, progressBar);
        }
    }
}