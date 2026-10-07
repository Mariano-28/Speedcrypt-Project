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

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    /// CryptoSecurityStrength: Security evaluation class for encryption algorithms.
    /// Provides a centralized representation of the relative strength of
    /// supported cryptographic ciphers used by Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized definition of encryption algorithm security scores
    /// - Clear distinction between recommended and non-recommended ciphers
    /// - Direct integration with UI controls to display security indicators
    /// - Consistent feedback to users regarding the strength of selected encryption methods
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class CryptoSecurityStrength
     {
         // =================================================================================
         // Represents the security level of an encryption algorithm.
         public class AlgorithmStrength
         {
             public string Name { get; set; }        // Algorithm name
             public int Value { get; set; }          // Security score 0-100
             public bool Recommended { get; set; }   // Is algorithm recommended?
             public string Label => Recommended ? "Recommended" : "Not Recommended";

             // =================================================================================
             // Apply values to standard ProgressBar
             public void ApplyToControls(Label lblValue, Label lblRecommended, ProgressBar progressBar)
             {
                 if (lblValue != null)
                 {
                     lblValue.Text = Value.ToString();
                     lblValue.ForeColor = Recommended ? Color.Green : Color.Red;
                 }

                 if (lblRecommended != null)
                 {
                     lblRecommended.Text = Label;
                     lblRecommended.ForeColor = Recommended ? Color.Green : Color.Red;
                 }

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
                     lblRecommended.Text = Label;
                     lblRecommended.ForeColor = Recommended ? Color.DarkGreen : Color.Red;
                 }

                 if (progressBar == null) return;

                 try
                 {
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
                     // Silently ignore if properties are not available
                 }
             }
         }

         // =================================================================================
         // Complete list of encryption algorithms with realistic security scores
         public static readonly List<AlgorithmStrength> Algorithms = new List<AlgorithmStrength>
     {
         new AlgorithmStrength { Name = "AES", Value = 90, Recommended = true },
         new AlgorithmStrength { Name = "PGP", Value = 88, Recommended = true },
         new AlgorithmStrength { Name = "IDEA", Value = 70, Recommended = false },
         new AlgorithmStrength { Name = "GOST", Value = 75, Recommended = false },
         new AlgorithmStrength { Name = "AES-GCM", Value = 98, Recommended = true },
         new AlgorithmStrength { Name = "SERPENT", Value = 95, Recommended = true },
         new AlgorithmStrength { Name = "TWOFISH", Value = 94, Recommended = true },
         new AlgorithmStrength { Name = "CAMELLIA", Value = 93, Recommended = true },
         new AlgorithmStrength { Name = "THREEFISH", Value = 91, Recommended = true },
         new AlgorithmStrength { Name = "KUZNYECHIK", Value = 92, Recommended = true },
         new AlgorithmStrength { Name = "XCHACHA20-POLY1305", Value = 99, Recommended = true }
     };

         // =================================================================================
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
         public static void UpdateUIFromCombo(ComboBox combo, Label lblValue, Label lblRecommended, ProgressBar progressBar)
         {
             if (combo?.SelectedItem == null) return;

             var alg = GetAlgorithmStrength(combo.SelectedItem.ToString());
             alg?.ApplyToControls(lblValue, lblRecommended, progressBar);
         }

         // =================================================================================
         public static void UpdateUIFromCombo(ComboBox combo, Label lblValue, Label lblRecommended, dynamic progressBar)
         {
             if (combo?.SelectedItem == null) return;

             var alg = GetAlgorithmStrength(combo.SelectedItem.ToString());
             alg?.ApplyToControls(lblValue, lblRecommended, progressBar);
         }
     }
}