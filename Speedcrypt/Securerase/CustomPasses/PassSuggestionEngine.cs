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

using System.Collections.Generic;

namespace Speedcrypt.Securerase.CustomPasses
{
    // PassSuggestionEngine - Secure Pass Suggestion Engine Class
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
    /// PassSuggestionEngine: Enterprise-grade intelligence component delivering optimized, pre-defined overwrite execution sequences.
    /// Formulates balanced data sanitization matrices combining high-entropy cryptographic sweeps with uniform block saturation resets.
    /// Fully integrated into the Speedcrypt framework to supply instant reference baselines for runtime user selection configurations.
    /// </summary>
    ///
    /// <remarks>
    /// This architecture ensures:
    /// - Static evaluation suggestions delivering a standard 5-pass sequence engineered to optimize physical hardware sector destruction.
    /// - Balanced structural distribution incorporating multiple cryptographic pseudorandom noise sweeps combined with uniform bit sweeping profiles.
    /// - Surface saturation neutralizations by combining consecutive zero-bit (0x00) and one-bit (0xFF) sweeps to compound target residual noise density.
    /// - Total logical isolation acting as an instant execution fallback framework without triggering interface parsing stall cycles.
    /// - Direct native inter-op mapping compliance ready to feed standalone utility interfaces or encapsulated compilation layers.
    ///
    /// Responsibility for this C# production implementation, structural design, integration layer, and runtime validation 
    /// lies entirely with the author.
    /// </remarks>

    //*************************************************************************************

    // NOTE FOR INTEGRATION:
    // PassSuggestionEngine originates from Mariano Ortu's "Custom Erase Algorithm" project:
    // - Technical documentation: https://www.sicurpas.it/my-algorithms.html
    // - Official GitHub repository: https://github.com/Mariano-28/CustomEraseAlgorithm
    // - SourceForge download: https://sourceforge.net/projects/custom-erase-algorithm/
    //
    // Integrated into Speedcrypt SecureErase module for advanced file deletion.
    // All original licensing, authorship, and functionality fully preserved.
    public static class PassSuggestionEngine
    {
        /// <summary>
        /// Returns a pre-defined list of suggested overwrite passes.
        /// This list combines cryptographically secure random noise sweeps with unified block patterns to optimize data sanitization.
        /// </summary>
        public static List<string> GetSuggestedAlgorithm()
        {
            // The suggested sequence is designed to maximize physical medium entropy and guarantee irreversible file erasure:
            // - Random: Executes a full cryptographic entropy overwrite pass to distort baseline magnetic residual signals.
            // - Zero(0x00): Formats block memory layouts with homogeneous zero bit segments to reset surface saturation levels.
            // - One(0xFF): Enforces an alternative complete single bit pattern sweep to disrupt dual layer state persistence.
            // - Repetition of Random: Appends multiple final pseudorandom sweeps to compound noise density and eliminate remnant tracking vectors.
            return new List<string>
        {
            "Random",
            "Zero(0x00)",
            "One(0xFF)",
            "Random",
            "Random"
        };

        }
    }
}