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

using System.Diagnostics;
using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// LifecycleManager: Provides simple application runtime lifecycle utilities for
    /// software execution management. Includes methods to force an immediate software restart,
    /// terminate the current hardware process, and ensure a clean environment bootstrap.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - ForceAtomicApplicationRestart: Safely spawns a clean initialization instance of the current
    ///   executable, followed by an immediate hardware-level termination of the active process.
    /// - All shutdown hooks, layout auto-saves, and backup flush routines are preemptively suppressed.
    /// - Execution operations are simple, deterministic, and suitable for atomic environment recycling.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class LifecycleManager
    {
        /// <summary>
        /// Executes an immediate, atomic application environment recycling sequence.
        /// </summary>
        public static void ForceAtomicApplicationRestart()
        {
            // Spawns a clean bootstrap initialization instance of the software executable environment
            Process.Start(Application.ExecutablePath);

            // Forces an abrupt hardware-level process termination to preemptively suppress layout auto-save or backup flush lifecycle routines
            Process.GetCurrentProcess().Kill();
        }
    }
}