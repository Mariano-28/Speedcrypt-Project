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
using System.IO;
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.UI;

namespace Speedcrypt.Protect
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// ConfigSanityGuard: Runtime deployment protection component for validating critical 
    /// configuration file presence and enforcing application architectural stability.
    /// </summary>
    ///
    /// <remarks>
    /// This class is part of the Speedcrypt project and belongs to the "Protect" module.
    ///
    /// Purpose:
    /// - Verify the physical presence of critical deployment configuration files on disk.
    /// - Prevent application state inconsistency, unhandled NullReferenceException faults, and structural failures.
    /// - Terminate execution threads cleanly before uninitialized memory allocation occurs.
    ///
    /// Security scope and limits:
    /// - This class implements reasonable and effective sanity safeguards achievable
    ///   in a managed .NET environment to prevent accidental or malicious infrastructure disruption.
    /// - It is designed to preserve application integrity and maintain clean degradation paths,
    ///   not to replace cryptographic binary signature anti-tampering routines.
    /// - No software-based protection is insuperable; this component handles deployment safety
    ///   within realistic technical boundaries.
    ///
    /// Important:
    /// - This class focuses exclusively on layout sanity checks and environmental verification.
    /// - Its role is defensive, deterrent, and damage-limiting, ensuring predictable execution failure paths.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and overall security validation lies entirely with the author.
    /// </remarks>

    public static class ConfigSanityGuard
    {
        // ENTERPRISE ARCHITECTURE: TARGET SPECIFIC SYSTEM CONFIGURATION FILE PATH
        private static readonly string TargetConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Speedcrypt.exe.config");

        /// <summary>
        /// ENFORCES RUNTIME SANITY CHECK BY VERIFYING THE EXISTENCE OF CRITICAL CONFIGURATION NODES.
        /// TERMINATES EXECUTION IMMEDIATELY UPON FAILURE TO PREVENT MEMORY CORRUPTION OR UNHANDLED FAULTS.
        /// </summary>
        public static void VerifyIntegrityOrTerminate()
        {
            // DEFENSIVE GUARD: EVALUATE FILE EXISTENCE ON DISK BEFORE INITIALIZING RUNTIME UTILITIES
            if (File.Exists(TargetConfigPath))
            {
                return;
            }

            // ENTERPRISE ISOLATED NOTIFICATION ROUTINE
            MessageBox.Show("Critical System Error:\n\n" +  "The essential deployment file 'Speedcrypt.exe.config' could not be located.\n" +
                            "Application execution has been halted to prevent unhandled hardware and memory state exceptions.",
                            ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);

            // MILITARY GRADE ENFORCED SHUTDOWN: TERMINATE ALL THREAD PROCESSES IMMEDIATELY
            Environment.Exit(0);
        }
    }
}