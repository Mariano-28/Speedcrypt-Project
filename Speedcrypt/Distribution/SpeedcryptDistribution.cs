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

// Speedcrypt
using Speedcrypt.UI;

namespace Speedcrypt.Distribution
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// SpeedcryptDistribution: Evaluates the active execution context at runtime 
    /// to determine the distribution mode (Portable or Setup) and exposes corporate 
    /// configuration parameters governing global application behavior.
    /// </summary>
    ///
    /// <remarks>
    /// This architectural component enforces the following operational specifications:
    /// - Deterministic resolution of the deployment environment during bootstrap initialization.
    /// - Dynamic validation of the current assembly execution path against standard system installation matrices.
    /// - Enforced boundary isolation ensuring portable instances remain uncompromised by local system installations.
    /// - Autonomous fault-tolerant fallback to Portable execution state under anomalous runtime contexts.
    /// - Centralized orchestration of presentation layer metadata, interface titles, and component visibility flags.
    /// - Zero external dependencies on configuration payloads or system registry hives to guarantee absolute portability.
    /// - Lightweight, deterministic implementation fully aligned with the Speedcrypt deployment model.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    using System;
    using System.IO;

    public static class SpeedcryptDistribution
    {
        public static bool IsPortable { get; private set; } = true;
        public static bool IsSetup => !IsPortable;

        public static string MainTitle =>
            IsPortable
            ? ForAllUnits.Ver + " [Portable Edition]"
            : ForAllUnits.Ver;

        public static bool ShowAboutIcon => IsPortable;
        public static bool ShowAboutLabel => IsPortable;

        private const string AppFolderName = "Speedcrypt";
        private const string AppExeName = "Speedcrypt.exe";

        public static string SetupDefaultPath =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppFolderName, AppExeName);

        public static void Initialize()
        {
            try
            {
                string currentExecutionDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string expectedSetupDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppFolderName);

                if (!currentExecutionDirectory.EndsWith(Path.DirectorySeparatorChar.ToString()))
                {
                    currentExecutionDirectory += Path.DirectorySeparatorChar;
                }
                if (!expectedSetupDir.EndsWith(Path.DirectorySeparatorChar.ToString()))
                {
                    expectedSetupDir += Path.DirectorySeparatorChar;
                }

                bool isExecutingFromSetup = currentExecutionDirectory.StartsWith(expectedSetupDir, StringComparison.OrdinalIgnoreCase);
                IsPortable = !isExecutingFromSetup;
            }
            catch
            {
                IsPortable = true;
            }
        }
    }

}
