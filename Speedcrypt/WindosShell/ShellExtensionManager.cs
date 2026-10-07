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
using System.Threading;
using System.Reflection;
using System.Diagnostics;

namespace Speedcrypt.WindowsShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ShellExtensionManager provides strict and reusable management logic
    /// for registering, unregistering, and synchronizing a dedicated Windows 
    /// Shell Extension DLL within the active operating system environment.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Automation of COM registration and unregistration via localized system regasm.exe.
    /// - Dynamic runtime location discovery for both 32-bit and 64-bit .NET runtime framework paths.
    /// - Structural chaining of registration payloads inside a single cmd process wrapper execution.
    /// - Single-prompt UAC optimization leveraging the native OS runas execution verb sequence.
    /// - Deterministic validation checking for necessary file payloads before triggering elevation prompts.
    /// - Clean termination of existing explorer instances to instantly release locked memory modules.
    /// - Reliance on native Winlogon self-healing behavior to rebuild taskbar instances without window leaks.
    /// - Encapsulation of shell synchronization delays, preventing process racing across target deployments.
    /// - Strict translation of execution anomalies into managed application system exceptions.
    /// - Modular separation between context deployment logic and underlying graphical windows form interfaces.
    ///
    /// - The class is UI-aware only to the extent of calling process start routines for UAC elevation prompts,
    /// -  but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class ShellExtensionManager
    {
        private const string DllName = "SpcShell.dll";

        /// <summary>
        /// Activates the shell extension by unregistering the old version and registering the new one.
        /// Executes both commands in a single elevated session to minimize UAC prompts.
        /// </summary>
        public static void Activate()
        {
            string dllPath = GetDllPath();
            string regasmPath = GetRegasmPath();

            try
            {
                // Execute unregistration and registration sequentially within a single UAC prompt
                ExecuteCombinedElevatedCommands(regasmPath, dllPath);

                // Restart Explorer to apply changes safely
                RestartExplorer();
            }
            catch (Exception ex)
            {
                throw new Exception($"Error during activation: {ex.Message}");
            }
        }

        /// <summary>
        /// Removes the shell extension registration and releases the DLL from Windows memory.
        /// </summary>
        public static void Remove()
        {
            string dllPath = GetDllPath();
            string regasmPath = GetRegasmPath();

            try
            {
                // Remove registration
                ExecuteElevatedCommand(regasmPath, $"\"{dllPath}\" /u");

                // Restart Explorer to release the DLL from Windows memory
                RestartExplorer();
            }
            catch (Exception ex)
            {
                throw new Exception($"Error during removal: {ex.Message}");
            }
        }

        /// <summary>
        /// Automatically determines the current DLL path based on the hosting executable location.
        /// </summary>
        private static string GetDllPath()
        {
            string exePath = Assembly.GetExecutingAssembly().Location;
            string currentDir = Path.GetDirectoryName(exePath);
            string dllPath = Path.Combine(currentDir, DllName);

            if (!File.Exists(dllPath))
            {
                throw new FileNotFoundException($"The DLL '{DllName}' was not found in the application folder.");
            }

            return dllPath;
        }

        /// <summary>
        /// Locates the appropriate regasm.exe path for 64-bit or 32-bit environments.
        /// </summary>
        private static string GetRegasmPath()
        {
            string windir = Environment.GetEnvironmentVariable("windir");
            string regasm64 = Path.Combine(windir, @"Microsoft.NET\Framework64\v4.0.30319\regasm.exe");

            if (File.Exists(regasm64))
            {
                return regasm64;
            }

            string regasm32 = Path.Combine(windir, @"Microsoft.NET\Framework\v4.0.30319\regasm.exe");
            if (File.Exists(regasm32))
            {
                return regasm32;
            }

            throw new FileNotFoundException("Could not locate regasm.exe on this system.");
        }

        /// <summary>
        /// Executes a single regasm command requesting temporary administrator privileges (UAC prompt).
        /// </summary>
        private static void ExecuteElevatedCommand(string file, string arguments)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = file,
                Arguments = arguments,
                WorkingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                Verb = "runas", // Triggers the Windows UAC elevation prompt
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using (Process process = Process.Start(startInfo))
            {
                process?.WaitForExit();
            }
        }

        /// <summary>
        /// Combines unregistration and registration into a single cmd session to prompt UAC only once.
        /// </summary>
        private static void ExecuteCombinedElevatedCommands(string regasmPath, string dllPath)
        {
            // Chaining commands via '&&' ensures the second executes only if the first succeeds
            string combinedArguments = $"/c \"\"{regasmPath}\" \"{dllPath}\" /u && \"{regasmPath}\" \"{dllPath}\" /codebase\"";

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = combinedArguments,
                WorkingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                Verb = "runas", // Single UAC prompt for the entire chain
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(startInfo))
            {
                process?.WaitForExit();
            }
        }

        /// <summary>
        /// Restarts Windows Explorer cleanly. Relies on the OS native Winlogon auto-restart 
        /// behavior to restore the taskbar and desktop without opening accidental File Explorer windows.
        /// </summary>
        private static void RestartExplorer()
        {
            foreach (var process in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    process.Kill();
                    process.WaitForExit();
                }
                catch
                {
                    // Ignore errors if a specific explorer instance cannot be terminated
                }
            }

            // Allow a brief physiological pause for Windows to automatically rebuild the desktop shell.
            // Avoid calling Process.Start("explorer.exe") here, as it forces an unwanted File Explorer window.
            Thread.Sleep(2000);
        }
    }
}