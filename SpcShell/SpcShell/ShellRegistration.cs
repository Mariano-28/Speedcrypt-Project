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
// https://www.gnu.org/licenses/gpl-3.0.html

using System;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace SpcShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ShellRegistration provides strict and reusable management logic
    /// for installing and removing configuration endpoints for the context menu handler 
    /// across target Windows Registry paths.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Automation of registry deployment operations under LocalMachine and ClassesRoot pathways.
    /// - Dynamic recording of installation folder anchors inferred from assembly location scans.
    /// - Activation of COM approval permissions inside the Windows Shell Extension tracking nodes.
    /// - Simultaneous registration mapping for both independent file systems and directory nodes.
    /// - Sequential system rollbacks purging specialized context layout entries cleanly.
    /// - Defensive validation constraints throwing explicit exceptions upon failed key provisioning.
    /// - Failure-tolerant fallback traps isolating non-critical registry erasure processes.
    /// - Strict isolation of target variables avoiding variable pollution inside deployment workflows.
    /// - Prevention of configuration duplication across detached installation setup layers.
    ///
    /// - The class is UI-aware only to the extent of defining shell context shortcuts in registry paths,
    /// -  but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for this C# implementation, registry automation logic,
    /// architectural integration, and behavioral correctness lies entirely with the author.
    /// </remarks>

    [ComVisible(false)]
    public static class ShellRegistration
    {
        private const string ContextMenuGuid =
            "{D6E693C4-0A4F-4E54-9E87-8F53E3E7D2A1}";

        private const string ApprovedKey =
            @"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";

        private const string InstallKey =
            @"Software\Speedcrypt";

        private const string AllFilesKey =
            @"*\shellex\ContextMenuHandlers\Speedcrypt";

        private const string DirectoryKey =
            @"Directory\shellex\ContextMenuHandlers\Speedcrypt";

        public static void Register()
        {
            RegisterInstallPath();
            RegisterApproved();
            RegisterHandler(AllFilesKey);
            RegisterHandler(DirectoryKey);
        }
        public static void Unregister()
        {
            RemoveKey(AllFilesKey);
            RemoveKey(DirectoryKey);
            RemoveApproved();

            try
            {
                Registry.LocalMachine.DeleteSubKeyTree(InstallKey, false);
            }
            catch { }
        }
        private static void RegisterInstallPath()
        {
            string dllPath = typeof(ShellRegistration).Assembly.Location;
            string folder = System.IO.Path.GetDirectoryName(dllPath);

            using (var key = Registry.LocalMachine.CreateSubKey(InstallKey))
            {
                if (key == null)
                    throw new System.InvalidOperationException("Cannot open install registry key.");

                key.SetValue("InstallPath", folder, RegistryValueKind.String);
            }
        }
        private static void RegisterApproved()
        {
            using (RegistryKey key =
                Registry.LocalMachine.CreateSubKey(ApprovedKey))
            {
                if (key == null)
                    throw new InvalidOperationException("Cannot open shell approved registry.");

                key.SetValue(ContextMenuGuid, "Speedcrypt Shell Extension", RegistryValueKind.String);
            }
        }
        private static void RegisterHandler(string path)
        {
            using (RegistryKey key =
                Registry.ClassesRoot.CreateSubKey(path))
            {
                if (key == null)
                    throw new InvalidOperationException("Cannot create context menu handler.");

                key.SetValue(null, ContextMenuGuid, RegistryValueKind.String);
            }
        }
        private static void RemoveApproved()
        {
            using (RegistryKey key =
                Registry.LocalMachine.OpenSubKey(ApprovedKey, true))
            {
                if (key == null) return;

                key.DeleteValue(ContextMenuGuid, false);
            }
        }
        private static void RemoveKey(string path)
        {
            try
            {
                Registry.ClassesRoot.DeleteSubKeyTree(path, false);
            }
            catch { }
        }
    }
}