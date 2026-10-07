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
using IWshRuntimeLibrary;

namespace Speedcrypt.WindowsShell
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// SendToSpeedcrypt provides strict and reusable management logic
    /// for creating, removing, and verifying the presence of an application 
    /// shortcut link inside the standard Windows SendTo user folder.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Deterministic resolution of the user-specific profile SendTo system directory path.
    /// - Dynamic programmatic creation of shell shortcuts using the COM Windows Script Host object layer.
    /// - Explicit mapping of application path, description, and executing working folder parameters.
    /// - Safe validation checks regarding shortcut existence before execution operations.
    /// - Automated generation of missing target directory branches during execution setup routines.
    /// - Clean deletion of shell shortcut files without altering surrounding operating system links.
    /// - Absolute isolation of deployment parameters using localized state tracking fields.
    /// - Complete prevention of structural code duplication across separate configuration layout modules.
    /// - Clean integration behavior leveraging standard IO operations and native shell libraries.
    ///
    /// - The class is UI-aware only to the extent of defining shell links for context menus,
    /// -  but contains no unrelated application logic, ensuring modularity and reusability.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class SendToSpeedcrypt
    {
        private readonly string _appName;
        private readonly string _exePath;

        private readonly string _sendToFolder;
        private readonly string _shortcutPath;
        public SendToSpeedcrypt(string appName, string exePath)
        {
            _appName = appName;
            _exePath = exePath;

            _sendToFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\SendTo"
            );

            _shortcutPath = Path.Combine(_sendToFolder, $"{_appName}.lnk");
        }
        public bool IsEnabled()
        {
            return System.IO.File.Exists(_shortcutPath);
        }
        public void Enable()
        {
            if (!Directory.Exists(_sendToFolder))
                Directory.CreateDirectory(_sendToFolder);

            CreateShortcut();
        }
        public void Disable()
        {
            if (System.IO.File.Exists(_shortcutPath))
                System.IO.File.Delete(_shortcutPath);
        }
        private void CreateShortcut()
        {
            WshShell shell = new WshShell();
            IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(_shortcutPath);

            shortcut.TargetPath = _exePath;
            shortcut.WorkingDirectory = Path.GetDirectoryName(_exePath);
            shortcut.Description = _appName;
            shortcut.Save();
        }
    }
}