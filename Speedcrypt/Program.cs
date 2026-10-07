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
using System.Threading;
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.Distribution;
using Speedcrypt.UI;

namespace Speedcrypt
{
    internal static class Program
    {
        private static Mutex _mutex;

        [STAThread]
        static void Main(string[] args)
        {
            bool createdNew;

            // Prevent multiple instances of Speedcrypt
            _mutex = new Mutex(true, "Speedcrypt_Global_Mutex", out createdNew);

            if (!createdNew)
                return;

            // Prevent application crashes on exit caused by unobserved asynchronous exceptions
            // left behind by stream failures or interrupted cryptographic operations.
            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (sender, e) =>
            {
                e.SetObserved();
            };

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Distribution Initialization
            SpeedcryptDistribution.Initialize();

            // Entry point handling for external file invocation (Explorer / SendTo / Open With).
            // If command-line arguments are present, they represent files passed by the Windows Shell
            // and are forwarded to the main form for processing (context setup + crypto decision flow).
            FrmMain mainForm = new FrmMain();

            if (args != null && args.Length > 0)
            {
                mainForm.SetShellFiles(args);
            }

            Application.Run(mainForm);
        }
    }
}