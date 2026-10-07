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
using System.IO;
using System.Windows.Forms;

// SpcUtility
using SpcUtility.UI;

namespace SpcUtility
{
    internal static class Program
    {
        /// <summary>
        /// Punto di ingresso principale dell'applicazione.
        /// </summary>
        /// 

        [STAThread]
        static void Main()
        {
           
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                Application.Run(new FrmMain());
            }
            catch (Exception ex)
            {
                // Log the exception to a file in the application directory
                try
                {
                    string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StartupErrors.log");
                    string logEntry = $"[{DateTime.Now}] SpcUtility Critical startup Error: {ex}\r\n";
                    File.AppendAllText(logPath, logEntry);
                }
                catch
                {
                    // If logging fails, silently ignore to avoid crashing
                }

                // Show error message to the user
                MessageBox.Show("A critical error occurred during startup:" + ex.Message, ForAllUnits.Error, MessageBoxButtons.OK,  MessageBoxIcon.Error);
            }
        }
    }
}