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
using System.Windows.Forms;
using System.Runtime.InteropServices;

// Speedcrypt

using Speedcrypt.Exceptionlog;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// SpeedcryptGhost: Internal static helper class to prevent screenshots and
    /// screen recording on sensitive forms, such as encryption/decryption windows.
    /// Combines modern total transparency exclusion (WDA_EXCLUDEFROMCAPTURE) with 
    /// legacy black box masking fallback (WDA_MONITOR).
    ///
    /// 📒 Note: Provides high-level operating system protection; on compatible systems (Windows 10 2004+), 
    /// it renders the interface fully transparent to capture streams, while automatically falling 
    /// back to a solid black rectangle on older environments.
    ///
    /// Designed to maximize protection in Windows Forms while remaining safe,
    /// stable, and deterministic. Developers should be aware of system limitations.
    ///
    /// Responsibility for defining, validating, and using these algorithm parameters
    /// lies entirely with the author.
    /// </remarks>
    internal static class SpeedcryptGhost
    {
        // Windows API constants
        private const int WDA_NONE = 0;
        private const int WDA_MONITOR = 1;
        private const int WDA_EXCLUDEFROMCAPTURE = 17; // Enables total transparency in capture on Windows 10 2004+

        // P/Invoke with SetLastError to allow GetLastWin32Error.
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, int dwAffinity);

        /// <summary>
        /// Try to enable screenshot protection for the provided Form with transparency support.
        /// Returns true when protection was successfully applied or scheduled (HandleCreated).
        /// Returns false if the operation failed or is not supported.
        /// </summary>
        /// <param name="form">Target WinForms Form (must not be null).</param>
        /// <param name="throwOnError">If true, throw on unexpected exceptions (useful for tests).</param>
        /// <returns>bool indicating success or scheduled success.</returns>
        public static bool Enable(Form form, bool throwOnError = false)
        {
            if (form == null)
            {
                var ex = new ArgumentNullException(nameof(form));
                CentralLog.LogException(ex, "SpeedcryptGhost", "Enable called with null form. " + ex.Message);
                if (throwOnError) throw ex;
                return false;
            }

            try
            {
                // If handle is not yet created, attach and return true (action scheduled)
                if (!form.IsHandleCreated)
                {
                    EventHandler handler = null;
                    handler = (sender, args) =>
                    {
                        try
                        {
                            ApplyProtection(form);
                        }
                        finally
                        {
                            try { form.HandleCreated -= handler; } catch { }
                        }
                    };
                    form.HandleCreated += handler;
                    return true;
                }

                // Ensure we execute on UI thread
                if (form.InvokeRequired)
                {
                    form.BeginInvoke(new Action(() => ApplyProtection(form)));
                    return true;
                }

                return ApplyProtection(form);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "SpeedcryptGhost", "Enable exception occurred: " + ex.Message);
                if (throwOnError) throw;
                return false;
            }
        }

        /// <summary>
        /// Try to disable screenshot protection for the provided Form.
        /// Returns true when protection removed successfully.
        /// </summary>
        /// <param name="form">Target WinForms Form (must not be null).</param>
        /// <param name="throwOnError">If true, throw on unexpected exceptions (useful for tests).</param>
        /// <returns>bool indicating success.</returns>
        public static bool Disable(Form form, bool throwOnError = false)
        {
            if (form == null)
            {
                var ex = new ArgumentNullException(nameof(form));
                CentralLog.LogException(ex, "SpeedcryptGhost", "Disable called with null form. " + ex.Message);
                if (throwOnError) throw ex;
                return false;
            }

            try
            {
                if (!form.IsHandleCreated)
                {
                    return true;
                }

                if (form.InvokeRequired)
                {
                    form.BeginInvoke(new Action(() => SetAffinityInternal(form, WDA_NONE)));
                    return true;
                }

                return SetAffinityInternal(form, WDA_NONE);
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "SpeedcryptGhost", "Disable exception occurred: " + ex.Message);
                if (throwOnError) throw;
                return false;
            }
        }

        /// <summary>
        /// Checks whether the API appears to work for the provided window handle.
        /// </summary>
        public static bool IsSupported(Form form)
        {
            if (form == null || !form.IsHandleCreated) return false;

            try
            {
                // First try the modern transparent exclusion affinity
                bool setResult = SetWindowDisplayAffinity(form.Handle, WDA_EXCLUDEFROMCAPTURE);
                if (!setResult)
                {
                    // Fallback probe to classic monitor black rectangle affinity
                    setResult = SetWindowDisplayAffinity(form.Handle, WDA_MONITOR);
                }

                if (!setResult)
                {
                    int err = Marshal.GetLastWin32Error();
                    var ex = new COMException("SetWindowDisplayAffinity failed during support check.", err);
                    CentralLog.LogException(ex, "SpeedcryptGhost", $"IsSupported check failed with Win32Error: {err}. " + ex.Message);
                    return false;
                }

                // Restore original state
                SetWindowDisplayAffinity(form.Handle, WDA_NONE);
                return true;
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "SpeedcryptGhost", "IsSupported exception occurred: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Internal wrapper to handle fallback logic between transparency and black box masking.
        /// </summary>
        private static bool ApplyProtection(Form form)
        {
            // Try Windows 10 2004+ total transparency mode first
            if (SetAffinityInternal(form, WDA_EXCLUDEFROMCAPTURE))
            {
                return true;
            }

            // Fallback to legacy black rectangle window masking
            return SetAffinityInternal(form, WDA_MONITOR);
        }

        /// <summary>
        /// Internal helper that actually calls the Win32 API and logs results on failure.
        /// </summary>
        private static bool SetAffinityInternal(Form form, int affinity)
        {
            if (form == null || !form.IsHandleCreated)
            {
                return false;
            }

            try
            {
                bool result = SetWindowDisplayAffinity(form.Handle, affinity);
                if (!result)
                {
                    int err = Marshal.GetLastWin32Error();
                    var ex = new COMException($"SetWindowDisplayAffinity execution failed for affinity: {affinity}.", err);
                    CentralLog.LogException(ex, "SpeedcryptGhost", $"SetWindowDisplayAffinity failed. Affinity: {affinity}, Win32Error: {err}. " + ex.Message);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                CentralLog.LogException(ex, "SpeedcryptGhost", "SetAffinityInternal exception occurred: " + ex.Message);
                return false;
            }
        }
    }
}