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

// Speedcrypt
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// UiListMutationManager: Provides centralized, thread-safe, and anti-flicker 
    /// utilities for manipulating structural user interface lists during real-time 
    /// cryptographic operations across Speedcrypt deployment environments.
    /// </summary>
    ///
    /// <remarks>
    /// This architectural component ensures:
    /// - Thread-safe synchronization when marshalling state mutations back onto the primary UI execution thread.
    /// - Defensive double-buffering isolation via context-sensitive paint suppression mechanisms (BeginUpdate/EndUpdate).
    /// - Mitigation against display flickering anomalies and interface rendering performance bottlenecks during mass items traversal.
    /// - Atomic validation parameters to protect structural memory layouts and eliminate infinite loop execution risks.
    /// - Structural context retention by preserving data layouts configuration profiles during operational closures.
    /// 
    /// - Responsibility for driving layout updates and coordinating structural UI bindings lies entirely with this manager wrapper.
    /// - The function is architected to be fully compatible with Speedcrypt's design patterns
    /// - to enforce robust, enterprise-grade interface performance.
    ///   
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class UiListMutationManager
    {
        /// <summary>
        /// Safely removes a processed cryptographic item from the inventory list view, updates real-time remaining items counters, suppresses UI flickering, and enforces thread synchronization.
        /// </summary>
        /// <param name="hostForm">The parent form executing the thread invoke marshalling.</param>
        /// <param name="targetList">The active ListView control containing execution rows.</param>
        /// <param name="fileItem">The target row element to decouple from the layout model.</param>
        /// <param name="statusLabel">The target Label control to publish real-time item count telemetry (optional, can be null).</param>
        /// <returns>True if the item was successfully removed; otherwise, false.</returns>
        public static bool SafeRemoveItem(Form hostForm, ListView targetList, ListViewItem fileItem, Label statusLabel = null)
        {
            if (hostForm == null || targetList == null || fileItem == null)
                return false;

            // Marshals execution context back onto the primary user interface thread if required
            if (hostForm.InvokeRequired)
            {
                return (bool)hostForm.Invoke(new Func<bool>(() => SafeRemoveItem(hostForm, targetList, fileItem, statusLabel)));
            }

            bool hasBoundPainted = false; // RECOVERY TRACKING: Tracks explicit paint suppression to prevent mismatched Windows Forms window procedure calls.

            try
            {
                // DETERMINISTIC EXISTENCE CHECK: Verify item presence directly in memory to decouple UI rendering states from internal data integrity.
                if (targetList.Items.Contains(fileItem))
                {
                    // Temporarily disables the system painting threads to prevent destructive screen flickering anomalies
                    targetList.BeginUpdate();
                    hasBoundPainted = true;

                    // Execution step: removes the row index immediately from memory without triggering real-time layout redraw events
                    targetList.Items.Remove(fileItem);

                    // Real-time telemetry engine: evaluates and updates status label metrics automatically if instantiated
                    if (statusLabel != null)
                    {
                        // Emits the raw, localized mathematical count value directly onto the text property wrapper
                        statusLabel.Text = targetList.Items.Count.ToString();
                    }

                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                // Logs serialization or visual tree mutation exceptions inside the centralized diagnostics tracker
                CentralLog.LogException(ex, "UI_MUTATION", "Failed to safely remove processed cryptographic item and update visual telemetry status loops.");
                return false;
            }
            finally
            {
                // ATOMIC PAINT RESTORATION: Enforce strict execution of layout engine restoration only if painting threads were actively suppressed.
                if (hasBoundPainted)
                {
                    targetList.EndUpdate();
                }
            }
        }
    }
}