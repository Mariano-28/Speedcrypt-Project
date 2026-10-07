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

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// DirtyTracker: Tracks changes in interactive UI components such as ListViews
    /// and enables/disables a target Save button accordingly.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized tracking of "dirty" state (unsaved changes) in UI lists or forms
    /// - Automatic enabling of the associated Save button when data is modified
    /// - Automatic disabling of the Save button once data is saved
    /// - Deterministic behavior: no side effects, minimal overhead
    /// - Simple API: MarkDirty(), MarkSaved(), IsDirty()
    /// - Safe integration into Windows Forms applications
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class DirtyTracker
    {
        // Reference to the button that will be enabled/disabled
        private System.Windows.Forms.Button _btnSave;

        // Internal flag to track if data has changed
        private bool _isDirty = false;

        // =================================================================================
        // Constructor: assigns the target Save button and disables it initially
        // =================================================================================
        public DirtyTracker(System.Windows.Forms.Button btnSave)
        {
            _btnSave = btnSave;
            _btnSave.Enabled = false;
        }

        // =================================================================================
        // Mark the state as dirty (data changed)
        // Enables the associated Save button if not already enabled
        // =================================================================================
        public void MarkDirty()
        {
            if (!_isDirty)
            {
                _isDirty = true;
                _btnSave.Enabled = true;
            }
        }

        // =================================================================================
        // Reset the state to saved (data saved)
        // Disables the Save button
        // =================================================================================
        public void MarkSaved()
        {
            _isDirty = false;
            _btnSave.Enabled = false;
        }

        // =================================================================================
        // Optional helper: check if the data is currently dirty
        // =================================================================================
        public bool IsDirty()
        {
            return _isDirty;
        }
    }
}