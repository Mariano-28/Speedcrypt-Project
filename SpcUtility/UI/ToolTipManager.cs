/// Speedcrypt software - The Open-Source for encrypt and decrypt files
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

using System.Windows.Forms;

namespace SpcUtility.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ToolTipManager: Encapsulates a shared ToolTip instance for consistent UI hints
    /// across Speedcrypt forms. Provides methods to assign and remove tooltips on
    /// standard WinForms controls while maintaining uniform timing and styling.
    /// </summary>
    ///
    /// <remarks>
    /// Features:
    /// - Single ToolTip instance to minimize resource usage and ensure uniform behavior.
    /// - Configured delays: AutoPopDelay = 6000ms, InitialDelay = 500ms, ReshowDelay = 200ms.
    /// - Always visible when required, with Info icon and "Speedcrypt Tip" title.
    /// - Assign tooltips using Set(control, message) and remove using Clear(control).
    /// - Designed to enhance user guidance without introducing side effects or state complexity.
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class ToolTipManager
    {
        private readonly ToolTip _toolTip;

        // Constructor: creates a new ToolTip instance with shared style
        public ToolTipManager()
        {
            _toolTip = new ToolTip
            {
                AutoPopDelay = 6000,
                InitialDelay = 500,
                ReshowDelay = 200,
                ShowAlways = true,
                ToolTipIcon = ToolTipIcon.Info,
                ToolTipTitle = "Speedcrypt Tip"
            };
        }

        // Assigns a tooltip to the specified control
        public void Set(Control control, string message)
        {
            if (control == null || string.IsNullOrWhiteSpace(message))
                return;

            _toolTip.SetToolTip(control, message);
        }

        // Removes a tooltip from the specified control
        public void Clear(Control control)
        {
            if (control != null)
                _toolTip.SetToolTip(control, null);
        }
    }
}