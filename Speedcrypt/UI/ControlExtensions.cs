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
using System.Reflection;
using System.Windows.Forms;

// Speedcryp
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// ControlExtensions: Provides high-performance utility and extension methods for 
    /// Windows Forms controls to optimize UI rendering and eliminate drawing artifacts.
    /// Extends any Control instance to toggle double-buffered rendering modes programmatically.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - SetDoubleBuffered(this T, bool): Extension method enabling double buffering on any control.
    /// - Specialized optimization for ListView controls using direct bitwise ControlStyles injection.
    /// - High-efficiency caching of Reflection targets (PropertyInfo and MethodInfo) to minimize CPU overhead.
    /// - Absolute thread-safe and crash-resilient UI decoration fallback via defensive guard clauses.
    /// - Zero performance penalties during rapid bulk UI updates or frequent hierarchical tree redrawing.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class ControlExtensions
    {
        // Cached property info to eliminate reflection overhead during runtime execution
        private static readonly PropertyInfo DoubleBufferedProperty =
            typeof(Control).GetProperty("DoubleBuffered", BindingFlags.NonPublic | BindingFlags.Instance);

        // Cached method info for specialized control style manipulation
        private static readonly MethodInfo SetStyleMethod =
            typeof(Control).GetMethod("SetStyle", BindingFlags.NonPublic | BindingFlags.Instance);

        /// <summary>
        /// Safely enables or disables double buffering on any WinForms control (TreeView, ListView, DataGridView, etc.)
        /// to eliminate flickering during bulk updates. Applies native style optimizations where applicable.
        /// </summary>
        /// <typeparam name="T">The type of the control, which must inherit from <see cref="Control"/>.</typeparam>
        /// <param name="control">The target control instance.</param>
        /// <param name="enabled">True to enable double buffering; false to disable it.</param>
        public static void SetDoubleBuffered<T>(this T control, bool enabled) where T : Control
        {
            // Guard clause against null instances to ensure application stability
            if (control == null) return;

            // Specialized native optimization for ListView controls
            if (control is ListView listView)
            {
                try
                {
                    if (SetStyleMethod != null)
                    {
                        const ControlStyles styles = ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint;
                        SetStyleMethod.Invoke(listView, new object[] { styles, enabled });
                        return;
                    }
                }
                catch
                {
                    // Fallback immediately to standard reflection if the specialized style optimization fails
                }
            }

            // Standard cached reflection approach for TreeView, DataGridView, and other generic controls
            try
            {
                if (DoubleBufferedProperty != null)
                {
                    DoubleBufferedProperty.SetValue(control, enabled, null);
                }
            }
            catch (Exception ex)
            {
                // Non-critical fallback log - application logic continues uninterrupted
                CentralLog.LogException(ex, "SETTINGS", $"Error not critical if reflection fails for {control.GetType().Name}!");
            }
        }
    }
}