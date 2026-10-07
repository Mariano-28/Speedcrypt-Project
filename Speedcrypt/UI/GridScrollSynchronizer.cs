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

namespace Speedcrypt.UI
{   
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// GridScrollSynchronizer: Encapsulates native grid scroll inputs, keyboard directional vectors, 
    /// and ToolStripButton hardware state boundaries across polymorphic form architectures.
    /// </summary>
    ///
    /// <remarks>
    /// This architecture ensures:
    /// - Isolation of native window messages (WM_VSCROLL, WM_MOUSEWHEEL, WM_KEYDOWN) from the main form footprint.
    /// - Hardcoded performance optimization for the default 44-item selftest grid via a fixed mid-point threshold.
    /// - Seamless adaptation capabilities: while optimized for the 44-item selftest layout, this system can be 
    ///   easily adapted to any custom ListView by altering the threshold calculation logic.
    /// - Dynamic toolstrip hardware synchronization through zero-overhead state tracking execution.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class GridScrollSynchronizer
    {
        private readonly ListView _targetList;
        private readonly ToolStripButton _btnUp;
        private readonly ToolStripButton _btnDown;
        private readonly Action<int> _onStateChanged;
        private ScrollMessageFilter _scrollFilter;
        private int _currentState;

        /// <summary>
        /// Initializes a new instance of the <see cref="GridScrollSynchronizer"/> class with strict hardware ToolStripButton component bindings.
        /// </summary>
        /// <param name="targetList">The target diagnostic list view component containing item collections.</param>
        /// <param name="btnUp">The hardware toolstrip button boundary representing the baseline directional execution.</param>
        /// <param name="btnDown">The hardware toolstrip button boundary representing the terminal directional execution.</param>
        /// <param name="initialState">The baseline directional state tracking identifier.</param>
        /// <param name="onStateChanged">Delegate callback invoked to synchronize the local state tracker variable within the parent form context.</param>
        public GridScrollSynchronizer(ListView targetList, ToolStripButton btnUp, ToolStripButton btnDown, int initialState, Action<int> onStateChanged)
        {
            _targetList = targetList ?? throw new ArgumentNullException(nameof(targetList));
            _btnUp = btnUp ?? throw new ArgumentNullException(nameof(btnUp));
            _btnDown = btnDown ?? throw new ArgumentNullException(nameof(btnDown));
            _currentState = initialState;
            _onStateChanged = onStateChanged ?? throw new ArgumentNullException(nameof(onStateChanged));

            InitializeScrollInterception();
        }

        /// <summary>
        /// Instantiates the internal message filtering subsystem assigned to the target control handle context.
        /// </summary>
        private void InitializeScrollInterception()
        {
            _scrollFilter = new ScrollMessageFilter(_targetList, ExecuteScrollStateEvaluation);
        }

        /// <summary>
        /// Evaluates runtime scroll displacement against deterministic self-test dataset thresholds 
        /// to dynamically synchronize directional state boundaries and hardware toolstrip button states.
        /// </summary>
        private void ExecuteScrollStateEvaluation()
        {
            if (_targetList.Items.Count < 44) return;

            const int FIXED_HALF_THRESHOLD = 22;
            int topIndex = _targetList.TopItem != null ? _targetList.TopItem.Index : 0;

            if (topIndex >= FIXED_HALF_THRESHOLD)
            {
                if (_currentState != 0)
                {
                    _btnDown.Enabled = false;
                    _btnUp.Enabled = true;
                    _currentState = 0;
                    _onStateChanged.Invoke(_currentState);
                }
            }
            else
            {
                if (_currentState != 1)
                {
                    _btnUp.Enabled = false;
                    _btnDown.Enabled = true;
                    _currentState = 1;
                    _onStateChanged.Invoke(_currentState);
                }
            }
        }

        /// <summary>
        /// Internal specialized listener to intercept and route vertical scroll and hardware keyboard events from the native control.
        /// </summary>
        private class ScrollMessageFilter : NativeWindow
        {
            private const int WM_VSCROLL = 0x0115;
            private const int WM_MOUSEWHEEL = 0x020A;
            private const int WM_KEYDOWN = 0x0100;

            private const int VK_UP = 0x26;
            private const int VK_DOWN = 0x28;

            private readonly Action _onScrollDetected;

            public ScrollMessageFilter(ListView targetList, Action onScrollDetected)
            {
                _onScrollDetected = onScrollDetected;
                this.AssignHandle(targetList.Handle);
            }

            protected override void WndProc(ref Message m)
            {
                base.WndProc(ref m);

                if (m.Msg == WM_VSCROLL || m.Msg == WM_MOUSEWHEEL)
                {
                    _onScrollDetected?.Invoke();
                }
                else if (m.Msg == WM_KEYDOWN)
                {
                    int virtualKey = m.WParam.ToInt32();
                    if (virtualKey == VK_UP || virtualKey == VK_DOWN)
                    {
                        _onScrollDetected?.Invoke();
                    }
                }
            }
        }
    }
}