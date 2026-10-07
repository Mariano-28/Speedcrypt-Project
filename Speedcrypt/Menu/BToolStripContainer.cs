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
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Speedcrypt.Menu {
    public class BToolStripContainer : ToolStripContainer {
        public BToolStripContainer() {
            this.TopToolStripPanel.Paint += new PaintEventHandler(TopToolStripPanel_Paint);
            this.TopToolStripPanel.SizeChanged += new EventHandler(TopToolStripPanel_SizeChanged);
        }

        void TopToolStripPanel_SizeChanged(object sender, EventArgs e) {
            this.Invalidate();
        }

        void TopToolStripPanel_Paint(object sender, PaintEventArgs e) {
            Graphics g = e.Graphics;
            var rect = new Rectangle(0, 0, this.Width, this.FindForm().Height);
            using (LinearGradientBrush b = new LinearGradientBrush(
                rect, clsColor.clrHorBG_GrayBlue, clsColor.clrHorBG_White, LinearGradientMode.Horizontal)) {
                g.FillRectangle(b, rect);
            }
        }
    }
}
