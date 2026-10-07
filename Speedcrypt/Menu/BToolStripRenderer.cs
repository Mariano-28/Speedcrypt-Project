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

using System.Drawing;
using System.Windows.Forms;
using System.Drawing.Drawing2D;

namespace Speedcrypt.Menu {
    public class BToolStripRenderer : ToolStripProfessionalRenderer {
        
        // Render custom background gradient
        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e) {
            base.OnRenderToolStripBackground(e);

            using (var b = new LinearGradientBrush(e.AffectedBounds,
                clsColor.clrVerBG_White, clsColor.clrVerBG_GrayBlue, LinearGradientMode.Vertical)) {
                using (var shadow = new SolidBrush(clsColor.clrVerBG_Shadow)) {
                    var rect = new Rectangle(0, e.ToolStrip.Height - 2, e.ToolStrip.Width, 1);
                    e.Graphics.FillRectangle(b, e.AffectedBounds);
                    e.Graphics.FillRectangle(shadow, rect);
                }
            }
        }

        // Render button selected and pressed state
        protected override void OnRenderButtonBackground(ToolStripItemRenderEventArgs e) {
            base.OnRenderButtonBackground(e);
            var rectBorder = new Rectangle(0, 0, e.Item.Width - 1, e.Item.Height - 1);
            var rect = new Rectangle(1, 1, e.Item.Width - 2, e.Item.Height - 2);

            if (e.Item.Selected == true || (e.Item as ToolStripButton).Checked) {
                using (var b = new LinearGradientBrush(rect, clsColor.clrToolstripBtnGrad_White,
                    clsColor.clrToolstripBtnGrad_Blue, LinearGradientMode.Vertical)) {
                    using (var b2 = new SolidBrush(clsColor.clrToolstripBtn_Border)) {
                        e.Graphics.FillRectangle(b2, rectBorder);
                        e.Graphics.FillRectangle(b, rect);
                    }
                }
            }
            if (e.Item.Pressed) {
                using (var b = new LinearGradientBrush(rect, clsColor.clrToolstripBtnGrad_White_Pressed,
                    clsColor.clrToolstripBtnGrad_Blue_Pressed, LinearGradientMode.Vertical)) {
                    using (var b2 = new SolidBrush(clsColor.clrToolstripBtn_Border)) {
                        e.Graphics.FillRectangle(b2, rectBorder);
                        e.Graphics.FillRectangle(b, rect);
                    }
                }
            }
        }
    }
}