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

namespace Speedcrypt.Menu {
    public class clsColor {
        public static Color clrHorBG_GrayBlue = Color.FromArgb(255, 233, 236, 250);
        public static Color clrHorBG_White = Color.FromArgb(255, 244, 247, 252);
        public static Color clrSubmenuBG = Color.FromArgb(255, 240, 240, 240);
        public static Color clrImageMarginBlue = Color.FromArgb(255, 212, 216, 230);
        public static Color clrImageMarginWhite = Color.FromArgb(255, 244, 247, 252);
        public static Color clrImageMarginLine = Color.FromArgb(255, 160, 160, 180);
        public static Color clrSelectedBG_Blue = Color.FromArgb(255, 186, 228, 246);
        public static Color clrSelectedBG_Header_Blue = Color.FromArgb(255, 146, 202, 230);
        public static Color clrSelectedBG_White = Color.FromArgb(255, 241, 248, 251);
        public static Color clrSelectedBG_Border = Color.FromArgb(255, 150, 217, 249);
        public static Color clrSelectedBG_Drop_Blue = Color.FromArgb(255, 139, 195, 225);
        public static Color clrSelectedBG_Drop_Border = Color.FromArgb(255, 48, 127, 177);
        public static Color clrMenuBorder = Color.FromArgb(255, 160, 160, 160);
        public static Color clrCheckBG = Color.FromArgb(255, 206, 237, 250);

        public static Color clrVerBG_GrayBlue = Color.FromArgb(255, 196, 203, 219);
        public static Color clrVerBG_White = Color.FromArgb(255, 250, 250, 253);
        public static Color clrVerBG_Shadow = Color.FromArgb(255, 181, 190, 206);

        public static Color clrToolstripBtnGrad_Blue = Color.FromArgb(255, 129, 192, 224);
        public static Color clrToolstripBtnGrad_White = Color.FromArgb(255, 237, 248, 253);
        public static Color clrToolstripBtn_Border = Color.FromArgb(255, 41, 153, 255);
        public static Color clrToolstripBtnGrad_Blue_Pressed = Color.FromArgb(255, 124, 177, 204);
        public static Color clrToolstripBtnGrad_White_Pressed = Color.FromArgb(255, 228, 245, 252);

        public static void DrawRoundedRectangle(Graphics g, int x , int y ,
            int width, int height, int m_diameter , Color color ) {

            using (Pen pen = new Pen(color)) {
                //Dim g As Graphics
                var BaseRect = new RectangleF(x, y, width, height);
                var ArcRect = new RectangleF(BaseRect.Location, new SizeF(m_diameter, m_diameter));
                //top left Arc
                g.DrawArc(pen, ArcRect, 180, 90);
                g.DrawLine(pen, x + Convert.ToInt32(m_diameter / 2), y, x + width - Convert.ToInt32(m_diameter / 2), y);

                // top right arc
                ArcRect.X = BaseRect.Right - m_diameter;
                g.DrawArc(pen, ArcRect, 270, 90);
                g.DrawLine(pen, x + width, y + Convert.ToInt32(m_diameter / 2), x + width, y + height - Convert.ToInt32(m_diameter / 2));

                // bottom right arc
                ArcRect.Y = BaseRect.Bottom - m_diameter;
                g.DrawArc(pen, ArcRect, 0, 90);
                g.DrawLine(pen, x + Convert.ToInt32(m_diameter / 2), y + height, x + width - Convert.ToInt32(m_diameter / 2), y + height);

                // bottom left arc
                ArcRect.X = BaseRect.Left;
                g.DrawArc(pen, ArcRect, 90, 90);
                g.DrawLine(pen, x, y + Convert.ToInt32(m_diameter / 2), x, y + height - Convert.ToInt32(m_diameter / 2));
            }
        }
    }
}