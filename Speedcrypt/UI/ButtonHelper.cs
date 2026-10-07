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

namespace Sppedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// I created this small helper class that is not used in this project,
    /// but it may be useful for any developer who wants to reuse it
    /// in their own projects.
    ///
    /// ButtonHelper: Utility class for WinForms button customization.
    /// Provides methods to configure a button with an image above text
    /// and custom vertical spacing for consistent UI design.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Proper alignment of image and text on buttons
    /// - Configurable vertical spacing between image and text
    /// - Clean rendering using a custom Paint event handler
    /// - Reusable utility for any WinForms project requiring enhanced button presentation
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class ButtonHelper
    {
        /// <summary>
        /// Configures a button to have an image above text with a custom vertical spacing.
        /// </summary>
        /// <param name="button">The Button to configure</param>
        /// <param name="image">The image to display on the button</param>
        /// <param name="text">The text to display under the image</param>
        /// <param name="spacing">Vertical distance in pixels between image and text</param>
        public static void SetImageAboveText(
            System.Windows.Forms.Button button,
            System.Drawing.Image image,
            string text,
            int spacing)
        {
            button.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            button.Text = text;
            button.Image = image;
            button.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;

            // Remove default drawing
            button.Paint += (s, e) =>
            {
                System.Windows.Forms.Button b = (System.Windows.Forms.Button)s;
                e.Graphics.Clear(b.BackColor);

                // Draw image centered horizontally, fixed at top
                if (b.Image != null)
                {
                    int imgX = (b.Width - b.Image.Width) / 2;
                    int imgY = 5; // distance from top edge, can be adjusted
                    e.Graphics.DrawImage(b.Image, imgX, imgY);
                }

                // Draw text centered below image with custom spacing
                if (!string.IsNullOrEmpty(b.Text))
                {
                    int textY = (b.Image != null ? 5 + b.Image.Height + spacing : spacing);
                    System.Drawing.Rectangle textRect =
                        new System.Drawing.Rectangle(0, textY, b.Width, b.Height - textY);

                    System.Windows.Forms.TextRenderer.DrawText(
                        e.Graphics,
                        b.Text,
                        b.Font,
                        textRect,
                        b.ForeColor,
                        System.Windows.Forms.TextFormatFlags.HorizontalCenter
                    );
                }
            };
        }
    }

    // =============================== Usage ==================================
    // ButtonHelper.SetImageAboveText(btnAdd, yourImage, "Add File", 15);
    // ButtonHelper.SetImageAboveText(btnRemove, yourImage2, "Remove File", 20);
}