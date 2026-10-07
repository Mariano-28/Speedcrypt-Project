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

using System.IO;
using System.Drawing;
using System.Windows.Forms;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// FolderContentLoader: Provides a method to synchronously load all files
    /// from a specified folder into a ListView with their associated icons.
    /// Designed for stable and visually coherent UI integration in Speedcrypt.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - LoadFilesToListViewWithIcons: Clears the target ListView and ImageList before
    ///   loading, then iterates through all files in the folder, adding each with
    ///   its original icon and storing the full path in the item's Tag property.
    /// - GetFileIcon: Extracts the original system icon associated with the file,
    ///   ensuring visual consistency in the UI.
    /// - Handles non-existent folders gracefully by exiting without error.
    /// - Fully synchronous operation to maintain predictable UI state.
    /// - No cryptographic data is processed; this class focuses purely on file display
    ///   and UI interaction.
    /// 
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public class FolderContentLoader
    {
        public static void LoadFilesToListViewWithIcons(string folderPath, ListView listView, ImageList imageList)
        {
            if (!Directory.Exists(folderPath)) return;

            listView.Items.Clear();
            imageList.Images.Clear(); // Clear the ImageList before adding new images

            // Load all files
            string[] files = Directory.GetFiles(folderPath);
            foreach (string file in files)
            {
                // Get the original file icon
                string fileName = Path.GetFileName(file);
                Icon fileIcon = GetFileIcon(file);

                // Add the icon to the ImageList
                imageList.Images.Add(fileIcon);

                // Add an item to the ListView with the name and icon
                ListViewItem item = new ListViewItem(fileName, imageList.Images.Count - 1)
                {
                    Tag = file // Save the file path in the item
                };
                listView.Items.Add(item);
            }
        }

        // Method to get the original file icon
         private static Icon GetFileIcon(string filePath)
         {
             return Icon.ExtractAssociatedIcon(filePath);
         }        
    } 
}