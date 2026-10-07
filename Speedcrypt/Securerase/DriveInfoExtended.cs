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

namespace Speedcrypt.Securerase
{
    public class DriveInfoExtended
    {
        public string Name { get; set; }
        public char DriveLetter { get; set; }
        public DriveType DriveType { get; set; }
        public int Id { get; set; }
        public string VolumeLabel { get; set; }
        public string DriveFormat { get; set; }
        public long TotalFreeSpace { get; set; }
        public long TotalSize { get; set; }
        public long AvailableFreeSpace { get; set; }
        public HardwareType HardwareType { get; set; }
        public DirectoryInfo RootDirectory { get; set; }
        public string UncPath { get; set; }
    }
}