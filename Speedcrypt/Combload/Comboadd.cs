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

namespace Speedcrypt.Combload
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Comboadd: Helper class for managing ComboBox items with enums and integer values.
    /// </summary>
    ///
    /// <remarks>
    /// This static class provides utility methods to:
    /// - Retrieve the index of a value in a ComboBox or enum
    /// - Populate ComboBox with a range or all values from an enum
    /// - Safely set selected index in ComboBox
    ///
    /// The conceptual approach is original, but inspired by general .NET patterns
    /// for enum and ComboBox manipulation found in community examples online.
    ///
    /// Technical note:
    /// - Methods ensure type-safety when converting between enums and integer values
    /// - LoadEnumValues uses DataSource for full enum binding
    /// - SetSelectedIndex prevents potential exceptions from invalid indices
    /// - Designed for Speedcrypt UI consistency and reusability
    /// 
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class Comboadd
    {
        public static int IndexFromValue(int Value, ComboBox Target)
        {
            int ct = -1;
            foreach (var val in Target.Items)
            {
                ct++;
                if (val.Equals(Value))
                    return ct;
            }
            return -1;
        }
        public static int IndexFromValue(int Value, Type EnumType)
        {
            int ct = -1;
            foreach (var val in Enum.GetValues(EnumType))
            {
                ct++;
                if ((int)val == Value)
                    return ct;
            }
            return -1;
        }
        public static int IndexFromValue(int Value, Type EnumType, ComboBox Target)
        {
            int ct = -1;
            var match = Enum.GetName(EnumType, Value);

            foreach (var val in Target.Items)
            {
                ct++;
                if (val.ToString().Equals(match))
                    return ct;
            }
            return -1;
        }
        public static void AddEnumRange(ComboBox Target, Type EnumType, int Start, int End)
        {
            Target.Items.Clear();

            foreach (var val in Enum.GetValues(EnumType))
            {
                if ((int)val >= Start && (int)val <= End)
                    Target.Items.Add(Enum.GetName(EnumType, val));
            }
        }
        public static string[] GetEnumNames(ComboBox Target, Type EnumType)
        {
            return Enum.GetNames(EnumType);
        }
        public static Array GetEnumValues(ComboBox Target, Type EnumType)
        {
            return Enum.GetValues(EnumType);
        }
        public static void LoadEnumValues(ComboBox Target, Type EnumType)
        {
            Target.DataSource = Enum.GetValues(EnumType);
        }
        public static void SetSelectedIndex(ComboBox Target, int Index)
        {
            try
            {
                // necessary because bug in .net throws null exception
                if (Target.Items.Count > Index)
                    Target.SelectedIndex = Index;
            }
            catch { }
        }
    }
}