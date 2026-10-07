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

using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.XMLConfig;

namespace Speedcrypt.Interfaces
{
    /// Summary
    /// Created by Mariano Ortu
    /// 
    /// UiConfigSaver: Infrastructure support class responsible for
    /// saving user interface control states to the XML configuration within Speedcrypt.
    /// 
    /// This class is NOT a cryptographic component.
    /// It does not perform encryption, decryption, hashing, or validation.
    ///
    /// Its sole responsibility is to extract text, selections, and states
    /// from UI elements and persist them as configuration values.
    ///
    /// The saving logic is purely administrative and user-interface-based.
    /// No cryptographic material is generated, processed, or evaluated.
    ///    
    /// Special constraint:
    /// Inputs from UI elements are saved as plain text. Input validation,
    /// sanitization, and handling of sensitive UI data are outside the scope of this class.
    ///
    /// Designed for configuration persistence, lifecycle control,
    /// and internal consistency only.
    ///
    /// Responsibility for algorithm choice, parameterization, integration,
    /// and security validation lies entirely with the author.
    /// </remarks>  
    public static class UiConfigSaver
    {
        public static void SaveTextBoxSetting(string key, TextBox textBox)
        {
            if (!string.IsNullOrWhiteSpace(textBox.Text))
            {
                AppConfigHelper.XmlConfig.SetValue(key, textBox.Text);
            }
        }
        public static void SaveComboBoxSetting(string key, ComboBox comboBox)
        {
            if (comboBox.SelectedItem != null)
            {
                AppConfigHelper.XmlConfig.SetValue(key, comboBox.SelectedItem.ToString());
            }
        }
        public static void SaveCheckBoxSetting(string key, CheckBox checkbox)
        {
            AppConfigHelper.XmlConfig.SetValue(key, checkbox.Checked.ToString());
        }
        public static void SaveRadioButtonSetting(string key, RadioButton radioButton)
        {
            AppConfigHelper.XmlConfig.SetValue(key, radioButton.Checked.ToString());
        }
        public static void SaveAll()
        {
            AppConfigHelper.Save();
        }
    }
}
