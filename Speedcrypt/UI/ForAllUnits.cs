// Speedcrypt software - The Open-Source for encrypt and decrypt files
// Copyright (C) 2023–2026 Mariano Ortu <https://www.sicurpas.it/>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

using System;
using System.IO;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;

// Speedcrypt
using Speedcrypt.Mix;
using Speedcrypt.Nuvola;

namespace Speedcrypt.UI
{
    /// <summary>
    /// Created by Mariano Ortu
    ///
    /// common data required by multiple components of the application.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Centralized storage of constants, status counters, and global buffers.
    /// - Secure storage of sensitive data in _ENC_TEXT (byte[]) and CharArr (char[]),
    ///   which should be cleared immediately after use to minimize memory exposure.
    /// - Provision of application version and executable directory information.
    /// - Maintenance of standard UI message strings for notifications, warnings,
    ///   confirmations, and error messages.
    /// - Includes a reusable reference to OpenFileDialog for file selection.
    /// - Centralized access to images of various sizes (16x16, 22x22, 32x32, 48x48, 64x64)
    ///   for consistent UI representation.
    /// - Fully static, final, and stable container; no computation or logic is performed.
    /// - Designed to minimize duplication and provide a single source of truth for shared
    ///   resources and buffers across the Speedcrypt application.
    ///
    /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
    public static class ForAllUnits
    {
        //===============================
        // Project-wide constants
        //===============================
        // Constants used to avoid typing errors in file names 


        // Global application state variables
        public static int MousCurs = 0,
                          LwIcon = 0,
                          DecSett = 0;

        public static string Ver = "Speedcrypt Ver: " + Assembly.GetExecutingAssembly().GetName().Version.ToString(),
                             DirPath = Path.GetDirectoryName(Application.ExecutablePath),
                             ConfigPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Speedcrypt.config.xml"),
                             KeySize = "K128",
                             BoxInfo = "Speedcrypt Information Message",
                             BoxWrg = "Speedcrypt Warning Message",
                             BoxErr = "Speedcrypt Error Message",
                             BoxSuc = "Speedcrypt Success Message",
                             BoxConf = "Speedcrypt Confirmation Message",
                             HelpFile = "Speedcrypt.chm", // Help File
                             LicenzeTopic = "Speedcrypt_license.htm",
                             AckTopic = "Acknowledgements.htm",
                             FirstStep = "First_steps.htm",
                             Security = "Security.htm",
                             Settings = "Settings.htm",
                             PasswGen = "Password_Generator.htm",
                             ShellExt = "Shell_Extensions.htm",
                             Configfile = "Configuration_File.htm",
                             Emergency = "Emergency.htm",
                             ConfigurationFile = "Speedcrypt.config.xml",
                             BckConfigurationFile = "Speedcrypt.config.xml.Bck";

        // Data buffers for encryption operations
        public static char[] CharArr = null;
        public static DateTime Start = new DateTime();

        // Open File Dialog
        public static OpenFileDialog openFileDialog1;

        //===============================
        // Shared Images
        //===============================
        // Nuvola 16
        public static readonly Image Ledred16 = Image.FromStream(new MemoryStream(Nuvola_16._16_ledred));
        public static readonly Image Ledgreen16 = Image.FromStream(new MemoryStream(Nuvola_16._16_ledgreen));
        public static readonly Image Ledorange16 = Image.FromStream(new MemoryStream(Nuvola_16._16_ledorange));
        public static readonly Image Connectcreating16 = Image.FromStream(new MemoryStream(Nuvola_16._16_connect_creating));
        public static readonly Image Foldercyanopen16 = Image.FromStream(new MemoryStream(Nuvola_16._16_folder_cyan_open));
        public static readonly Image Encrypted16 = Image.FromStream(new MemoryStream(Nuvola_16._16_encrypted));
        public static readonly Image Trash16 = Image.FromStream(new MemoryStream(Nuvola_16._16_edittrash));
        public static readonly Image Buttonup16 = Image.FromStream(new MemoryStream(Nuvola_16._16_player_play));
        public static readonly Image Kpager16 = Image.FromStream(new MemoryStream(Nuvola_16._16_kpager));
        public static readonly Image Filetxt16 = Image.FromStream(new MemoryStream(Nuvola_16._16_txt));
        public static readonly Image Apply16 = Image.FromStream(new MemoryStream(Nuvola_16._16_apply));
        public static readonly Image Help16 = Image.FromStream(new MemoryStream(Nuvola_16._16_help));
        public static readonly Image No16 = Image.FromStream(new MemoryStream(Nuvola_16._16_No));
        public static readonly Image Editcopy16 = Image.FromStream(new MemoryStream(Nuvola_16._16_editcopy));
        public static readonly Image Playrev16 = Image.FromStream(new MemoryStream(Nuvola_16._16_player_rev));
        public static readonly Image Playfwd16 = Image.FromStream(new MemoryStream(Nuvola_16._16_player_fwd));
        public static readonly Image Energy16 = Image.FromStream(new MemoryStream(Nuvola_16._16_energy));
        public static readonly Image Reload16 = Image.FromStream(new MemoryStream(Nuvola_16._16_reload_page));
        public static readonly Image Wbftp16 = Image.FromStream(new MemoryStream(Nuvola_16._16_ftp));

        //Nuvola 22
        public static readonly Image Display22 = Image.FromStream(new MemoryStream(Nuvola_22._22_icons));
        public static readonly Image Timer22 = Image.FromStream(new MemoryStream(Nuvola_22._22_ktimer));
        public static readonly Image Encrypt22 = Image.FromStream(new MemoryStream(Nuvola_22._22_encrypt));
        public static readonly Image Encrypted22 = Image.FromStream(new MemoryStream(Nuvola_22._22_encrypted));
        public static readonly Image Decrypted22 = Image.FromStream(new MemoryStream(Nuvola_22._22_decrypted));
        public static readonly Image Trash22 = Image.FromStream(new MemoryStream(Nuvola_22._22_edittrash));
        public static readonly Image Math22 = Image.FromStream(new MemoryStream(Nuvola_22._22_edu_mathematics));
        public static readonly Image Benck22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kfig));
        public static readonly Image List22 = Image.FromStream(new MemoryStream(Nuvola_22._22_dvi));
        public static readonly Image Notes22 = Image.FromStream(new MemoryStream(Nuvola_22._22_knotes));
        public static readonly Image Hdd22 = Image.FromStream(new MemoryStream(Nuvola_22._22_hdd_unmount));
        public static readonly Image Round22 = Image.FromStream(new MemoryStream(Nuvola_22._22_misc));
        public static readonly Image Ledred22 = Image.FromStream(new MemoryStream(Nuvola_22._22_Ledred));
        public static readonly Image Ledgreen22 = Image.FromStream(new MemoryStream(Nuvola_22._22_ledgreen));
        public static readonly Image Critical22 = Image.FromStream(new MemoryStream(Nuvola_22._22_messagebox_critical));
        public static readonly Image Passwordview22 = Image.FromStream(new MemoryStream(Nuvola_22._22_password));
        public static readonly Image Filesave22 = Image.FromStream(new MemoryStream(Nuvola_22._22_filesave));
        public static readonly Image Empty22 = Image.FromStream(new MemoryStream(Nuvola_22._22_empty));
        public static readonly Image Cancelitem22 = Image.FromStream(new MemoryStream(Nuvola_22._22_cancel));
        public static readonly Image Compfile22 = Image.FromStream(new MemoryStream(Nuvola_22._22_compfile));
        public static readonly Image Fileopen22 = Image.FromStream(new MemoryStream(Nuvola_22._22_fileopen));
        public static readonly Image Folder22 = Image.FromStream(new MemoryStream(Nuvola_22._22_folder));
        public static readonly Image Exit22 = Image.FromStream(new MemoryStream(Nuvola_22._22_exit));
        public static readonly Image Settings22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kcontrol));
        public static readonly Image Energy22 = Image.FromStream(new MemoryStream(Nuvola_22._22_energy));
        public static readonly Image Konsole22 = Image.FromStream(new MemoryStream(Nuvola_22._22_konsole));
        public static readonly Image Configure22 = Image.FromStream(new MemoryStream(Nuvola_22._22_configure));
        public static readonly Image Help22 = Image.FromStream(new MemoryStream(Nuvola_22._22_help));
        public static readonly Image Helpindex22 = Image.FromStream(new MemoryStream(Nuvola_22._22_help_index));
        public static readonly Image Edumisc22 = Image.FromStream(new MemoryStream(Nuvola_22._22_edu_miscellaneous));
        public static readonly Image Lock22 = Image.FromStream(new MemoryStream(Nuvola_22._22_lock));
        public static readonly Image Network22 = Image.FromStream(new MemoryStream(Nuvola_22._22_network));
        public static readonly Image Speedcrypt22 = Image.FromStream(new MemoryStream(Nuvola_22._22_Spcr));
        public static readonly Image Kformula22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kformula_kfo));
        public static readonly Image About22 = Image.FromStream(new MemoryStream(Nuvola_22._22_gnome_apps2));
        public static readonly Image Ascii22 = Image.FromStream(new MemoryStream(Nuvola_22._22_txt));
        public static readonly Image Atlantik22 = Image.FromStream(new MemoryStream(Nuvola_22._22_atlantik));
        public static readonly Image Salt22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kbrunch));
        public static readonly Image Processor22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kcmprocessor));
        public static readonly Image Memory22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kcmmemory));
        public static readonly Image Pakageutil22 = Image.FromStream(new MemoryStream(Nuvola_22._22_package_utilities));
        public static readonly Image Editcopy22 = Image.FromStream(new MemoryStream(Nuvola_22._22_editcopy));
        public static readonly Image Keystretc22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kgpg_key3));
        public static readonly Image Loadfolder22 = Image.FromStream(new MemoryStream(Nuvola_22._22_folder_blue_open));
        public static readonly Image Generatepassw22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kgpg_gen));
        public static readonly Image Keyboard22 = Image.FromStream(new MemoryStream(Nuvola_22._22_keyboard));
        public static readonly Image Exportkey22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kgpg_export));
        public static readonly Image Importkey22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kgpg_import));
        public static readonly Image Apply22 = Image.FromStream(new MemoryStream(Nuvola_22._22_apply));
        public static readonly Image Wbftp22 = Image.FromStream(new MemoryStream(Nuvola_22._22_ftp));
        public static readonly Image Hotkey22 = Image.FromStream(new MemoryStream(Nuvola_22._22_khotkeys));
        public static readonly Image Shell22 = Image.FromStream(new MemoryStream(Nuvola_22._22_kmenuedit));
        public static readonly Image Securedesk22 = Image.FromStream(new MemoryStream(Nuvola_22._22_display));
        public static readonly Image Cut22 = Image.FromStream(new MemoryStream(Nuvola_22._22_cut));
        public static readonly Image Emergency22 = Image.FromStream(new MemoryStream(Nuvola_22._22_ark_options));

        // Nuvola 32
        public static readonly Image Empty32 = Image.FromStream(new MemoryStream(Nuvola_32._32_empty));
        public static readonly Image Addfile32 = Image.FromStream(new MemoryStream(Nuvola_32._32_editcopy));
        public static readonly Image Importfile32 = Image.FromStream(new MemoryStream(Nuvola_32._32_folder_download));
        public static readonly Image Cancelitem32 = Image.FromStream(new MemoryStream(Nuvola_32._32_button_cancel));
        public static readonly Image Filesaveas32 = Image.FromStream(new MemoryStream(Nuvola_32._32_filesaveas));
        public static readonly Image Filesave32 = Image.FromStream(new MemoryStream(Nuvola_32._32_filesave));
        public static readonly Image Settings32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kcontrol));
        public static readonly Image Hdd32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kcmdevice));
        public static readonly Image Keystretc32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kgpg_key3));
        public static readonly Image Pakageutil32 = Image.FromStream(new MemoryStream(Nuvola_32._32_package_utilities));
        public static readonly Image Kpager32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kpager));
        public static readonly Image Newfolder32 = Image.FromStream(new MemoryStream(Nuvola_32._32_fileopen));
        public static readonly Image Loadfolder32 = Image.FromStream(new MemoryStream(Nuvola_32._32_folder_blue_open));
        public static readonly Image Generatepassw32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kgpg_gen));
        public static readonly Image Encrypted32 = Image.FromStream(new MemoryStream(Nuvola_32._32_encrypted));
        public static readonly Image Decrypted32 = Image.FromStream(new MemoryStream(Nuvola_32._32_decrypted));
        public static readonly Image Salt32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kbrunch));
        public static readonly Image Write32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kedit));
        public static readonly Image Hash32 = Image.FromStream(new MemoryStream(Nuvola_32._32_edu_mathematics));
        public static readonly Image Reload32 = Image.FromStream(new MemoryStream(Nuvola_32._32_reload));
        public static readonly Image Suggest32 = Image.FromStream(new MemoryStream(Nuvola_32._32_edu_languages));
        public static readonly Image Trash32 = Image.FromStream(new MemoryStream(Nuvola_32._32_trashcan_empty));
        public static readonly Image Connect32 = Image.FromStream(new MemoryStream(Nuvola_32._32_connect_creating));
        public static readonly Image Restore32 = Image.FromStream(new MemoryStream(Nuvola_32._32_folder_tar));
        public static readonly Image Entropy32 = Image.FromStream(new MemoryStream(Nuvola_32._32_Entropy_system));
        public static readonly Image Identity32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kgpg_identity));
        public static readonly Image Konsole32 = Image.FromStream(new MemoryStream(Nuvola_32._32_konsole));
        public static readonly Image Energy32 = Image.FromStream(new MemoryStream(Nuvola_32._32_energy));
        public static readonly Image Speedcrypt32 = Image.FromStream(new MemoryStream(Nuvola_32._32_Spcr));
        public static readonly Image List32 = Image.FromStream(new MemoryStream(Nuvola_32._32_dvi));
        public static readonly Image Backup32 = Image.FromStream(new MemoryStream(Nuvola_32._32_ark));
        public static readonly Image Configure32 = Image.FromStream(new MemoryStream(Nuvola_32._32_configure));
        public static readonly Image Ascii32 = Image.FromStream(new MemoryStream(Nuvola_32._32_txt));
        public static readonly Image Viewconf32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kgpg_info));
        public static readonly Image Warning32 = Image.FromStream(new MemoryStream(Nuvola_32._32_messagebox_warning));
        public static readonly Image Shell32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kmenuedit));
        public static readonly Image AddShell32 = Image.FromStream(new MemoryStream(Nuvola_32._32_redo));
        public static readonly Image RemoveShell32 = Image.FromStream(new MemoryStream(Nuvola_32._32_undo));
        public static readonly Image Cut32 = Image.FromStream(new MemoryStream(Nuvola_32._32_cut));
        public static readonly Image Emergency32 = Image.FromStream(new MemoryStream(Nuvola_32._32_kgpg_edit));

        // Nuovola 48
        public static readonly Image Power48 = Image.FromStream(new MemoryStream(Nuvola_48._48_power));
        public static readonly Image Find48 = Image.FromStream(new MemoryStream(Nuvola_48._48_xmag));
        public static readonly Image Connect48 = Image.FromStream(new MemoryStream(Nuvola_48._48_connect_creating));
        public static readonly Image Keybindings48 = Image.FromStream(new MemoryStream(Nuvola_48._48_keybindings));
        public static readonly Image Trashfull48 = Image.FromStream(new MemoryStream(Nuvola_48._48_trashcan_full));
        public static readonly Image Pakage48 = Image.FromStream(new MemoryStream(Nuvola_48._48_package_development));
        public static readonly Image Atlantik48 = Image.FromStream(new MemoryStream(Nuvola_48._48_atlantik));
        public static readonly Image keyboard48 = Image.FromStream(new MemoryStream(Nuvola_48._48_keyboard_layout));
        public static readonly Image Speedcrypt48 = Image.FromStream(new MemoryStream(Nuvola_48._48_Spcr));
        public static readonly Image Cpu48 = Image.FromStream(new MemoryStream(Nuvola_48._48_ksim_cpu));
        public static readonly Image Notes48 = Image.FromStream(new MemoryStream(Nuvola_48._48_klipper));

        // Nuovola 64
        public static readonly Image System64 = Image.FromStream(new MemoryStream(Nuvola_64._64_mycomputer));
        public static readonly Image Pendrive64 = Image.FromStream(new MemoryStream(Nuvola_64._64_usbpendrive_unmount));

        // Nuvola 128
        public static readonly Image Pendrive128 = Image.FromStream(new MemoryStream(Nuvola_128._128_usbpendrive_unmount));

        // All images
        public static readonly Image Gradientform = Image.FromStream(new MemoryStream(Allicon.Gradient));
        public static readonly Image Entropy = Image.FromStream(new MemoryStream(Allicon.Entropy_1));
        public static readonly Image Bord = Image.FromStream(new MemoryStream(Allicon.Bord_2));
        public static readonly Image Osicertified = Image.FromStream(new MemoryStream(Allicon.OSI_2));
    }
}