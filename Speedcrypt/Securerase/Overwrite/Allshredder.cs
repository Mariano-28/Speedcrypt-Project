//SecureDel software - The Open-Source for secure file deletion
// Copyright (C) 2024-2026 Mariano Ortu <https://www.sicurpas.it/>
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
using System.IO;
using System.Windows.Forms;
using System.Collections.Generic;

using Speedcrypt.Securerase;
using Speedcrypt.Exceptionlog;
using Speedcrypt.Securerase.NSACSS9;
using Speedcrypt.Securerase.Schneier;
using Speedcrypt.Securerase.NSACSS12;
using Speedcrypt.Securerase.NIST800_88;
using Speedcrypt.Securerase.GermanVSITR;
using Speedcrypt.Securerase.CustomPasses;
using Speedcrypt.Securerase.BritishHMGIS5;
using Speedcrypt.Securerase.RCMPTSSITOPSII;

namespace Speedcrypt.Secureerase.Overwrite
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Allshredder: Centralized secure file erasure dispatcher supporting multiple algorithms.
    /// Designed for Speedcrypt framework, integrating centralized logging on critical IO failures.
    /// </summary>
    ///
    /// <remarks>
    /// This class ensures:
    /// - Dispatch to multiple secure erase algorithms
    /// - No alteration of underlying erase logic
    /// - Centralized logging through Speedcrypt CentralLog
    /// - Any IO or operational failure is treated as critical
    ///
   /// Responsibility for integration, testing, and any minor adaptation within
    /// lies entirely with the author.
    /// </remarks>
     public class Allshredder
     {
         private static void ValidateFile(string filePath)
         {
             if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                 throw new FileNotFoundException("File not found.", filePath);
         }
         private static string ExecuteDelete(FileInfo fi, OverwriteAlgorithm algorithm, string logTag)
         {
             try
             {
                 ValidateFile(fi.FullName);
                 fi.Delete(algorithm);
                 return fi.FullName;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, $"Allshredder - {logTag}", $"Failed to securely erase file: {fi.FullName}");
                 throw;
             }
         }
         public static string Qckshr(string filePath) => ExecuteDelete(new FileInfo(filePath), OverwriteAlgorithm.Quick, "Quick 1 Pass");
         public static string Rndshr(string filePath) => ExecuteDelete(new FileInfo(filePath), OverwriteAlgorithm.Random, "Random 1 Pass");
         public static string Do3shr(string filePath) => ExecuteDelete(new FileInfo(filePath), OverwriteAlgorithm.DoD_3, "DoD 3 Passes");
         public static string Do7shr(string filePath) => ExecuteDelete(new FileInfo(filePath), OverwriteAlgorithm.DoD_7, "DoD 7 Passes");
         public static string Gtmshr(string filePath) => ExecuteDelete(new FileInfo(filePath), OverwriteAlgorithm.Gutmann, "Gutmann 35 Passes");
         public static string Schnshr(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 SchneierEraser.Schneier7Pass(filePath);
                 return filePath;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - Schneier 7 Passes", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string Germanshr(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 GermanVsitrEraser.Erase(filePath);
                 return filePath;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - German VSITR 7 Passes", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string RCMPshr(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 RCMPTSSIT.RCMP_TSSIT_OPS_II(filePath);
                 return filePath;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - RCMP TSSIT OPS-II", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string Britishshr(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 HmgIs5Eraser.Erase(filePath);
                 return filePath;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - British HMG IS5", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string Customshr(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 CustomPassType[] customPass = { CustomPassType.Zeros, CustomPassType.Random, CustomPassType.Ones, CustomPassType.Random, CustomPassType.Zeros };
                 CustomEraser.SecureErase(filePath, customPass);
                 return filePath;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - Custom Classic Passes", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string Customusershr(string filePath, ListBox listCustom)
         {
             try
             {
                 ValidateFile(filePath);
                 List<CustomPassType> customPasses = new List<CustomPassType>();
                 foreach (var item in listCustom.Items)
                 {
                     if (Enum.TryParse(item.ToString(), true, out CustomPassType pass))
                         customPasses.Add(pass);
                 }

                 if (customPasses.Count > 0)
                     CustomEraser.SecureErase(filePath, customPasses.ToArray());

                 return filePath;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - Custom User-defined Passes", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string NSACSS9Shr(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 return NSACSS9PassEraser.SecureErase(filePath);
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - NSA/CSS 9 Pass Standard", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string NSACSS12Shr(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 return NSACSS12PassEraser.SecureErase(filePath).ToString();
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - NSA/CSS 12 Pass Standard", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string ScrDel(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 Delete.DeleteFileWithoutDriveDetection(filePath);
                 return filePath;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - Secure Delete File", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string ScrDelfold(string folderPath)
         {
             try
             {
                 ValidateFile(folderPath);
                 Delete.DeleteDirectoryWithoutDriveDetection(folderPath, true);
                 return folderPath;
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - Secure Delete Folder", $"Failed to securely erase folder: {folderPath}");
                 throw;
             }
         }

         public static string NistClearShr(string filePath)
         {
             try
             {
                 ValidateFile(filePath);
                 return NistClearMethod.ClearFile(filePath).ToString();
             }
             catch (IOException ex)
             {
                 CentralLog.LogException(ex, "Allshredder - NIST 800-88 Secure Erase", $"Failed to securely erase file: {filePath}");
                 throw;
             }
         }
         public static string Execute(string algorithmName, string filePath, bool isCustomClassic, bool isCustomUser, ListBox listCustom)
         {
             switch (algorithmName)
             {
                 case "Quick 1 Pass": return Qckshr(filePath);
                 case "Random 1 Pass": return Rndshr(filePath);
                 case "DoD 3 Passes": return Do3shr(filePath);
                 case "DoD 7 Passes": return Do7shr(filePath);
                 case "Schneier 7 Passes": return Schnshr(filePath);
                 case "German VSITR 7 Passes": return Germanshr(filePath);
                 case "Gutmann 35 Passes": return Gtmshr(filePath);
                 case "RCMP TSSIT OPS-II": return RCMPshr(filePath);
                 case "British HMG IS5 [Enhanced]": return Britishshr(filePath);
                 case "Custom Erase by Mariano Ortu [User Defined]":
                     if (isCustomClassic) return Customshr(filePath);
                     if (isCustomUser) return Customusershr(filePath, listCustom);
                     throw new InvalidOperationException("Custom type not selected.");
                 case "NSA/CSS Standard 9": return NSACSS9Shr(filePath);
                 case "NSA/CSS Standard 12": return NSACSS12Shr(filePath);
                 case "Secure Delete": return ScrDel(filePath);
                 case "NIST 800-88 Rev.1 Secure Erase": return NistClearShr(filePath);
                 default: throw new ArgumentException("Unknown shredding algorithm.", nameof(algorithmName));
             }
         }
     }    
}