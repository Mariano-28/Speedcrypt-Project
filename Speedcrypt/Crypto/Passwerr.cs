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
using System;
using System.Windows.Forms;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Speedcrypt.Exceptionlog;

namespace Speedcrypt.Crypto
{
    /// <summary>
    /// Created by Mariano Ortu
    /// 
    /// Passwerr: Handles decryption failures by showing an appropriate error message to the user.
    /// </summary>
    ///
    /// <remarks>
    /// This static class is responsible for managing decryption failure scenarios:
    /// - Stops any active UI timer to prevent further activity during failure.
    /// - Determines the appropriate UI target (form/control) to display the error message.
    /// - Shows a detailed MessageBox on the UI thread for smooth user experience.
    /// 
    /// Technical note:
    /// - Uses `BeginInvoke` to ensure the MessageBox is displayed safely after stopping UI timers.
    /// - Silent exception handling is applied to avoid interruption of program flow.
    /// - Supports fallback to any available form or no-owner MessageBox if no valid UI target exists.
    /// 
    /// Responsibility for this C# implementation, cryptographic integration,
    /// testing, and validation lies entirely with the author.
    /// </remarks>
    public static class Passwerr
    {
         public static void HandleDecryptionFailure()
         {
               try
               {
                   // Stop the timer immediately if available
                   var frm = FrmSettings.Instance;
                   var tmr = (frm != null) ? frm.timer1 : null;
                   if (tmr != null)
                   {
                       tmr.Stop();
                       tmr.Enabled = false;
                   }

                   // Select a valid UI control to invoke on
                   Control uiTarget = null;
                   if (frm != null && frm.IsHandleCreated && !frm.IsDisposed)
                   {
                       uiTarget = frm;
                   }
                   else
                   {
                       // Fallback: use any available form as UI target
                       foreach (Form f in Application.OpenForms)
                       {
                           if (f != null && f.IsHandleCreated && !f.IsDisposed)
                           {
                               uiTarget = f;
                               break;
                           }
                       }
                   }

                   // Show the MessageBox through BeginInvoke to ensure the timer is stopped first
                   if (uiTarget != null)
                   {
                       uiTarget.BeginInvoke((MethodInvoker)delegate
                       {
                           var owner = uiTarget as IWin32Window;
                           CentralLog.LogEvent("DECRYPT", "Decryption failed: incorrect password or corrupted file.",  nameof(HandleDecryptionFailure));
                           //MessageBox.Show(owner, "Decryption failed: incorrect password or corrupted file.", ForAllUnits.BoxErr, MessageBoxButtons.OK, MessageBoxIcon.Error);
                       });
                   }
                   else
                   {
                     CentralLog.LogEvent("DECRYPT", "Decryption failed: incorrect password or corrupted file.", nameof(HandleDecryptionFailure));                    
                   }
               }
             catch
             {                
                 // Silent exception handling
             }
         }        
    }
}