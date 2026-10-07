namespace Speedcrypt
{
    partial class FrmShell
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(FrmShell));
            this.btnHelp = new System.Windows.Forms.Button();
            this.btnOk = new System.Windows.Forms.Button();
            this.labSec = new System.Windows.Forms.Label();
            this.labFir = new System.Windows.Forms.Label();
            this.picSimb = new System.Windows.Forms.PictureBox();
            this.picGrad = new System.Windows.Forms.PictureBox();
            this.labYel = new System.Windows.Forms.Label();
            this.grbSendTo = new System.Windows.Forms.GroupBox();
            this.labSendTo = new System.Windows.Forms.Label();
            this.listSendTo = new System.Windows.Forms.ListView();
            this.chkSendto = new System.Windows.Forms.CheckBox();
            this.imageList1 = new System.Windows.Forms.ImageList(this.components);
            this.imageList2 = new System.Windows.Forms.ImageList(this.components);
            this.grbShell = new System.Windows.Forms.GroupBox();
            this.listShellExt = new System.Windows.Forms.ListView();
            this.btnRemoveShell = new System.Windows.Forms.Button();
            this.btnAddShell = new System.Windows.Forms.Button();
            this.labShell = new System.Windows.Forms.Label();
            this.labShellNote = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.picSimb)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.picGrad)).BeginInit();
            this.grbSendTo.SuspendLayout();
            this.grbShell.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnHelp
            // 
            this.btnHelp.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.btnHelp.Location = new System.Drawing.Point(822, 629);
            this.btnHelp.Name = "btnHelp";
            this.btnHelp.Size = new System.Drawing.Size(90, 25);
            this.btnHelp.TabIndex = 3;
            this.btnHelp.UseVisualStyleBackColor = true;
            // 
            // btnOk
            // 
            this.btnOk.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.btnOk.Location = new System.Drawing.Point(730, 629);
            this.btnOk.Name = "btnOk";
            this.btnOk.Size = new System.Drawing.Size(90, 25);
            this.btnOk.TabIndex = 2;
            this.btnOk.Text = " ";
            this.btnOk.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageBeforeText;
            this.btnOk.UseVisualStyleBackColor = true;
            // 
            // labSec
            // 
            this.labSec.AutoSize = true;
            this.labSec.Location = new System.Drawing.Point(48, 21);
            this.labSec.Name = "labSec";
            this.labSec.Size = new System.Drawing.Size(35, 13);
            this.labSec.TabIndex = 344;
            this.labSec.Text = "label2";
            // 
            // labFir
            // 
            this.labFir.AutoSize = true;
            this.labFir.Location = new System.Drawing.Point(48, 5);
            this.labFir.Name = "labFir";
            this.labFir.Size = new System.Drawing.Size(35, 13);
            this.labFir.TabIndex = 343;
            this.labFir.Text = "label1";
            // 
            // picSimb
            // 
            this.picSimb.Location = new System.Drawing.Point(12, 5);
            this.picSimb.Name = "picSimb";
            this.picSimb.Size = new System.Drawing.Size(32, 32);
            this.picSimb.TabIndex = 342;
            this.picSimb.TabStop = false;
            // 
            // picGrad
            // 
            this.picGrad.BackgroundImageLayout = System.Windows.Forms.ImageLayout.None;
            this.picGrad.Dock = System.Windows.Forms.DockStyle.Top;
            this.picGrad.Location = new System.Drawing.Point(0, 0);
            this.picGrad.Name = "picGrad";
            this.picGrad.Size = new System.Drawing.Size(919, 43);
            this.picGrad.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.picGrad.TabIndex = 341;
            this.picGrad.TabStop = false;
            // 
            // labYel
            // 
            this.labYel.BackColor = System.Drawing.SystemColors.Control;
            this.labYel.Dock = System.Windows.Forms.DockStyle.Top;
            this.labYel.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.labYel.Location = new System.Drawing.Point(0, 43);
            this.labYel.Name = "labYel";
            this.labYel.Size = new System.Drawing.Size(919, 2);
            this.labYel.TabIndex = 345;
            // 
            // grbSendTo
            // 
            this.grbSendTo.Controls.Add(this.labSendTo);
            this.grbSendTo.Controls.Add(this.listSendTo);
            this.grbSendTo.Controls.Add(this.chkSendto);
            this.grbSendTo.ForeColor = System.Drawing.Color.Black;
            this.grbSendTo.Location = new System.Drawing.Point(10, 45);
            this.grbSendTo.Name = "grbSendTo";
            this.grbSendTo.Size = new System.Drawing.Size(445, 580);
            this.grbSendTo.TabIndex = 0;
            this.grbSendTo.TabStop = false;
            this.grbSendTo.Text = "Send To Speedcrypt...";
            // 
            // labSendTo
            // 
            this.labSendTo.AutoSize = true;
            this.labSendTo.ForeColor = System.Drawing.Color.Black;
            this.labSendTo.Location = new System.Drawing.Point(160, 25);
            this.labSendTo.Name = "labSendTo";
            this.labSendTo.Size = new System.Drawing.Size(279, 52);
            this.labSendTo.TabIndex = 353;
            this.labSendTo.Text = resources.GetString("labSendTo.Text");
            // 
            // listSendTo
            // 
            this.listSendTo.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.listSendTo.HideSelection = false;
            this.listSendTo.Location = new System.Drawing.Point(5, 135);
            this.listSendTo.Name = "listSendTo";
            this.listSendTo.Size = new System.Drawing.Size(435, 438);
            this.listSendTo.TabIndex = 352;
            this.listSendTo.UseCompatibleStateImageBehavior = false;
            // 
            // chkSendto
            // 
            this.chkSendto.AutoSize = true;
            this.chkSendto.ForeColor = System.Drawing.Color.Black;
            this.chkSendto.Location = new System.Drawing.Point(30, 40);
            this.chkSendto.Name = "chkSendto";
            this.chkSendto.Size = new System.Drawing.Size(120, 17);
            this.chkSendto.TabIndex = 0;
            this.chkSendto.Text = "Send to Speedcrypt";
            this.chkSendto.UseVisualStyleBackColor = true;
            // 
            // imageList1
            // 
            this.imageList1.ColorDepth = System.Windows.Forms.ColorDepth.Depth32Bit;
            this.imageList1.ImageSize = new System.Drawing.Size(22, 22);
            this.imageList1.TransparentColor = System.Drawing.Color.Transparent;
            // 
            // imageList2
            // 
            this.imageList2.ColorDepth = System.Windows.Forms.ColorDepth.Depth32Bit;
            this.imageList2.ImageSize = new System.Drawing.Size(22, 22);
            this.imageList2.TransparentColor = System.Drawing.Color.Transparent;
            // 
            // grbShell
            // 
            this.grbShell.Controls.Add(this.labShellNote);
            this.grbShell.Controls.Add(this.labShell);
            this.grbShell.Controls.Add(this.listShellExt);
            this.grbShell.Controls.Add(this.btnRemoveShell);
            this.grbShell.Controls.Add(this.btnAddShell);
            this.grbShell.ForeColor = System.Drawing.Color.Black;
            this.grbShell.Location = new System.Drawing.Point(465, 45);
            this.grbShell.Name = "grbShell";
            this.grbShell.Size = new System.Drawing.Size(445, 580);
            this.grbShell.TabIndex = 1;
            this.grbShell.TabStop = false;
            this.grbShell.Text = "Windows Shell Extension...";
            // 
            // listShellExt
            // 
            this.listShellExt.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.listShellExt.HideSelection = false;
            this.listShellExt.Location = new System.Drawing.Point(5, 135);
            this.listShellExt.Name = "listShellExt";
            this.listShellExt.Size = new System.Drawing.Size(435, 30);
            this.listShellExt.TabIndex = 351;
            this.listShellExt.UseCompatibleStateImageBehavior = false;
            // 
            // btnRemoveShell
            // 
            this.btnRemoveShell.ForeColor = System.Drawing.Color.Black;
            this.btnRemoveShell.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.btnRemoveShell.Location = new System.Drawing.Point(90, 25);
            this.btnRemoveShell.Name = "btnRemoveShell";
            this.btnRemoveShell.Size = new System.Drawing.Size(80, 75);
            this.btnRemoveShell.TabIndex = 1;
            this.btnRemoveShell.Text = "Remove";
            this.btnRemoveShell.UseVisualStyleBackColor = true;
            // 
            // btnAddShell
            // 
            this.btnAddShell.ForeColor = System.Drawing.Color.Black;
            this.btnAddShell.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.btnAddShell.Location = new System.Drawing.Point(10, 25);
            this.btnAddShell.Name = "btnAddShell";
            this.btnAddShell.Size = new System.Drawing.Size(80, 75);
            this.btnAddShell.TabIndex = 0;
            this.btnAddShell.Text = "Add";
            this.btnAddShell.UseVisualStyleBackColor = true;
            // 
            // labShell
            // 
            this.labShell.AutoSize = true;
            this.labShell.ForeColor = System.Drawing.Color.Black;
            this.labShell.Location = new System.Drawing.Point(180, 25);
            this.labShell.Name = "labShell";
            this.labShell.Size = new System.Drawing.Size(251, 52);
            this.labShell.TabIndex = 352;
            this.labShell.Text = "Shell extensions add \'Encrypt with SpeedCrypt\'\r\n and \'Decrypt with SpeedCrypt\' to" +
    " the Windows \r\ncontext menu for quick file transfer into the program.\r\nYou can r" +
    "emove these options at any time";
            // 
            // labShellNote
            // 
            this.labShellNote.AutoSize = true;
            this.labShellNote.ForeColor = System.Drawing.Color.Black;
            this.labShellNote.Location = new System.Drawing.Point(35, 185);
            this.labShellNote.Name = "labShellNote";
            this.labShellNote.Size = new System.Drawing.Size(318, 377);
            this.labShellNote.TabIndex = 353;
            this.labShellNote.Text = resources.GetString("labShellNote.Text");
            // 
            // FrmShell
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(919, 656);
            this.Controls.Add(this.grbShell);
            this.Controls.Add(this.grbSendTo);
            this.Controls.Add(this.labYel);
            this.Controls.Add(this.labSec);
            this.Controls.Add(this.labFir);
            this.Controls.Add(this.picSimb);
            this.Controls.Add(this.picGrad);
            this.Controls.Add(this.btnHelp);
            this.Controls.Add(this.btnOk);
            this.Name = "FrmShell";
            this.Text = "FrmShell";
            ((System.ComponentModel.ISupportInitialize)(this.picSimb)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.picGrad)).EndInit();
            this.grbSendTo.ResumeLayout(false);
            this.grbSendTo.PerformLayout();
            this.grbShell.ResumeLayout(false);
            this.grbShell.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btnHelp;
        private System.Windows.Forms.Button btnOk;
        private System.Windows.Forms.Label labSec;
        private System.Windows.Forms.Label labFir;
        private System.Windows.Forms.PictureBox picSimb;
        private System.Windows.Forms.PictureBox picGrad;
        private System.Windows.Forms.Label labYel;
        private System.Windows.Forms.GroupBox grbSendTo;
        private System.Windows.Forms.CheckBox chkSendto;
        private System.Windows.Forms.ImageList imageList1;
        private System.Windows.Forms.ListView listSendTo;
        private System.Windows.Forms.Label labSendTo;
        private System.Windows.Forms.ImageList imageList2;
        private System.Windows.Forms.GroupBox grbShell;
        private System.Windows.Forms.ListView listShellExt;
        private System.Windows.Forms.Button btnRemoveShell;
        private System.Windows.Forms.Button btnAddShell;
        private System.Windows.Forms.Label labShell;
        private System.Windows.Forms.Label labShellNote;
    }
}