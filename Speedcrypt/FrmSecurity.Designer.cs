namespace Speedcrypt
{
    partial class FrmSecurity
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(FrmSecurity));
            this.labYel = new System.Windows.Forms.Label();
            this.labSec = new System.Windows.Forms.Label();
            this.labFir = new System.Windows.Forms.Label();
            this.picSimb = new System.Windows.Forms.PictureBox();
            this.picGrad = new System.Windows.Forms.PictureBox();
            this.listTamper = new System.Windows.Forms.ListView();
            this.imageList1 = new System.Windows.Forms.ImageList(this.components);
            this.grbOptions = new System.Windows.Forms.GroupBox();
            this.labScreen = new System.Windows.Forms.Label();
            this.picObusc = new System.Windows.Forms.PictureBox();
            this.chkObfuscate = new System.Windows.Forms.CheckBox();
            this.grbTamper = new System.Windows.Forms.GroupBox();
            this.labNotes = new System.Windows.Forms.Label();
            this.picNote = new System.Windows.Forms.PictureBox();
            this.labTest = new System.Windows.Forms.Label();
            this.picTest = new System.Windows.Forms.PictureBox();
            this.btnTest = new System.Windows.Forms.Button();
            this.rdbConfig = new System.Windows.Forms.RadioButton();
            this.rdbTamper = new System.Windows.Forms.RadioButton();
            this.labReport = new System.Windows.Forms.Label();
            this.btnHelp = new System.Windows.Forms.Button();
            this.btnOk = new System.Windows.Forms.Button();
            this.btnCapture = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.picSimb)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.picGrad)).BeginInit();
            this.grbOptions.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.picObusc)).BeginInit();
            this.grbTamper.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.picNote)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.picTest)).BeginInit();
            this.SuspendLayout();
            // 
            // labYel
            // 
            this.labYel.BackColor = System.Drawing.SystemColors.Control;
            this.labYel.Dock = System.Windows.Forms.DockStyle.Top;
            this.labYel.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.labYel.Location = new System.Drawing.Point(0, 43);
            this.labYel.Name = "labYel";
            this.labYel.Size = new System.Drawing.Size(919, 2);
            this.labYel.TabIndex = 52;
            // 
            // labSec
            // 
            this.labSec.AutoSize = true;
            this.labSec.Location = new System.Drawing.Point(48, 21);
            this.labSec.Name = "labSec";
            this.labSec.Size = new System.Drawing.Size(35, 13);
            this.labSec.TabIndex = 51;
            this.labSec.Text = "label2";
            // 
            // labFir
            // 
            this.labFir.AutoSize = true;
            this.labFir.Location = new System.Drawing.Point(48, 5);
            this.labFir.Name = "labFir";
            this.labFir.Size = new System.Drawing.Size(35, 13);
            this.labFir.TabIndex = 50;
            this.labFir.Text = "label1";
            // 
            // picSimb
            // 
            this.picSimb.Location = new System.Drawing.Point(12, 5);
            this.picSimb.Name = "picSimb";
            this.picSimb.Size = new System.Drawing.Size(32, 32);
            this.picSimb.TabIndex = 49;
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
            this.picGrad.TabIndex = 48;
            this.picGrad.TabStop = false;
            // 
            // listTamper
            // 
            this.listTamper.HideSelection = false;
            this.listTamper.Location = new System.Drawing.Point(320, 50);
            this.listTamper.Name = "listTamper";
            this.listTamper.Size = new System.Drawing.Size(590, 575);
            this.listTamper.TabIndex = 328;
            this.listTamper.UseCompatibleStateImageBehavior = false;
            // 
            // imageList1
            // 
            this.imageList1.ColorDepth = System.Windows.Forms.ColorDepth.Depth32Bit;
            this.imageList1.ImageSize = new System.Drawing.Size(22, 22);
            this.imageList1.TransparentColor = System.Drawing.Color.Transparent;
            // 
            // grbOptions
            // 
            this.grbOptions.Controls.Add(this.btnCapture);
            this.grbOptions.Controls.Add(this.labScreen);
            this.grbOptions.Controls.Add(this.picObusc);
            this.grbOptions.Controls.Add(this.chkObfuscate);
            this.grbOptions.Location = new System.Drawing.Point(10, 430);
            this.grbOptions.Name = "grbOptions";
            this.grbOptions.Size = new System.Drawing.Size(300, 197);
            this.grbOptions.TabIndex = 1;
            this.grbOptions.TabStop = false;
            this.grbOptions.Text = "Other Options:";
            // 
            // labScreen
            // 
            this.labScreen.AutoSize = true;
            this.labScreen.ForeColor = System.Drawing.Color.Black;
            this.labScreen.Location = new System.Drawing.Point(15, 110);
            this.labScreen.Name = "labScreen";
            this.labScreen.Size = new System.Drawing.Size(236, 78);
            this.labScreen.TabIndex = 344;
            this.labScreen.Text = resources.GetString("labScreen.Text");
            // 
            // picObusc
            // 
            this.picObusc.Location = new System.Drawing.Point(15, 42);
            this.picObusc.Name = "picObusc";
            this.picObusc.Size = new System.Drawing.Size(22, 22);
            this.picObusc.TabIndex = 343;
            this.picObusc.TabStop = false;
            // 
            // chkObfuscate
            // 
            this.chkObfuscate.AutoSize = true;
            this.chkObfuscate.ForeColor = System.Drawing.Color.Black;
            this.chkObfuscate.Location = new System.Drawing.Point(45, 45);
            this.chkObfuscate.Name = "chkObfuscate";
            this.chkObfuscate.Size = new System.Drawing.Size(136, 17);
            this.chkObfuscate.TabIndex = 0;
            this.chkObfuscate.Text = "Obfuscate Print Screen";
            this.chkObfuscate.UseVisualStyleBackColor = true;
            // 
            // grbTamper
            // 
            this.grbTamper.Controls.Add(this.labNotes);
            this.grbTamper.Controls.Add(this.picNote);
            this.grbTamper.Controls.Add(this.labTest);
            this.grbTamper.Controls.Add(this.picTest);
            this.grbTamper.Controls.Add(this.btnTest);
            this.grbTamper.Controls.Add(this.rdbConfig);
            this.grbTamper.Controls.Add(this.rdbTamper);
            this.grbTamper.Controls.Add(this.labReport);
            this.grbTamper.ForeColor = System.Drawing.Color.Brown;
            this.grbTamper.Location = new System.Drawing.Point(10, 45);
            this.grbTamper.Name = "grbTamper";
            this.grbTamper.Size = new System.Drawing.Size(300, 385);
            this.grbTamper.TabIndex = 0;
            this.grbTamper.TabStop = false;
            this.grbTamper.Text = "Security Test:";
            // 
            // labNotes
            // 
            this.labNotes.AutoSize = true;
            this.labNotes.ForeColor = System.Drawing.Color.Black;
            this.labNotes.Location = new System.Drawing.Point(43, 145);
            this.labNotes.Name = "labNotes";
            this.labNotes.Size = new System.Drawing.Size(44, 13);
            this.labNotes.TabIndex = 343;
            this.labNotes.Text = "Notes...";
            // 
            // picNote
            // 
            this.picNote.Location = new System.Drawing.Point(15, 140);
            this.picNote.Name = "picNote";
            this.picNote.Size = new System.Drawing.Size(22, 22);
            this.picNote.TabIndex = 342;
            this.picNote.TabStop = false;
            // 
            // labTest
            // 
            this.labTest.AutoSize = true;
            this.labTest.ForeColor = System.Drawing.Color.Black;
            this.labTest.Location = new System.Drawing.Point(15, 170);
            this.labTest.Name = "labTest";
            this.labTest.Size = new System.Drawing.Size(264, 208);
            this.labTest.TabIndex = 341;
            this.labTest.Text = resources.GetString("labTest.Text");
            // 
            // picTest
            // 
            this.picTest.Location = new System.Drawing.Point(15, 110);
            this.picTest.Name = "picTest";
            this.picTest.Size = new System.Drawing.Size(16, 16);
            this.picTest.TabIndex = 340;
            this.picTest.TabStop = false;
            // 
            // btnTest
            // 
            this.btnTest.ForeColor = System.Drawing.Color.Black;
            this.btnTest.Location = new System.Drawing.Point(190, 15);
            this.btnTest.Name = "btnTest";
            this.btnTest.Size = new System.Drawing.Size(95, 85);
            this.btnTest.TabIndex = 0;
            this.btnTest.Text = "Start &Test";
            this.btnTest.UseVisualStyleBackColor = true;
            // 
            // rdbConfig
            // 
            this.rdbConfig.AutoSize = true;
            this.rdbConfig.ForeColor = System.Drawing.Color.Black;
            this.rdbConfig.Location = new System.Drawing.Point(40, 70);
            this.rdbConfig.Name = "rdbConfig";
            this.rdbConfig.Size = new System.Drawing.Size(106, 17);
            this.rdbConfig.TabIndex = 2;
            this.rdbConfig.TabStop = true;
            this.rdbConfig.Text = "Configuration File";
            this.rdbConfig.UseVisualStyleBackColor = true;
            // 
            // rdbTamper
            // 
            this.rdbTamper.AutoSize = true;
            this.rdbTamper.ForeColor = System.Drawing.Color.Black;
            this.rdbTamper.Location = new System.Drawing.Point(40, 40);
            this.rdbTamper.Name = "rdbTamper";
            this.rdbTamper.Size = new System.Drawing.Size(82, 17);
            this.rdbTamper.TabIndex = 1;
            this.rdbTamper.TabStop = true;
            this.rdbTamper.Text = "Anti-Tamper";
            this.rdbTamper.UseVisualStyleBackColor = true;
            // 
            // labReport
            // 
            this.labReport.AutoSize = true;
            this.labReport.ForeColor = System.Drawing.Color.Black;
            this.labReport.Location = new System.Drawing.Point(35, 112);
            this.labReport.Name = "labReport";
            this.labReport.Size = new System.Drawing.Size(179, 13);
            this.labReport.TabIndex = 333;
            this.labReport.Text = "Speedcrypt integrity verified – Ready";
            // 
            // btnHelp
            // 
            this.btnHelp.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.btnHelp.Location = new System.Drawing.Point(822, 629);
            this.btnHelp.Name = "btnHelp";
            this.btnHelp.Size = new System.Drawing.Size(90, 25);
            this.btnHelp.TabIndex = 336;
            this.btnHelp.UseVisualStyleBackColor = true;
            // 
            // btnOk
            // 
            this.btnOk.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.btnOk.Location = new System.Drawing.Point(730, 629);
            this.btnOk.Name = "btnOk";
            this.btnOk.Size = new System.Drawing.Size(90, 25);
            this.btnOk.TabIndex = 335;
            this.btnOk.Text = " ";
            this.btnOk.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageBeforeText;
            this.btnOk.UseVisualStyleBackColor = true;
            // 
            // btnCapture
            // 
            this.btnCapture.ForeColor = System.Drawing.Color.Black;
            this.btnCapture.Location = new System.Drawing.Point(190, 15);
            this.btnCapture.Name = "btnCapture";
            this.btnCapture.Size = new System.Drawing.Size(95, 85);
            this.btnCapture.TabIndex = 1;
            this.btnCapture.Text = "Capture";
            this.btnCapture.UseVisualStyleBackColor = true;
            // 
            // FrmSecurity
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(919, 656);
            this.Controls.Add(this.btnHelp);
            this.Controls.Add(this.btnOk);
            this.Controls.Add(this.grbTamper);
            this.Controls.Add(this.grbOptions);
            this.Controls.Add(this.listTamper);
            this.Controls.Add(this.labYel);
            this.Controls.Add(this.labSec);
            this.Controls.Add(this.labFir);
            this.Controls.Add(this.picSimb);
            this.Controls.Add(this.picGrad);
            this.Name = "FrmSecurity";
            this.Text = "FrmSecurity";
            ((System.ComponentModel.ISupportInitialize)(this.picSimb)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.picGrad)).EndInit();
            this.grbOptions.ResumeLayout(false);
            this.grbOptions.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.picObusc)).EndInit();
            this.grbTamper.ResumeLayout(false);
            this.grbTamper.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.picNote)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.picTest)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label labYel;
        private System.Windows.Forms.Label labSec;
        private System.Windows.Forms.Label labFir;
        private System.Windows.Forms.PictureBox picSimb;
        private System.Windows.Forms.PictureBox picGrad;
        private System.Windows.Forms.ListView listTamper;
        private System.Windows.Forms.ImageList imageList1;
        private System.Windows.Forms.GroupBox grbOptions;
        private System.Windows.Forms.CheckBox chkObfuscate;
        private System.Windows.Forms.GroupBox grbTamper;
        private System.Windows.Forms.Label labReport;
        private System.Windows.Forms.RadioButton rdbConfig;
        private System.Windows.Forms.RadioButton rdbTamper;
        private System.Windows.Forms.Button btnTest;
        private System.Windows.Forms.Button btnHelp;
        private System.Windows.Forms.Button btnOk;
        private System.Windows.Forms.PictureBox picTest;
        private System.Windows.Forms.Label labTest;
        private System.Windows.Forms.Label labNotes;
        private System.Windows.Forms.PictureBox picNote;
        private System.Windows.Forms.PictureBox picObusc;
        private System.Windows.Forms.Label labScreen;
        private System.Windows.Forms.Button btnCapture;
    }
}