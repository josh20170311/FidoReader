namespace FidoReader
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.selectFIDOApplet = new System.Windows.Forms.Button();
            this.getInfo = new System.Windows.Forms.Button();
            this.APDUbox = new System.Windows.Forms.TextBox();
            this.clearWindow = new System.Windows.Forms.Button();
            this.CBORbox = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.getPuKxRx = new System.Windows.Forms.Button();
            this.getAttestationPublicKey = new System.Windows.Forms.Button();
            this.dumpIDSecret = new System.Windows.Forms.Button();
            this.getCx = new System.Windows.Forms.Button();
            this.getPuKxCx = new System.Windows.Forms.Button();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.paramBox = new System.Windows.Forms.TextBox();
            this.resetCredentials = new System.Windows.Forms.Button();
            this.getCredentialCount = new System.Windows.Forms.Button();
            this.getFreeSpace = new System.Windows.Forms.Button();
            this.IDxBox = new System.Windows.Forms.TextBox();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.SuspendLayout();
            // 
            // selectFIDOApplet
            // 
            this.selectFIDOApplet.Location = new System.Drawing.Point(832, 87);
            this.selectFIDOApplet.Name = "selectFIDOApplet";
            this.selectFIDOApplet.Size = new System.Drawing.Size(119, 23);
            this.selectFIDOApplet.TabIndex = 0;
            this.selectFIDOApplet.Text = "selectApplet";
            this.selectFIDOApplet.UseVisualStyleBackColor = true;
            this.selectFIDOApplet.Click += new System.EventHandler(this.selectFIDOApplet_Click);
            // 
            // getInfo
            // 
            this.getInfo.Location = new System.Drawing.Point(832, 116);
            this.getInfo.Name = "getInfo";
            this.getInfo.Size = new System.Drawing.Size(119, 23);
            this.getInfo.TabIndex = 1;
            this.getInfo.Text = "getInfo";
            this.getInfo.UseVisualStyleBackColor = true;
            this.getInfo.Click += new System.EventHandler(this.getInfo_click);
            // 
            // APDUbox
            // 
            this.APDUbox.Font = new System.Drawing.Font("Monospac821 BT", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.APDUbox.Location = new System.Drawing.Point(0, 0);
            this.APDUbox.Multiline = true;
            this.APDUbox.Name = "APDUbox";
            this.APDUbox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.APDUbox.Size = new System.Drawing.Size(411, 629);
            this.APDUbox.TabIndex = 2;
            // 
            // clearWindow
            // 
            this.clearWindow.Location = new System.Drawing.Point(832, 58);
            this.clearWindow.Name = "clearWindow";
            this.clearWindow.Size = new System.Drawing.Size(119, 23);
            this.clearWindow.TabIndex = 3;
            this.clearWindow.Text = "clear window";
            this.clearWindow.UseVisualStyleBackColor = true;
            this.clearWindow.Click += new System.EventHandler(this.clearWindow_Click);
            // 
            // CBORbox
            // 
            this.CBORbox.Font = new System.Drawing.Font("Monospac821 BT", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.CBORbox.Location = new System.Drawing.Point(445, 59);
            this.CBORbox.Multiline = true;
            this.CBORbox.Name = "CBORbox";
            this.CBORbox.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.CBORbox.Size = new System.Drawing.Size(381, 629);
            this.CBORbox.TabIndex = 4;
            this.CBORbox.WordWrap = false;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(445, 41);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(40, 15);
            this.label2.TabIndex = 6;
            this.label2.Text = "CBOR";
            // 
            // getPuKxRx
            // 
            this.getPuKxRx.Location = new System.Drawing.Point(832, 290);
            this.getPuKxRx.Name = "getPuKxRx";
            this.getPuKxRx.Size = new System.Drawing.Size(119, 23);
            this.getPuKxRx.TabIndex = 7;
            this.getPuKxRx.Text = "getPuKxRx";
            this.getPuKxRx.UseVisualStyleBackColor = true;
            this.getPuKxRx.Click += new System.EventHandler(this.getPuKxRx_Click);
            // 
            // getAttestationPublicKey
            // 
            this.getAttestationPublicKey.Location = new System.Drawing.Point(832, 145);
            this.getAttestationPublicKey.Name = "getAttestationPublicKey";
            this.getAttestationPublicKey.Size = new System.Drawing.Size(164, 23);
            this.getAttestationPublicKey.TabIndex = 8;
            this.getAttestationPublicKey.Text = "get Attestation Public Key";
            this.getAttestationPublicKey.UseVisualStyleBackColor = true;
            this.getAttestationPublicKey.Click += new System.EventHandler(this.getAttestationPublicKey_Click);
            // 
            // dumpIDSecret
            // 
            this.dumpIDSecret.Location = new System.Drawing.Point(832, 261);
            this.dumpIDSecret.Name = "dumpIDSecret";
            this.dumpIDSecret.Size = new System.Drawing.Size(119, 23);
            this.dumpIDSecret.TabIndex = 9;
            this.dumpIDSecret.Text = "dumpIDSecret";
            this.dumpIDSecret.UseVisualStyleBackColor = true;
            this.dumpIDSecret.Click += new System.EventHandler(this.dumpIDSecret_Click);
            // 
            // getCx
            // 
            this.getCx.Location = new System.Drawing.Point(832, 319);
            this.getCx.Name = "getCx";
            this.getCx.Size = new System.Drawing.Size(119, 23);
            this.getCx.TabIndex = 10;
            this.getCx.Text = "getCx";
            this.getCx.UseVisualStyleBackColor = true;
            this.getCx.Click += new System.EventHandler(this.getCx_Click);
            // 
            // getPuKxCx
            // 
            this.getPuKxCx.Location = new System.Drawing.Point(832, 377);
            this.getPuKxCx.Name = "getPuKxCx";
            this.getPuKxCx.Size = new System.Drawing.Size(119, 23);
            this.getPuKxCx.TabIndex = 11;
            this.getPuKxCx.Text = "getPuKxCx";
            this.getPuKxCx.UseVisualStyleBackColor = true;
            this.getPuKxCx.Click += new System.EventHandler(this.getPuKxCx_Click);
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Location = new System.Drawing.Point(16, 26);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(423, 662);
            this.tabControl1.TabIndex = 12;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.APDUbox);
            this.tabPage1.Location = new System.Drawing.Point(4, 24);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(415, 634);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "APDU";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.paramBox);
            this.tabPage2.Location = new System.Drawing.Point(4, 24);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(415, 634);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "IDP params";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // paramBox
            // 
            this.paramBox.Font = new System.Drawing.Font("Monospac821 BT", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.paramBox.Location = new System.Drawing.Point(2, 3);
            this.paramBox.Multiline = true;
            this.paramBox.Name = "paramBox";
            this.paramBox.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.paramBox.Size = new System.Drawing.Size(411, 629);
            this.paramBox.TabIndex = 3;
            this.paramBox.WordWrap = false;
            // 
            // resetCredentials
            // 
            this.resetCredentials.Location = new System.Drawing.Point(832, 232);
            this.resetCredentials.Name = "resetCredentials";
            this.resetCredentials.Size = new System.Drawing.Size(119, 23);
            this.resetCredentials.TabIndex = 13;
            this.resetCredentials.Text = "resetCredentials";
            this.resetCredentials.UseVisualStyleBackColor = true;
            this.resetCredentials.Click += new System.EventHandler(this.resetCredentials_Click);
            // 
            // getCredentialCount
            // 
            this.getCredentialCount.Location = new System.Drawing.Point(832, 203);
            this.getCredentialCount.Name = "getCredentialCount";
            this.getCredentialCount.Size = new System.Drawing.Size(134, 23);
            this.getCredentialCount.TabIndex = 14;
            this.getCredentialCount.Text = "getCredentialCount";
            this.getCredentialCount.UseVisualStyleBackColor = true;
            this.getCredentialCount.Click += new System.EventHandler(this.getCredentialCount_Click);
            // 
            // getFreeSpace
            // 
            this.getFreeSpace.Location = new System.Drawing.Point(832, 174);
            this.getFreeSpace.Name = "getFreeSpace";
            this.getFreeSpace.Size = new System.Drawing.Size(119, 23);
            this.getFreeSpace.TabIndex = 15;
            this.getFreeSpace.Text = "getFreeSpace";
            this.getFreeSpace.UseVisualStyleBackColor = true;
            this.getFreeSpace.Click += new System.EventHandler(this.getFreeSpace_Click);
            // 
            // IDxBox
            // 
            this.IDxBox.Location = new System.Drawing.Point(832, 348);
            this.IDxBox.Name = "IDxBox";
            this.IDxBox.PlaceholderText = "IDx";
            this.IDxBox.Size = new System.Drawing.Size(119, 23);
            this.IDxBox.TabIndex = 16;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1008, 729);
            this.Controls.Add(this.IDxBox);
            this.Controls.Add(this.getFreeSpace);
            this.Controls.Add(this.getCredentialCount);
            this.Controls.Add(this.resetCredentials);
            this.Controls.Add(this.tabControl1);
            this.Controls.Add(this.getPuKxCx);
            this.Controls.Add(this.getCx);
            this.Controls.Add(this.dumpIDSecret);
            this.Controls.Add(this.getAttestationPublicKey);
            this.Controls.Add(this.getPuKxRx);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.CBORbox);
            this.Controls.Add(this.clearWindow);
            this.Controls.Add(this.getInfo);
            this.Controls.Add(this.selectFIDOApplet);
            this.Name = "Form1";
            this.Text = "Form1";
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            this.tabPage2.ResumeLayout(false);
            this.tabPage2.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private Button selectFIDOApplet;
        private Button getInfo;
        private TextBox APDUbox;
        private Button clearWindow;
        private TextBox CBORbox;
        private Label label2;
        private Button getPuKxRx;
        private Button getAttestationPublicKey;
        private Button dumpIDSecret;
        private Button getCx;
        private Button getPuKxCx;
        private TabControl tabControl1;
        private TabPage tabPage1;
        private TabPage tabPage2;
        private TextBox paramBox;
        private Button resetCredentials;
        private Button getCredentialCount;
        private Button getFreeSpace;
        private TextBox IDxBox;
    }
}