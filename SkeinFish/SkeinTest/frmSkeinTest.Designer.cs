namespace SkeinTest
{
    partial class frmSkeinTest
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
            this.lblTestResult = new System.Windows.Forms.Label();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.rbSkein1024 = new System.Windows.Forms.RadioButton();
            this.rbSkein512 = new System.Windows.Forms.RadioButton();
            this.rbSkein256 = new System.Windows.Forms.RadioButton();
            this.btnBenchmark = new System.Windows.Forms.Button();
            this.groupBox2.SuspendLayout();
            this.SuspendLayout();
            // 
            // lblTestResult
            // 
            this.lblTestResult.AutoSize = true;
            this.lblTestResult.Location = new System.Drawing.Point(12, 9);
            this.lblTestResult.Name = "lblTestResult";
            this.lblTestResult.Size = new System.Drawing.Size(68, 13);
            this.lblTestResult.TabIndex = 1;
            this.lblTestResult.Text = "lblTestResult";
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.rbSkein1024);
            this.groupBox2.Controls.Add(this.rbSkein512);
            this.groupBox2.Controls.Add(this.rbSkein256);
            this.groupBox2.Location = new System.Drawing.Point(7, 37);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(222, 86);
            this.groupBox2.TabIndex = 3;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Hash";
            // 
            // rbSkein1024
            // 
            this.rbSkein1024.AutoSize = true;
            this.rbSkein1024.Location = new System.Drawing.Point(6, 60);
            this.rbSkein1024.Name = "rbSkein1024";
            this.rbSkein1024.Size = new System.Drawing.Size(79, 17);
            this.rbSkein1024.TabIndex = 7;
            this.rbSkein1024.TabStop = true;
            this.rbSkein1024.Text = "Skein 1024";
            this.rbSkein1024.UseVisualStyleBackColor = true;
            // 
            // rbSkein512
            // 
            this.rbSkein512.AutoSize = true;
            this.rbSkein512.Checked = true;
            this.rbSkein512.Location = new System.Drawing.Point(6, 37);
            this.rbSkein512.Name = "rbSkein512";
            this.rbSkein512.Size = new System.Drawing.Size(73, 17);
            this.rbSkein512.TabIndex = 6;
            this.rbSkein512.TabStop = true;
            this.rbSkein512.Text = "Skein 512";
            this.rbSkein512.UseVisualStyleBackColor = true;
            // 
            // rbSkein256
            // 
            this.rbSkein256.AutoSize = true;
            this.rbSkein256.Location = new System.Drawing.Point(6, 14);
            this.rbSkein256.Name = "rbSkein256";
            this.rbSkein256.Size = new System.Drawing.Size(73, 17);
            this.rbSkein256.TabIndex = 5;
            this.rbSkein256.TabStop = true;
            this.rbSkein256.Text = "Skein 256";
            this.rbSkein256.UseVisualStyleBackColor = true;
            // 
            // btnBenchmark
            // 
            this.btnBenchmark.Location = new System.Drawing.Point(7, 129);
            this.btnBenchmark.Name = "btnBenchmark";
            this.btnBenchmark.Size = new System.Drawing.Size(222, 30);
            this.btnBenchmark.TabIndex = 4;
            this.btnBenchmark.Text = "Benchmark";
            this.btnBenchmark.UseVisualStyleBackColor = true;
            // 
            // frmSkeinTest
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(241, 167);
            this.Controls.Add(this.btnBenchmark);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.lblTestResult);
            this.Name = "frmSkeinTest";
            this.Text = "Skein Test App";
            this.Load += new System.EventHandler(this.frmSkeinTest_Load);
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lblTestResult;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.RadioButton rbSkein1024;
        private System.Windows.Forms.RadioButton rbSkein512;
        private System.Windows.Forms.RadioButton rbSkein256;
        private System.Windows.Forms.Button btnBenchmark;
    }
}

