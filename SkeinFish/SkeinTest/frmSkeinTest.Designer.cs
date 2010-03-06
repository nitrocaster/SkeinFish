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
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.rbSkein1024 = new System.Windows.Forms.RadioButton();
            this.rbSkein512 = new System.Windows.Forms.RadioButton();
            this.rbSkein256 = new System.Windows.Forms.RadioButton();
            this.btnBenchmark = new System.Windows.Forms.Button();
            this.groupBox1.SuspendLayout();
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
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.rbSkein1024);
            this.groupBox1.Controls.Add(this.rbSkein512);
            this.groupBox1.Controls.Add(this.rbSkein256);
            this.groupBox1.Controls.Add(this.btnBenchmark);
            this.groupBox1.Location = new System.Drawing.Point(14, 41);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(192, 136);
            this.groupBox1.TabIndex = 2;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Benchmark";
            // 
            // rbSkein1024
            // 
            this.rbSkein1024.AutoSize = true;
            this.rbSkein1024.Location = new System.Drawing.Point(16, 73);
            this.rbSkein1024.Name = "rbSkein1024";
            this.rbSkein1024.Size = new System.Drawing.Size(79, 17);
            this.rbSkein1024.TabIndex = 4;
            this.rbSkein1024.TabStop = true;
            this.rbSkein1024.Text = "Skein 1024";
            this.rbSkein1024.UseVisualStyleBackColor = true;
            // 
            // rbSkein512
            // 
            this.rbSkein512.AutoSize = true;
            this.rbSkein512.Checked = true;
            this.rbSkein512.Location = new System.Drawing.Point(16, 50);
            this.rbSkein512.Name = "rbSkein512";
            this.rbSkein512.Size = new System.Drawing.Size(73, 17);
            this.rbSkein512.TabIndex = 3;
            this.rbSkein512.TabStop = true;
            this.rbSkein512.Text = "Skein 512";
            this.rbSkein512.UseVisualStyleBackColor = true;
            // 
            // rbSkein256
            // 
            this.rbSkein256.AutoSize = true;
            this.rbSkein256.Location = new System.Drawing.Point(16, 27);
            this.rbSkein256.Name = "rbSkein256";
            this.rbSkein256.Size = new System.Drawing.Size(73, 17);
            this.rbSkein256.TabIndex = 2;
            this.rbSkein256.TabStop = true;
            this.rbSkein256.Text = "Skein 256";
            this.rbSkein256.UseVisualStyleBackColor = true;
            // 
            // btnBenchmark
            // 
            this.btnBenchmark.Location = new System.Drawing.Point(71, 96);
            this.btnBenchmark.Name = "btnBenchmark";
            this.btnBenchmark.Size = new System.Drawing.Size(115, 30);
            this.btnBenchmark.TabIndex = 1;
            this.btnBenchmark.Text = "Benchmark";
            this.btnBenchmark.UseVisualStyleBackColor = true;
            this.btnBenchmark.Click += new System.EventHandler(this.btnBenchmark_Click);
            // 
            // frmSkeinTest
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(222, 187);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.lblTestResult);
            this.Name = "frmSkeinTest";
            this.Text = "Skein Test App";
            this.Load += new System.EventHandler(this.frmSkeinTest_Load);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lblTestResult;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.RadioButton rbSkein256;
        private System.Windows.Forms.Button btnBenchmark;
        private System.Windows.Forms.RadioButton rbSkein1024;
        private System.Windows.Forms.RadioButton rbSkein512;
    }
}

