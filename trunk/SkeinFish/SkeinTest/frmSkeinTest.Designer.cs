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
            this.btnBenchmark = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // btnBenchmark
            // 
            this.btnBenchmark.Location = new System.Drawing.Point(12, 12);
            this.btnBenchmark.Name = "btnBenchmark";
            this.btnBenchmark.Size = new System.Drawing.Size(149, 46);
            this.btnBenchmark.TabIndex = 0;
            this.btnBenchmark.Text = "Benchmark";
            this.btnBenchmark.UseVisualStyleBackColor = true;
            this.btnBenchmark.Click += new System.EventHandler(this.btnBenchmark_Click);
            // 
            // frmSkeinTest
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(525, 306);
            this.Controls.Add(this.btnBenchmark);
            this.Name = "frmSkeinTest";
            this.Text = "Skein Test App";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button btnBenchmark;
    }
}

