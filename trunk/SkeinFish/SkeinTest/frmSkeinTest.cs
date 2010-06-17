using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using SkeinFish;

namespace SkeinTest
{

    public partial class frmSkeinTest : Form
    {
        public frmSkeinTest()
        {
            InitializeComponent();
        }

        private void btnBenchmark_Click(object sender, EventArgs e)
        {
            Skein skein;

            if (rbSkein256.Checked)
                skein = new Skein256();
            else if (rbSkein512.Checked)
                skein = new Skein512();
            else
                skein = new Skein1024();
            
            var test = new SkeinTesting(skein);
            double mbs = test.Benchmark(600000);

            MessageBox.Show("Result: " + mbs.ToString("0.00") + " mb/s");
        }

        private void frmSkeinTest_Load(object sender, EventArgs e)
        {
            lblTestResult.Text = SkeinTesting.TestHash() ? "Skein hash self-tests PASSED." : "Skein hash self-tests FAILED.";
        }
    }
}
