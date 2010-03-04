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
            Skein512 skein = new Skein512();
            double mbs;

            mbs = skein.Benchmark(100000);

            MessageBox.Show("Result: " + mbs.ToString("0.00") + " mb/s");
        }
    }
}
