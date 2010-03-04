using System;
using System.Diagnostics;

namespace SkeinFish
{
    public partial class Skein
    {
        /// <summary>
        /// Benchmarks this instance of the Skein hash function.
        /// </summary>
        /// <param name="iterations">Number of hash computations to perform.</param>
        /// <returns>Resulting speed in megabytes per second.</returns>
        public double Benchmark(long iterations)
        {
            byte[] hash = new byte[m_OutputBytes];
            Stopwatch sw = new Stopwatch();

            sw.Start();
            for (long i = 0; i < iterations; i++)
            {
                hash = ComputeHash(hash);
            }
            sw.Stop();

            double ops_per_tick = iterations / (double)sw.ElapsedTicks;
            double ops_per_sec = ops_per_tick * (double)TimeSpan.FromSeconds(1).Ticks;

            double mbs = ops_per_sec * m_CipherStateBytes / 1024 / 1024;

            return mbs;
        }

        /// <summary>
        /// Tests the 256, 512, and 1024 bit versions of Skein against
        /// known test vectors.
        /// </summary>
        /// <returns>True if the test succeeded without errors, false otherwise.</returns>
        public static bool TestHash()
        {
            Skein256 skein256 = new Skein256();
            Skein512 skein512 = new Skein512();
            Skein1024 skein1024 = new Skein1024();

            byte[] test_vector = new byte[256];
            int i;

            for (i = 0; i < 256; i++)
                test_vector[i] = (byte) (255 - i);



            return false;
        }
    }
}
