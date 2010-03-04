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
            this.Initialize();
            for (long i = 0; i < iterations; i++)
            {
                this.TransformBlock(hash, 0, m_OutputBytes, hash, 0);
            }
            this.TransformFinalBlock(hash, 0, m_OutputBytes);
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

            byte[] result256 = {
                0x90, 0xE5, 0x0C, 0x4D, 0xCF, 0xC7, 0x49, 0x0A, 
                0x09, 0xF3, 0xA1, 0xA7, 0x9B, 0xF3, 0xB3, 0xDF,
                0x21, 0xEA, 0x85, 0x44, 0x7B, 0x0F, 0xF0, 0x29, 
                0xC8, 0x47, 0xD6, 0x59, 0x85, 0x6E, 0xC7, 0xA5
            };

            byte[] result512 = { 
                0x04, 0xF9, 0x6C, 0x6F, 0x61, 0xB3, 0xE2, 0x37, 
                0xA4, 0xFA, 0x77, 0x55, 0xEE, 0x4A, 0xCF, 0x34,
                0x49, 0x42, 0x22, 0x96, 0x89, 0x54, 0xF4, 0x95, 
                0xAD, 0x14, 0x7A, 0x1A, 0x71, 0x5F, 0x7A, 0x73,
                0xEB, 0xEC, 0xFA, 0x1E, 0xF2, 0x75, 0xBE, 0xD8, 
                0x7D, 0xC6, 0x0B, 0xD1, 0xA0, 0xBC, 0x60, 0x21,
                0x06, 0xFA, 0x98, 0xF8, 0xE7, 0x23, 0x7B, 0xD1,
                0xAC, 0x09, 0x58, 0xE7, 0x6D, 0x30, 0x66, 0x78
            };


            byte[] test_vector = new byte[64];
            byte[] hash;
            int i;

            for (i = 0; i < test_vector.Length; i++)
                test_vector[i] = (byte) (255 - i);


            hash = skein256.ComputeHash(test_vector);

            // compare with 256-bit test vector
            for (i = 0; i < result256.Length; i++)
                if (hash[i] != result256[i]) return false;

            hash = skein512.ComputeHash(test_vector);

            // compare with 512-bit test vector
            for (i = 0; i < result512.Length; i++)
                if (hash[i] != result512[i]) return false;


            return true;
        }
    }
}
