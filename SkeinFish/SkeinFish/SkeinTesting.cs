/*
Copyright (c) 2010 Alberto Fajardo

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

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
            byte[] hash = new byte[_outputBytes];
            Stopwatch sw = new Stopwatch();

            sw.Start();
            this.Initialize();
            for (long i = 0; i < iterations; i++)
            {
                this.TransformBlock(hash, 0, _outputBytes, hash, 0);
            }
            this.TransformFinalBlock(hash, 0, _outputBytes);
            sw.Stop();

            double ops_per_tick = iterations / (double)sw.ElapsedTicks;
            double ops_per_sec = ops_per_tick * (double)TimeSpan.FromSeconds(1).Ticks;

            double mbs = ops_per_sec * _cipherStateBytes / 1024 / 1024;

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
                0xB4, 0x84, 0xAE, 0x9F, 0xB7, 0x3E, 0x66, 0x20, 
                0xB1, 0x0D, 0x52, 0xE4, 0x92, 0x60, 0xAD, 0x26, 
                0x62, 0x0D, 0xB2, 0x88, 0x3E, 0xBA, 0xFA, 0x21, 
                0x0D, 0x70, 0x19, 0x22, 0xAC, 0xA8, 0x53, 0x68, 
                0x08, 0x81, 0x44, 0xBD, 0xF4, 0xEF, 0x3D, 0x98, 
                0x98, 0xD4, 0x7C, 0x34, 0xF1, 0x30, 0x03, 0x1B, 
                0x0A, 0x09, 0x92, 0xF0, 0x9F, 0x62, 0xDD, 0x78,
                0xB3, 0x29, 0x52, 0x5A, 0x77, 0x7D, 0xAF, 0x7D
            };

            byte[] result1024 = {
                0xC2, 0xE6, 0xB6, 0xFC, 0x04, 0x2F, 0x86, 0xF2, 
                0xE3, 0x17, 0x38, 0x64, 0x1D, 0xB6, 0x02, 0x95, 
                0xF7, 0x42, 0x04, 0xAB, 0x52, 0x58, 0x95, 0xA5, 
                0xDE, 0xC5, 0xC8, 0x06, 0xAC, 0x47, 0x86, 0xEC, 
                0x1C, 0x98, 0x29, 0x20, 0x09, 0x5B, 0x71, 0x29, 
                0xFE, 0x3D, 0x8B, 0xD4, 0x51, 0xF6, 0x7E, 0xA3, 
                0x13, 0x20, 0xC7, 0x8B, 0x11, 0x57, 0x5E, 0xA6, 
                0xDD, 0xE3, 0x94, 0xE7, 0x5D, 0xC5, 0xF5, 0xC9, 
                0x6A, 0x51, 0x04, 0x38, 0x6D, 0xD5, 0x50, 0x16, 
                0xD4, 0x94, 0xDF, 0xFA, 0xC5, 0xAD, 0x11, 0x9B, 
                0x22, 0xC9, 0x60, 0xDC, 0x46, 0xB6, 0x58, 0xCF, 
                0x2C, 0xEB, 0x7D, 0x73, 0xAF, 0x0F, 0xD0, 0xE1, 
                0x9C, 0x7E, 0x21, 0x34, 0x4A, 0xAD, 0x06, 0xAF, 
                0x39, 0xFC, 0xBE, 0xF6, 0xC6, 0xC5, 0xD0, 0x0D, 
                0xE8, 0x96, 0xB8, 0x88, 0xD9, 0x54, 0x56, 0xDE, 
                0xDB, 0xA6, 0xE5, 0x37, 0x7B, 0x0C, 0xC5, 0x72
            };


            byte[] test_vector;
            byte[] hash;
            int i;

            // Make test vector for 256-bit hash
            test_vector = new byte[64];
            for (i = 0; i < test_vector.Length; i++)
                test_vector[i] = (byte) (255 - i);

            hash = skein256.ComputeHash(test_vector);

            // Compare with 256-bit test vector
            for (i = 0; i < result256.Length; i++)
                if (hash[i] != result256[i]) return false;
            

            // Make the test vector for the 512 and 1024-bit hash
            test_vector = new byte[128];
            for (i = 0; i < test_vector.Length; i++)
                test_vector[i] = (byte)(255 - i);

            hash = skein512.ComputeHash(test_vector);

            // Compare with 512-bit test vector
            for (i = 0; i < result512.Length; i++)
                if (hash[i] != result512[i]) return false;

            hash = skein1024.ComputeHash(test_vector);

            // Compare with 1024-bit test vector
            for (i = 0; i < result1024.Length; i++)
                if (hash[i] != result1024[i]) return false;

            return true;
        }
    }
}
