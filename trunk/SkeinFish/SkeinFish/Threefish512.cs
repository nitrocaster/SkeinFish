/*
Copyright (c) 2009 Alberto Fajardo

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

namespace SkeinFish
{
    internal class Threefish512 : ThreefishCipher
    {
        const int CIPHER_SIZE = 512;
        const int CIPHER_QWORDS = CIPHER_SIZE / 64;
        const int EXPANDED_KEY_SIZE = CIPHER_QWORDS + 1;

        public Threefish512()
        {
            // Create the expanded key array
            m_ExpandedKey = new ulong[EXPANDED_KEY_SIZE];
        }

        public override void Encrypt(ulong[] input, ulong[] output)
        {
            // Cache the block, key, and tweak
            ulong b0 = input[0], b1 = input[1],
                  b2 = input[2], b3 = input[3],
                  b4 = input[4], b5 = input[5],
                  b6 = input[6], b7 = input[7];
            ulong k0 = m_ExpandedKey[0], k1 = m_ExpandedKey[1],
                  k2 = m_ExpandedKey[2], k3 = m_ExpandedKey[3],
                  k4 = m_ExpandedKey[4], k5 = m_ExpandedKey[5],
                  k6 = m_ExpandedKey[6], k7 = m_ExpandedKey[7],
                  k8 = m_ExpandedKey[8];
            ulong t0 = m_ExpandedTweak[0], t1 = m_ExpandedTweak[1],
                  t2 = m_ExpandedTweak[2];

            Mix(ref b0, ref b1, 38, k0, k1);
            Mix(ref b2, ref b3, 30, k2, k3);
            Mix(ref b4, ref b5, 50, k4, k5 + t0);
            Mix(ref b6, ref b7, 53, k6 + t1, k7);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k1, k2);
            Mix(ref b2, ref b3, 49, k3, k4);
            Mix(ref b4, ref b5, 8, k5, k6 + t1);
            Mix(ref b6, ref b7, 42, k7 + t2, k8 + 1);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);
            Mix(ref b0, ref b1, 38, k2, k3);
            Mix(ref b2, ref b3, 30, k4, k5);
            Mix(ref b4, ref b5, 50, k6, k7 + t2);
            Mix(ref b6, ref b7, 53, k8 + t0, k0 + 2);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k3, k4);
            Mix(ref b2, ref b3, 49, k5, k6);
            Mix(ref b4, ref b5, 8, k7, k8 + t0);
            Mix(ref b6, ref b7, 42, k0 + t1, k1 + 3);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);
            Mix(ref b0, ref b1, 38, k4, k5);
            Mix(ref b2, ref b3, 30, k6, k7);
            Mix(ref b4, ref b5, 50, k8, k0 + t1);
            Mix(ref b6, ref b7, 53, k1 + t2, k2 + 4);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k5, k6);
            Mix(ref b2, ref b3, 49, k7, k8);
            Mix(ref b4, ref b5, 8, k0, k1 + t2);
            Mix(ref b6, ref b7, 42, k2 + t0, k3 + 5);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);
            Mix(ref b0, ref b1, 38, k6, k7);
            Mix(ref b2, ref b3, 30, k8, k0);
            Mix(ref b4, ref b5, 50, k1, k2 + t0);
            Mix(ref b6, ref b7, 53, k3 + t1, k4 + 6);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k7, k8);
            Mix(ref b2, ref b3, 49, k0, k1);
            Mix(ref b4, ref b5, 8, k2, k3 + t1);
            Mix(ref b6, ref b7, 42, k4 + t2, k5 + 7);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);
            Mix(ref b0, ref b1, 38, k8, k0);
            Mix(ref b2, ref b3, 30, k1, k2);
            Mix(ref b4, ref b5, 50, k3, k4 + t2);
            Mix(ref b6, ref b7, 53, k5 + t0, k6 + 8);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k0, k1);
            Mix(ref b2, ref b3, 49, k2, k3);
            Mix(ref b4, ref b5, 8, k4, k5 + t0);
            Mix(ref b6, ref b7, 42, k6 + t1, k7 + 9);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);
            Mix(ref b0, ref b1, 38, k1, k2);
            Mix(ref b2, ref b3, 30, k3, k4);
            Mix(ref b4, ref b5, 50, k5, k6 + t1);
            Mix(ref b6, ref b7, 53, k7 + t2, k8 + 10);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k2, k3);
            Mix(ref b2, ref b3, 49, k4, k5);
            Mix(ref b4, ref b5, 8, k6, k7 + t2);
            Mix(ref b6, ref b7, 42, k8 + t0, k0 + 11);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);
            Mix(ref b0, ref b1, 38, k3, k4);
            Mix(ref b2, ref b3, 30, k5, k6);
            Mix(ref b4, ref b5, 50, k7, k8 + t0);
            Mix(ref b6, ref b7, 53, k0 + t1, k1 + 12);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k4, k5);
            Mix(ref b2, ref b3, 49, k6, k7);
            Mix(ref b4, ref b5, 8, k8, k0 + t1);
            Mix(ref b6, ref b7, 42, k1 + t2, k2 + 13);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);
            Mix(ref b0, ref b1, 38, k5, k6);
            Mix(ref b2, ref b3, 30, k7, k8);
            Mix(ref b4, ref b5, 50, k0, k1 + t2);
            Mix(ref b6, ref b7, 53, k2 + t0, k3 + 14);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k6, k7);
            Mix(ref b2, ref b3, 49, k8, k0);
            Mix(ref b4, ref b5, 8, k1, k2 + t0);
            Mix(ref b6, ref b7, 42, k3 + t1, k4 + 15);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);
            Mix(ref b0, ref b1, 38, k7, k8);
            Mix(ref b2, ref b3, 30, k0, k1);
            Mix(ref b4, ref b5, 50, k2, k3 + t1);
            Mix(ref b6, ref b7, 53, k4 + t2, k5 + 16);
            Mix(ref b2, ref b1, 48);
            Mix(ref b4, ref b7, 20);
            Mix(ref b6, ref b5, 43);
            Mix(ref b0, ref b3, 31);
            Mix(ref b4, ref b1, 34);
            Mix(ref b6, ref b3, 14);
            Mix(ref b0, ref b5, 15);
            Mix(ref b2, ref b7, 27);
            Mix(ref b6, ref b1, 26);
            Mix(ref b0, ref b7, 12);
            Mix(ref b2, ref b5, 58);
            Mix(ref b4, ref b3, 7);
            Mix(ref b0, ref b1, 33, k8, k0);
            Mix(ref b2, ref b3, 49, k1, k2);
            Mix(ref b4, ref b5, 8, k3, k4 + t2);
            Mix(ref b6, ref b7, 42, k5 + t0, k6 + 17);
            Mix(ref b2, ref b1, 39);
            Mix(ref b4, ref b7, 27);
            Mix(ref b6, ref b5, 41);
            Mix(ref b0, ref b3, 14);
            Mix(ref b4, ref b1, 29);
            Mix(ref b6, ref b3, 26);
            Mix(ref b0, ref b5, 11);
            Mix(ref b2, ref b7, 9);
            Mix(ref b6, ref b1, 33);
            Mix(ref b0, ref b7, 51);
            Mix(ref b2, ref b5, 39);
            Mix(ref b4, ref b3, 35);

            // Final key schedule
            output[0] = b0 + k0;
            output[1] = b1 + k1;
            output[2] = b2 + k2;
            output[3] = b3 + k3;
            output[4] = b4 + k4;
            output[5] = b5 + k5 + t0;
            output[6] = b6 + k6 + t1;
            output[7] = b7 + k7 + 18;
        }

        public override void Decrypt(ulong[] input, ulong[] output)
        {
            // Cache the block, key, and tweak
            ulong b0 = input[0], b1 = input[1],
                  b2 = input[2], b3 = input[3],
                  b4 = input[4], b5 = input[5],
                  b6 = input[6], b7 = input[7];
            ulong k0 = m_ExpandedKey[0], k1 = m_ExpandedKey[1],
                  k2 = m_ExpandedKey[2], k3 = m_ExpandedKey[3],
                  k4 = m_ExpandedKey[4], k5 = m_ExpandedKey[5],
                  k6 = m_ExpandedKey[6], k7 = m_ExpandedKey[7],
                  k8 = m_ExpandedKey[8];
            ulong t0 = m_ExpandedTweak[0], t1 = m_ExpandedTweak[1],
                  t2 = m_ExpandedTweak[2];



            b0 -= k0;
            b1 -= k1;
            b2 -= k2;
            b3 -= k3;
            b4 -= k4;
            b5 -= k5 + t0;
            b6 -= k6 + t1;
            b7 -= k7 + 18;
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k8, k0);
            UnMix(ref b2, ref b3, 49, k1, k2);
            UnMix(ref b4, ref b5, 8, k3, k4 + t2);
            UnMix(ref b6, ref b7, 42, k5 + t0, k6 + 17);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k7, k8);
            UnMix(ref b2, ref b3, 30, k0, k1);
            UnMix(ref b4, ref b5, 50, k2, k3 + t1);
            UnMix(ref b6, ref b7, 53, k4 + t2, k5 + 16);
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k6, k7);
            UnMix(ref b2, ref b3, 49, k8, k0);
            UnMix(ref b4, ref b5, 8, k1, k2 + t0);
            UnMix(ref b6, ref b7, 42, k3 + t1, k4 + 15);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k5, k6);
            UnMix(ref b2, ref b3, 30, k7, k8);
            UnMix(ref b4, ref b5, 50, k0, k1 + t2);
            UnMix(ref b6, ref b7, 53, k2 + t0, k3 + 14);
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k4, k5);
            UnMix(ref b2, ref b3, 49, k6, k7);
            UnMix(ref b4, ref b5, 8, k8, k0 + t1);
            UnMix(ref b6, ref b7, 42, k1 + t2, k2 + 13);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k3, k4);
            UnMix(ref b2, ref b3, 30, k5, k6);
            UnMix(ref b4, ref b5, 50, k7, k8 + t0);
            UnMix(ref b6, ref b7, 53, k0 + t1, k1 + 12);
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k2, k3);
            UnMix(ref b2, ref b3, 49, k4, k5);
            UnMix(ref b4, ref b5, 8, k6, k7 + t2);
            UnMix(ref b6, ref b7, 42, k8 + t0, k0 + 11);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k1, k2);
            UnMix(ref b2, ref b3, 30, k3, k4);
            UnMix(ref b4, ref b5, 50, k5, k6 + t1);
            UnMix(ref b6, ref b7, 53, k7 + t2, k8 + 10);
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k0, k1);
            UnMix(ref b2, ref b3, 49, k2, k3);
            UnMix(ref b4, ref b5, 8, k4, k5 + t0);
            UnMix(ref b6, ref b7, 42, k6 + t1, k7 + 9);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k8, k0);
            UnMix(ref b2, ref b3, 30, k1, k2);
            UnMix(ref b4, ref b5, 50, k3, k4 + t2);
            UnMix(ref b6, ref b7, 53, k5 + t0, k6 + 8);
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k7, k8);
            UnMix(ref b2, ref b3, 49, k0, k1);
            UnMix(ref b4, ref b5, 8, k2, k3 + t1);
            UnMix(ref b6, ref b7, 42, k4 + t2, k5 + 7);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k6, k7);
            UnMix(ref b2, ref b3, 30, k8, k0);
            UnMix(ref b4, ref b5, 50, k1, k2 + t0);
            UnMix(ref b6, ref b7, 53, k3 + t1, k4 + 6);
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k5, k6);
            UnMix(ref b2, ref b3, 49, k7, k8);
            UnMix(ref b4, ref b5, 8, k0, k1 + t2);
            UnMix(ref b6, ref b7, 42, k2 + t0, k3 + 5);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k4, k5);
            UnMix(ref b2, ref b3, 30, k6, k7);
            UnMix(ref b4, ref b5, 50, k8, k0 + t1);
            UnMix(ref b6, ref b7, 53, k1 + t2, k2 + 4);
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k3, k4);
            UnMix(ref b2, ref b3, 49, k5, k6);
            UnMix(ref b4, ref b5, 8, k7, k8 + t0);
            UnMix(ref b6, ref b7, 42, k0 + t1, k1 + 3);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k2, k3);
            UnMix(ref b2, ref b3, 30, k4, k5);
            UnMix(ref b4, ref b5, 50, k6, k7 + t2);
            UnMix(ref b6, ref b7, 53, k8 + t0, k0 + 2);
            UnMix(ref b6, ref b1, 33);
            UnMix(ref b0, ref b7, 51);
            UnMix(ref b2, ref b5, 39);
            UnMix(ref b4, ref b3, 35);
            UnMix(ref b4, ref b1, 29);
            UnMix(ref b6, ref b3, 26);
            UnMix(ref b0, ref b5, 11);
            UnMix(ref b2, ref b7, 9);
            UnMix(ref b2, ref b1, 39);
            UnMix(ref b4, ref b7, 27);
            UnMix(ref b6, ref b5, 41);
            UnMix(ref b0, ref b3, 14);
            UnMix(ref b0, ref b1, 33, k1, k2);
            UnMix(ref b2, ref b3, 49, k3, k4);
            UnMix(ref b4, ref b5, 8, k5, k6 + t1);
            UnMix(ref b6, ref b7, 42, k7 + t2, k8 + 1);
            UnMix(ref b6, ref b1, 26);
            UnMix(ref b0, ref b7, 12);
            UnMix(ref b2, ref b5, 58);
            UnMix(ref b4, ref b3, 7);
            UnMix(ref b4, ref b1, 34);
            UnMix(ref b6, ref b3, 14);
            UnMix(ref b0, ref b5, 15);
            UnMix(ref b2, ref b7, 27);
            UnMix(ref b2, ref b1, 48);
            UnMix(ref b4, ref b7, 20);
            UnMix(ref b6, ref b5, 43);
            UnMix(ref b0, ref b3, 31);
            UnMix(ref b0, ref b1, 38, k0, k1);
            UnMix(ref b2, ref b3, 30, k2, k3);
            UnMix(ref b4, ref b5, 50, k4, k5 + t0);
            UnMix(ref b6, ref b7, 53, k6 + t1, k7);

            output[7] = b7;
            output[6] = b6;
            output[5] = b5;
            output[4] = b4;
            output[3] = b3;
            output[2] = b2;
            output[1] = b1;
            output[0] = b0;
        }
    }
}
