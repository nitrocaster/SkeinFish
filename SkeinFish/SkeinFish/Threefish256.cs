using System;

namespace SkeinFish
{
    internal class Threefish256 : ThreefishCipher
    {
        const int CIPHER_SIZE = 256;
        const int CIPHER_QWORDS = CIPHER_SIZE / 64;
        const int EXPANDED_KEY_SIZE = CIPHER_QWORDS + 1;

        public Threefish256()
        {
            // Create the expanded key array
            m_ExpandedKey = new ulong[EXPANDED_KEY_SIZE];
        }

        public override void Encrypt(ulong[] input, ulong[] output)
        {
            // Cache the block, key, and tweak
            ulong b0 = input[0], b1 = input[1],
                  b2 = input[2], b3 = input[3];
            ulong k0 = m_ExpandedKey[0], k1 = m_ExpandedKey[1],
                  k2 = m_ExpandedKey[2], k3 = m_ExpandedKey[3],
                  k4 = m_ExpandedKey[4];
            ulong t0 = m_ExpandedTweak[0], t1 = m_ExpandedTweak[1],
                  t2 = m_ExpandedTweak[2];

            Mix(ref b0, ref b1, 5, k0, k1 + t0);
            Mix(ref b2, ref b3, 56, k2 + t1, k3);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k1, k2 + t1);
            Mix(ref b2, ref b3, 20, k3 + t2, k4 + 1);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);
            Mix(ref b0, ref b1, 5, k2, k3 + t2);
            Mix(ref b2, ref b3, 56, k4 + t0, k0 + 2);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k3, k4 + t0);
            Mix(ref b2, ref b3, 20, k0 + t1, k1 + 3);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);
            Mix(ref b0, ref b1, 5, k4, k0 + t1);
            Mix(ref b2, ref b3, 56, k1 + t2, k2 + 4);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k0, k1 + t2);
            Mix(ref b2, ref b3, 20, k2 + t0, k3 + 5);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);
            Mix(ref b0, ref b1, 5, k1, k2 + t0);
            Mix(ref b2, ref b3, 56, k3 + t1, k4 + 6);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k2, k3 + t1);
            Mix(ref b2, ref b3, 20, k4 + t2, k0 + 7);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);
            Mix(ref b0, ref b1, 5, k3, k4 + t2);
            Mix(ref b2, ref b3, 56, k0 + t0, k1 + 8);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k4, k0 + t0);
            Mix(ref b2, ref b3, 20, k1 + t1, k2 + 9);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);
            Mix(ref b0, ref b1, 5, k0, k1 + t1);
            Mix(ref b2, ref b3, 56, k2 + t2, k3 + 10);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k1, k2 + t2);
            Mix(ref b2, ref b3, 20, k3 + t0, k4 + 11);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);
            Mix(ref b0, ref b1, 5, k2, k3 + t0);
            Mix(ref b2, ref b3, 56, k4 + t1, k0 + 12);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k3, k4 + t1);
            Mix(ref b2, ref b3, 20, k0 + t2, k1 + 13);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);
            Mix(ref b0, ref b1, 5, k4, k0 + t2);
            Mix(ref b2, ref b3, 56, k1 + t0, k2 + 14);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k0, k1 + t0);
            Mix(ref b2, ref b3, 20, k2 + t1, k3 + 15);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);
            Mix(ref b0, ref b1, 5, k1, k2 + t1);
            Mix(ref b2, ref b3, 56, k3 + t2, k4 + 16);
            Mix(ref b0, ref b3, 36);
            Mix(ref b2, ref b1, 28);
            Mix(ref b0, ref b1, 13);
            Mix(ref b2, ref b3, 46);
            Mix(ref b0, ref b3, 58);
            Mix(ref b2, ref b1, 44);
            Mix(ref b0, ref b1, 26, k2, k3 + t2);
            Mix(ref b2, ref b3, 20, k4 + t0, k0 + 17);
            Mix(ref b0, ref b3, 53);
            Mix(ref b2, ref b1, 35);
            Mix(ref b0, ref b1, 11);
            Mix(ref b2, ref b3, 42);
            Mix(ref b0, ref b3, 59);
            Mix(ref b2, ref b1, 50);

            output[0] = b0 + k3;
            output[1] = b1 + k4 + t0;
            output[2] = b2 + k0 + t1;
            output[3] = b3 + k1 + 18;
        }

        public override void Decrypt(ulong[] input, ulong[] output)
        {
            // Cache the block, key, and tweak
            ulong b0 = input[0], b1 = input[1],
                  b2 = input[2], b3 = input[3];
            ulong k0 = m_ExpandedKey[0], k1 = m_ExpandedKey[1],
                  k2 = m_ExpandedKey[2], k3 = m_ExpandedKey[3],
                  k4 = m_ExpandedKey[4];
            ulong t0 = m_ExpandedTweak[0], t1 = m_ExpandedTweak[1],
                  t2 = m_ExpandedTweak[2];

            b0 -= k3;
            b1 -= k4 + t0;
            b2 -= k0 + t1;
            b3 -= k1 + 18;
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k2, k3 + t2);
            UnMix(ref b2, ref b3, 20, k4 + t0, k0 + 17);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k1, k2 + t1);
            UnMix(ref b2, ref b3, 56, k3 + t2, k4 + 16);
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k0, k1 + t0);
            UnMix(ref b2, ref b3, 20, k2 + t1, k3 + 15);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k4, k0 + t2);
            UnMix(ref b2, ref b3, 56, k1 + t0, k2 + 14);
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k3, k4 + t1);
            UnMix(ref b2, ref b3, 20, k0 + t2, k1 + 13);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k2, k3 + t0);
            UnMix(ref b2, ref b3, 56, k4 + t1, k0 + 12);
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k1, k2 + t2);
            UnMix(ref b2, ref b3, 20, k3 + t0, k4 + 11);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k0, k1 + t1);
            UnMix(ref b2, ref b3, 56, k2 + t2, k3 + 10);
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k4, k0 + t0);
            UnMix(ref b2, ref b3, 20, k1 + t1, k2 + 9);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k3, k4 + t2);
            UnMix(ref b2, ref b3, 56, k0 + t0, k1 + 8);
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k2, k3 + t1);
            UnMix(ref b2, ref b3, 20, k4 + t2, k0 + 7);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k1, k2 + t0);
            UnMix(ref b2, ref b3, 56, k3 + t1, k4 + 6);
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k0, k1 + t2);
            UnMix(ref b2, ref b3, 20, k2 + t0, k3 + 5);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k4, k0 + t1);
            UnMix(ref b2, ref b3, 56, k1 + t2, k2 + 4);
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k3, k4 + t0);
            UnMix(ref b2, ref b3, 20, k0 + t1, k1 + 3);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k2, k3 + t2);
            UnMix(ref b2, ref b3, 56, k4 + t0, k0 + 2);
            UnMix(ref b0, ref b3, 59);
            UnMix(ref b2, ref b1, 50);
            UnMix(ref b0, ref b1, 11);
            UnMix(ref b2, ref b3, 42);
            UnMix(ref b0, ref b3, 53);
            UnMix(ref b2, ref b1, 35);
            UnMix(ref b0, ref b1, 26, k1, k2 + t1);
            UnMix(ref b2, ref b3, 20, k3 + t2, k4 + 1);
            UnMix(ref b0, ref b3, 58);
            UnMix(ref b2, ref b1, 44);
            UnMix(ref b0, ref b1, 13);
            UnMix(ref b2, ref b3, 46);
            UnMix(ref b0, ref b3, 36);
            UnMix(ref b2, ref b1, 28);
            UnMix(ref b0, ref b1, 5, k0, k1 + t0);
            UnMix(ref b2, ref b3, 56, k2 + t1, k3);

            output[0] = b0;
            output[1] = b1;
            output[2] = b2;
            output[3] = b3;
        }
    }
}
