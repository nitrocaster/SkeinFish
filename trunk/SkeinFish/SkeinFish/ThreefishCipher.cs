using System;
using System.Security.Cryptography;

namespace SkeinFish
{
    internal abstract class ThreefishCipher
    {
        protected const ulong KEY_SCHEDULE_CONST = 0x5555555555555555;
        protected const int EXPANDED_TWEAK_SIZE = 3;

        protected ulong[] m_ExpandedKey;
        protected ulong[] m_ExpandedTweak;

        public ThreefishCipher()
        {
            m_ExpandedTweak = new ulong[EXPANDED_TWEAK_SIZE];
        }

        protected static ulong RotateLeft64(ulong v, int b)
        {
            return (v << b) | (v >> (64 - b));
        }

        protected static ulong RotateRight64(ulong v, int b)
        {
            return (v >> b) | (v << (64 - b));
        }

        protected static void Mix(ref ulong a, ref ulong b, int r)
        {
            a += b;
            b = RotateLeft64(b, r) ^ a;
        }

        protected static void Mix(ref ulong a, ref ulong b, int r, ulong k0, ulong k1)
        {
            b += k1;
            a += b + k0;
            b = RotateLeft64(b, r) ^ a;
        }

        protected static void UnMix(ref ulong a, ref ulong b, int r)
        {
            b = RotateRight64(b ^ a, r);
            a -= b;
        }

        protected static void UnMix(ref ulong a, ref ulong b, int r, ulong k0, ulong k1)
        {
            b = RotateRight64(b ^ a, r);
            a -= b + k0;
            b -= k1;
        }

        public void SetTweak(ulong[] tweak)
        {
            m_ExpandedTweak[0] = tweak[0];
            m_ExpandedTweak[1] = tweak[1];
            m_ExpandedTweak[2] = tweak[0] ^ tweak[1];
        }

        public void SetKey(ulong[] key)
        {
            int i;
            ulong parity = KEY_SCHEDULE_CONST;

            for (i = 0; i < m_ExpandedKey.Length - 1; i++)
            {
                m_ExpandedKey[i] = key[i];
                parity ^= key[i];
            }

            m_ExpandedKey[i] = parity;
        }

        abstract public void Encrypt(ulong[] input, ulong[] output);
        abstract public void Decrypt(ulong[] input, ulong[] output);
    }
}
