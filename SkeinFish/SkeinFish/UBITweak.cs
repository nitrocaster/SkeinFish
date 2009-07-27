using System;

namespace SkeinFish
{
    public enum UBIType : ulong
    {
        Key = 0,
        Config = 4,
        Personalization = 8,
        PublicKey = 16,
        Nonce = 20,
        Message = 48,
        Out = 63
    }

    public class UBITweak
    {
        const ulong T1_FLAG_FINAL = (ulong)1 << 63;
        const ulong T1_FLAG_FIRST = (ulong)1 << 62;

        ulong[] m_Tweak = new ulong[2];

        public void SetFirstFlag(bool enabled)
        {
            long mask = enabled ? 1 : 0;
            m_Tweak[1] = (m_Tweak[1] & ~T1_FLAG_FIRST) | ((ulong)-mask & T1_FLAG_FIRST);
        }

        public void SetFinalFlag(bool enabled)
        {
            long mask = enabled ? 1 : 0;
            m_Tweak[1] = (m_Tweak[1] & ~T1_FLAG_FINAL) | ((ulong)-mask & T1_FLAG_FINAL);
        }

        public void IncrementCount(int amount)
        {
            m_Tweak[0] += (ulong)amount;
        }

        public void StartNewType(UBIType type)
        {
            m_Tweak[0] = 0;
            m_Tweak[1] = ((ulong)type << 56) | T1_FLAG_FIRST;
        }

        public ulong[] Tweak
        {
            get { return m_Tweak; }
        }
    }
}
