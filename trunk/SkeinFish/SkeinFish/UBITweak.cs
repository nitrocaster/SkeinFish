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
        const ulong T1_FLAG_FINAL = unchecked((ulong)1 << 63);
        const ulong T1_FLAG_FIRST = unchecked((ulong)1 << 62);

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

        public void SetTreeLevel(byte level)
        {
            if (level > 63)
                throw new Exception("Tree level must be between 0 and 63, inclusive.");

            m_Tweak[1] &= ~((ulong)0x3f << 48);
            m_Tweak[1] |= (ulong)level << 48;
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
