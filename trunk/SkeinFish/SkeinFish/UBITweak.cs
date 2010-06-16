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

namespace SkeinFish
{
    public enum UbiType : ulong
    {
        Key = 0,
        Config = 4,
        Personalization = 8,
        PublicKey = 12,
        KeyIdentifier = 16,
        Nonce = 20,
        Message = 48,
        Out = 63
    }

    public class UbiTweak
    {
        const ulong T1FlagFinal = unchecked((ulong)1 << 63);
        const ulong T1FlagFirst = unchecked((ulong)1 << 62);

        public UbiTweak()
        {
            Tweak = new ulong[2];
        }

        public void SetFirstFlag(bool enabled)
        {
            long mask = enabled ? 1 : 0;
            Tweak[1] = (Tweak[1] & ~T1FlagFirst) | ((ulong)-mask & T1FlagFirst);
        }

        public void SetFinalFlag(bool enabled)
        {
            long mask = enabled ? 1 : 0;
            Tweak[1] = (Tweak[1] & ~T1FlagFinal) | ((ulong)-mask & T1FlagFinal);
        }

        public void SetTreeLevel(byte level)
        {
            if (level > 63)
                throw new Exception("Tree level must be between 0 and 63, inclusive.");

            Tweak[1] &= ~((ulong)0x3f << 48);
            Tweak[1] |= (ulong)level << 48;
        }

        /// <summary>
        /// The number of bits processed so far, inclusive.
        /// </summary>
        public ulong BitsProcessed
        {
            get { return Tweak[0]; }
            set { Tweak[0] = value; }
        }

        public void StartNewType(UbiType type)
        {
            BitsProcessed = 0;
            Tweak[1] = ((ulong)type << 56) | T1FlagFirst;
        }

        public ulong[] Tweak { get; private set; }
    }
}
