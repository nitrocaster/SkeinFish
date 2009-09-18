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
using System.Text;
using System.Security.Cryptography;

namespace SkeinFish
{
    public class SkeinConfig
    {
        int m_StateSize;
        ulong[] m_ConfigString;
        ulong[] m_ConfigValue;

        public SkeinConfig(Skein source_hash)
        {
            m_StateSize = source_hash.StateSize;

            // Allocate config value
            m_ConfigValue = new ulong[source_hash.StateSize / 8];

            // Set the state size for the configuration
            m_ConfigString = new ulong[m_ConfigValue.Length];
            m_ConfigString[1] = (ulong) source_hash.StateSize;
        }

        public void GenerateConfiguration()
        {
            ThreefishCipher cipher = ThreefishCipher.CreateCipher(m_StateSize);
            UBITweak tweak = new UBITweak();
            ulong[] initial_state = new ulong[m_ConfigValue.Length];

            // Initialize the tweak value
            tweak.StartNewType(UBIType.Config);
            tweak.SetFinalFlag(true);
            tweak.IncrementCount(32);

            cipher.SetKey(initial_state);
            cipher.SetTweak(tweak.Tweak);
            cipher.Encrypt(m_ConfigString, m_ConfigValue);

            m_ConfigValue[0] ^= m_ConfigString[0];
            m_ConfigValue[1] ^= m_ConfigString[1];
        }

        public void SetSchema(byte[] schema)
        {
            if (schema.Length != 4) throw new Exception("Schema must be 4 bytes.");

            ulong n = m_ConfigString[0];

            // Clear the schema bytes
            n &= ~(ulong)0xffffffff;
            // Set schema bytes
            n |= (ulong) schema[3] << 24;
            n |= (ulong) schema[2] << 16;
            n |= (ulong) schema[1] << 8;
            n |= (ulong) schema[0];

            m_ConfigString[0] = n;
        }

        public void SetSchema(string schema)
        {
            byte[] schema_bytes = ASCIIEncoding.ASCII.GetBytes(schema);
            SetSchema(schema_bytes);
        }

        public void SetVersion(int version)
        {
            if (version < 0 || version > 3)
                throw new Exception("Version must be between 0 and 3, inclusive.");

            m_ConfigString[0] &= ~((ulong)0x03 << 32);
            m_ConfigString[0] |= (ulong)version << 32;
        }

        public ulong[] ConfigValue
        {
            get { return m_ConfigValue; }
        }

        public ulong[] ConfigString
        {
            get { return m_ConfigString; }
        }
    }
}
