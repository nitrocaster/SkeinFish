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
using System.Text;
using System.Security.Cryptography;

namespace SkeinFish
{
    public class SkeinConfig
    {
        private readonly int _stateSize;
        private ulong[] _configString;
        private ulong[] _configValue;

        public SkeinConfig(Skein sourceHash)
        {
            _stateSize = sourceHash.StateSize;

            // Allocate config value
            _configValue = new ulong[sourceHash.StateSize / 8];

            // Set the state size for the configuration
            _configString = new ulong[_configValue.Length];
            _configString[1] = (ulong) sourceHash.HashSize;
        }

        public void GenerateConfiguration()
        {
            var cipher = ThreefishCipher.CreateCipher(_stateSize);
            var tweak = new UbiTweak();
            var initialState = new ulong[_configValue.Length];

            // Initialize the tweak value
            tweak.StartNewType(UbiType.Config);
            tweak.SetFinalFlag(true);
            tweak.BitsProcessed += 32;

            cipher.SetKey(initialState);
            cipher.SetTweak(tweak.Tweak);
            cipher.Encrypt(_configString, _configValue);

            _configValue[0] ^= _configString[0]; 
            _configValue[1] ^= _configString[1];
            _configValue[2] ^= _configString[2];
        }

        public void SetSchema(params byte[] schema)
        {
            if (schema.Length != 4) throw new Exception("Schema must be 4 bytes.");

            ulong n = _configString[0];

            // Clear the schema bytes
            n &= ~(ulong)0xfffffffful;
            // Set schema bytes
            n |= (ulong) schema[3] << 24;
            n |= (ulong) schema[2] << 16;
            n |= (ulong) schema[1] << 8;
            n |= (ulong) schema[0];

            _configString[0] = n;
        }

        public void SetVersion(int version)
        {
            if (version < 0 || version > 3)
                throw new Exception("Version must be between 0 and 3, inclusive.");

            _configString[0] &= ~((ulong)0x03 << 32);
            _configString[0] |= (ulong)version << 32;
        }

        public void SetTreeLeafSize(byte size)
        {
            _configString[2] &= ~(ulong)0xff;
            _configString[2] |= (ulong)size;
        }

        public void SetTreeFanOutSize(byte size)
        {
            _configString[2] &= ~((ulong)0xff << 8);
            _configString[2] |= (ulong)size << 8;
        }

        public void SetMaxTreeHeight(byte height)
        {
            if (height == 1)
                throw new Exception("Tree height must be zero or greater than 1.");

            _configString[2] &= ~((ulong)0xff << 16);
            _configString[2] |= (ulong)height << 16;
        }

        public ulong[] ConfigValue
        {
            get { return _configValue; }
        }

        public ulong[] ConfigString
        {
            get { return _configString; }
        }
    }
}
