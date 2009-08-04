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
using System.Security.Cryptography;

namespace SkeinFish
{
    public enum ThreefishTransformType
    {
        Encrypt, Decrypt
    }

    public class ThreefishTransform : ICryptoTransform
    {
        delegate void TransformFunc(ulong[] input, ulong[] output);
        delegate void CipherModeFunc();

        ThreefishTransformType m_TransformType;
        ThreefishCipher m_Cipher;
        TransformFunc m_TransformFunc;
        CipherModeFunc m_PreTransformFunc;
        CipherModeFunc m_PostTransformFunc;

        CipherMode  m_CipherMode;
        PaddingMode m_PaddingMode;

        int m_CipherBytes;
        int m_CipherWords;
        int m_CipherBits;

        ulong[] m_PreInputBlock;
        ulong[] m_InputBlock;
        ulong[] m_OutputBlock;
        ulong[] m_IV;

        public ThreefishTransform(byte[] key, byte[] iv, ThreefishTransformType type, CipherMode mode)
        {
            m_TransformType = type;
            m_CipherMode    = mode;

            m_CipherBytes = key.Length;
            m_CipherWords = key.Length / 8;
            m_CipherBits  = key.Length * 8;

            // Allocate working blocks now so that we don't
            // have to allocate them each time 
            // Transform(Final)Block is called
            m_PreInputBlock = new ulong[m_CipherWords];
            m_InputBlock = new ulong[m_CipherWords];
            m_OutputBlock = new ulong[m_CipherWords];

            // Allocate IV and set value
            m_IV = new ulong[m_CipherWords];
            GetBytes(iv, 0, m_IV, m_CipherBytes);

            // Figure out which cipher we need based on
            // the cipher bit size
            switch (m_CipherBits)
            {
                case 256:
                    m_Cipher = new Threefish256();
                    break;
                case 512:
                    m_Cipher = new Threefish512();
                    break;
                case 1024:
                    m_Cipher = new Threefish1024();
                    break;

                default:
                    throw new CryptographicException("Unsupported key/block size.");
            }

            // Get the transform function
            switch (type)
            {
                case ThreefishTransformType.Encrypt:
                    m_TransformFunc = new TransformFunc(m_Cipher.Encrypt);
                    m_PreTransformFunc = new CipherModeFunc(PreEncryptTransform);
                    m_PostTransformFunc = new CipherModeFunc(PostEncryptTransform);
                    break;
                case ThreefishTransformType.Decrypt:
                    m_TransformFunc = new TransformFunc(m_Cipher.Decrypt);
                    m_PreTransformFunc = new CipherModeFunc(PreDecryptTransform);
                    m_PostTransformFunc = new CipherModeFunc(PostDecryptTransform);
                    break;
            }

            // Set the key
            ulong[] key_words = new ulong[m_CipherWords];
            GetBytes(key, 0, key_words, m_CipherBytes);
            m_Cipher.SetKey(key_words);
        }

        static ulong GetUInt64(byte[] buf, int offset)
        {
            ulong v;
            v = (ulong)buf[offset];
            v |= (ulong)buf[offset + 1] << 8;
            v |= (ulong)buf[offset + 2] << 16;
            v |= (ulong)buf[offset + 3] << 24;
            v |= (ulong)buf[offset + 4] << 32;
            v |= (ulong)buf[offset + 5] << 40;
            v |= (ulong)buf[offset + 6] << 48;
            v |= (ulong)buf[offset + 7] << 56;
            return v;
        }

        static void PutUInt64(byte[] buf, int offset, ulong v)
        {
            buf[offset] = (byte)(v & 0xff);
            buf[offset + 1] = (byte)((v >> 8) & 0xff);
            buf[offset + 2] = (byte)((v >> 16) & 0xff);
            buf[offset + 3] = (byte)((v >> 24) & 0xff);
            buf[offset + 4] = (byte)((v >> 32) & 0xff);
            buf[offset + 5] = (byte)((v >> 40) & 0xff);
            buf[offset + 6] = (byte)((v >> 48) & 0xff);
            buf[offset + 7] = (byte)(v >> 56);
        }

        static void GetBytes(byte[] input, int offset, ulong[] output, int byte_count)
        {
            for (int i = 0; i < byte_count; i += 8)
            {
                output[i / 8] = GetUInt64(input, i + offset);
            }
        }

        static void PutBytes(ulong[] input, byte[] output, int offset, int byte_count)
        {
            for (int i = 0; i < byte_count; i += 8)
            {
                PutUInt64(output, i + offset, input[i / 8]);
            }
        }

        void PreEncryptTransform()
        {
            switch (m_CipherMode)
            {
                case CipherMode.ECB: break;
                case CipherMode.CBC:
                    // XOR the IV with the input block
                    for (int i = 0; i < m_CipherWords; i++)
                        m_InputBlock[i] = m_PreInputBlock[i] ^ m_IV[i];

                    break;

                case CipherMode.OFB:
                    break;
            }
        }

        void PostEncryptTransform()
        {
            switch (m_CipherMode)
            {
                case CipherMode.ECB: break;
                case CipherMode.CBC:
                    // Copy the block to the IV
                    for (int i = 0; i < m_CipherWords; i++)
                        m_OutputBlock[i] = m_IV[i];

                    break;
            }
        }

        void PreDecryptTransform()
        {
            switch (m_CipherMode)
            {
                case CipherMode.ECB: break;
                case CipherMode.CBC: break;
            }
        }

        void PostDecryptTransform()
        {
            switch (m_CipherMode)
            {
                case CipherMode.ECB: break;
                case CipherMode.CBC:
                    // XOR the IV with the output block,
                    // copy input block to IV
                    for (int i = 0; i < m_CipherWords; i++)
                    {
                        m_OutputBlock[i] ^= m_IV[i];
                        m_IV[i] = m_InputBlock[i];
                    }
                    break;
            }
        }

        #region ICryptoTransform Members

        public bool CanReuseTransform
        {
            get { throw new NotImplementedException(); }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public int InputBlockSize
        {
            get { return m_CipherBits; }
        }

        public int OutputBlockSize
        {
            get { return m_CipherBits; }
        }

        int TransformDivisibleByBlock(byte[] input, int input_offset, int input_count, byte[] output, int output_offset)
        {
            // Transform each block
            int end_offset = input_offset + input_count;
            int offset;

            for (offset = input_offset; offset < end_offset; offset += m_CipherBytes)
            {
                GetBytes(input, offset, m_PreInputBlock, m_CipherBytes);
                m_PreTransformFunc();
                m_TransformFunc(m_InputBlock, m_OutputBlock);
                m_PostTransformFunc();
                PutBytes(m_OutputBlock, output, offset + output_offset, m_CipherBytes);
            }

            return offset - input_offset;
        }

        void PadBlock(byte[] input)
        {
            // Get the input amount before we
            // resize the buffer
            int input_count = input.Length;
            // Resize array to match block size
            Array.Resize(ref input, m_CipherBytes);

            // Apply the type of padding we're using
            switch (m_PaddingMode)
            {
                case PaddingMode.None:
                case PaddingMode.Zeros:
                    break; // Array resize already filled it with zeros

                case PaddingMode.PKCS7:
                    // Fill each byte value with the number of
                    // bytes padded
                    for (int i = input_count; i < m_CipherBytes; i++)
                        input[i] = (byte) (m_CipherBytes - input_count);

                    break;

                case PaddingMode.ANSIX923:
                    // If there was padding done, set last byte 
                    // to number of bytes padded (bytes in between
                    // are zeros, already done by Array.Resize)
                    if (input_count < m_CipherBytes)
                        input[m_CipherBytes - 1] = (byte)(m_CipherBytes - input_count);

                    break;

                case PaddingMode.ISO10126:
                    // Fill remaining bytes with random values
                    if (input_count < m_CipherBytes)
                    {
                        byte[] rand_bytes;

                        rand_bytes = new byte[m_CipherBytes - input_count];
                        new RNGCryptoServiceProvider().GetBytes(rand_bytes);

                        for (int i = input_count; i < m_CipherBytes; i++)
                            input[i] = rand_bytes[i - input_count];
                    }

                    break;
            }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            // Make sure the input count is evenly
            // divisible by the block size
            if ((inputCount & (m_CipherBytes - 1)) != 0)
                throw new CryptographicException("inputCount must be divisible by the block size.");

            return TransformDivisibleByBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            // Encrypt as many blocks as we can
            // normally, without padding
            //int bytes_done = TransformDivisibleByBlock(
            return null;
        }

        #endregion

        #region IDisposable Members

        public void Dispose()
        {
            // nothing to dispose
        }

        #endregion
    }
}
