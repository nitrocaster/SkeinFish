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
        delegate int TransformFunc(byte[] input, int input_offset, int input_count, byte[] output, int output_offset);

        ThreefishTransformType m_TransformType;
        ThreefishCipher m_Cipher;
        TransformFunc m_TransformFunc;
        
        CipherMode  m_CipherMode;
        PaddingMode m_PaddingMode;

        int m_CipherBytes;
        int m_CipherWords;
        int m_CipherBits;

        ulong[] m_Block;
        ulong[] m_TempBlock;
        ulong[] m_IV;
        
        // Used when in a stream ciphering mode
        byte[] m_StreamBytes;
        int m_UsedStreamBytes;

        public ThreefishTransform(
            byte[] key, byte[] iv, ThreefishTransformType type, CipherMode mode, PaddingMode padding
        )
        {
            m_TransformType = type;
            m_CipherMode    = mode;
            m_PaddingMode   = padding;

            m_CipherBytes = key.Length;
            m_CipherWords = key.Length / 8;
            m_CipherBits  = key.Length * 8;

            // Allocate working blocks now so that we don't
            // have to allocate them each time 
            // Transform(Final)Block is called
            m_Block = new ulong[m_CipherWords];
            m_TempBlock = new ulong[m_CipherWords];
            m_StreamBytes = new byte[m_CipherBytes];
            m_UsedStreamBytes = m_CipherBytes;

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

            bool e = (type == ThreefishTransformType.Encrypt);

            switch(m_CipherMode)
            {
                case CipherMode.ECB:
                    m_TransformFunc = e ? new TransformFunc(ECB_Encrypt) : new TransformFunc(ECB_Decrypt);
                    break;
                case CipherMode.CBC:
                    m_TransformFunc = e ? new TransformFunc(CBC_Encrypt) : new TransformFunc(CBC_Decrypt);
                    break;
                case CipherMode.OFB:
                    m_TransformFunc = new TransformFunc(OFB_ApplyStream);
                    break;
            }

            // Set the key
            ulong[] key_words = new ulong[m_CipherWords];
            GetBytes(key, 0, key_words, m_CipherBytes);
            m_Cipher.SetKey(key_words);

            InitializeBlocks();
        }

        // (Re)initializes the blocks for encryption
        void InitializeBlocks()
        {
            switch (m_CipherMode)
            {
                case CipherMode.ECB:
                case CipherMode.CBC:
                    // Clear the working block
                    for (int i = 0; i < m_CipherWords; i++)
                        m_Block[i] = 0;
                    break;

                case CipherMode.OFB:
                    // Copy the IV to the working block
                    for (int i = 0; i < m_CipherWords; i++)
                        m_Block[i] = m_IV[i];

                    break;
            }
        }

        #region Utils

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

        #endregion

        #region ModeTransformFunctions

        // ECB mode encryption
        int ECB_Encrypt(byte[] input, int input_offset, int input_count, byte[] output, int output_offset)
        {
            if (input_count >= m_CipherBytes)
            {
                GetBytes(input, input_offset, m_Block, m_CipherBytes);
                m_Cipher.Encrypt(m_Block, m_Block);
                PutBytes(m_Block, output, output_offset, m_CipherBytes);

                return m_CipherBytes;
            }

            return 0;
        }

        // ECB mode decryption
        int ECB_Decrypt(byte[] input, int input_offset, int input_count, byte[] output, int output_offset)
        {
            if (input_count >= m_CipherBytes)
            {
                GetBytes(input, input_offset, m_Block, m_CipherBytes);
                m_Cipher.Decrypt(m_Block, m_Block);
                PutBytes(m_Block, output, output_offset, m_CipherBytes);

                return m_CipherBytes;
            }

            return 0;
        }

        // CBC mode encryption
        int CBC_Encrypt(byte[] input, int input_offset, int input_count, byte[] output, int output_offset)
        {
            if (input_count >= m_CipherBytes)
            {
                int i;

                GetBytes(input, input_offset, m_Block, m_CipherBytes);

                // Apply the IV
                for (i = 0; i < m_CipherWords; i++)
                    m_Block[i] ^= m_IV[i];

                m_Cipher.Encrypt(m_Block, m_Block);

                // Copy the output to the IV
                for (i = 0; i < m_CipherWords; i++)
                    m_IV[i] = m_Block[i];

                PutBytes(m_Block, output, output_offset, m_CipherBytes);

                return m_CipherBytes;
            }

            return 0;
        }

        // CBC mode encryption
        int CBC_Decrypt(byte[] input, int input_offset, int input_count, byte[] output, int output_offset)
        {
            if (input_count >= m_CipherBytes)
            {
                int i;

                GetBytes(input, input_offset, m_Block, m_CipherBytes);
                
                // Copy the block to the temp block for later (wink wink)
                for (i = 0; i < m_CipherWords; i++)
                    m_TempBlock[i] = m_Block[i];

                m_Cipher.Decrypt(m_Block, m_Block);

                // Apply the IV and copy temp block
                // to IV
                for (i = 0; i < m_CipherWords; i++)
                {
                    m_Block[i] ^= m_IV[i];
                    m_IV[i] = m_TempBlock[i];
                }

                PutBytes(m_Block, output, output_offset, m_CipherBytes);

                return m_CipherBytes;
            }

            return 0;
        }

        // OFB mode encryption/decryption
        int OFB_ApplyStream(byte[] input, int input_offset, int input_count, byte[] output, int output_offset)
        {
            int i;

            // Input length doesn't matter in OFB, just encrypt
            // as much as we can
            for (i = 0; i < input_count; i++)
            {
                // Generate new stream bytes if we've used
                // them all up
                if (m_UsedStreamBytes >= m_CipherBytes)
                {
                    m_Cipher.Encrypt(m_Block, m_Block);
                    PutBytes(m_Block, m_StreamBytes, 0, m_CipherBytes);
                    m_UsedStreamBytes = 0;
                }

                // XOR input byte with stream byte, output it
                output[output_offset + i] = (byte)(input[input_offset + i] ^
                                             m_StreamBytes[m_UsedStreamBytes]);
                m_UsedStreamBytes++;
            }

            // Return bytes done
            return i;
        }

        #endregion


        #region ICryptoTransform Members

        public bool CanReuseTransform
        {
            get { return true; }
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

 


        void PadBlock(byte[] input, int input_offset, int already_filled)
        {
            // Apply the type of padding we're using
            switch (m_PaddingMode)
            {
                case PaddingMode.None: break;
                case PaddingMode.Zeros:
                    // Fill with zeros
                    for (int i = already_filled; i < m_CipherBytes; i++)
                        input[i + input_offset] = 0;

                    break;

                case PaddingMode.PKCS7:
                    // Fill each byte value with the number of
                    // bytes padded
                    for (int i = already_filled; i < m_CipherBytes; i++)
                        input[i + input_offset] = (byte) (m_CipherBytes - already_filled);

                    break;

                case PaddingMode.ANSIX923:
                    // fill with zeros, set last byte
                    // to number of bytes padded
                    for (int i = already_filled; i < m_CipherBytes; i++)
                    {
                        input[i + input_offset] = 0;
                        // If its the last byte, set to number of bytes padded
                        if (i == m_CipherBytes - 1)
                            input[i + input_offset] = (byte)(m_CipherBytes - already_filled);
                    }

                    break;

                case PaddingMode.ISO10126:
                    // Fill remaining bytes with random values
                    if (already_filled < m_CipherBytes)
                    {
                        byte[] rand_bytes;

                        rand_bytes = new byte[m_CipherBytes - already_filled];
                        new RNGCryptoServiceProvider().GetBytes(rand_bytes);

                        for (int i = already_filled; i < m_CipherBytes; i++)
                            input[i + input_offset] = rand_bytes[i - already_filled];
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

            int total_done = 0;
            int done;
            // Apply as much of the transform as we can
            do
            {
                done = m_TransformFunc(
                    inputBuffer,
                    inputOffset + total_done,
                    inputCount - total_done,
                    outputBuffer,
                    outputOffset + total_done
                    );

                total_done += done;

            } while (done > m_CipherBytes);
           
            return total_done;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] output = new byte[inputCount];

            int total_done = 0;
            int done;
            // Apply as much of the transform as we can
            do
            {
                done = m_TransformFunc(
                    inputBuffer,
                    inputOffset + total_done,
                    inputCount - total_done,
                    output,
                    total_done
                    );

                total_done += done;

            } while (done > m_CipherBytes);

            int remaining = inputCount - total_done;

            // Do the padding and the final transform if
            // there's any data left
            if (total_done < inputCount)
            {
                // Resize output buffer to be evenly
                // divisible by the block size
                // (m_CipherBytes is always a power of 2 here,
                // so we can just do the & trick with m_CipherBytes - 1
                // to get a really small and probably insignificant speedup)
                int output_size = inputCount + (m_CipherBytes - (inputCount & (m_CipherBytes - 1)));
                Array.Resize(ref output, output_size);
                
                // Copy remaining bytes over to the output
                for (int i = 0; i < remaining; i++)
                    output[i + total_done] = inputBuffer[inputOffset + total_done + i];

                // Pad the block
                PadBlock(output, total_done, remaining);

                // Encrypt the block
                m_TransformFunc(output, total_done, m_CipherBytes, output, total_done);
            }

            // Reinitialize the cipher
            InitializeBlocks();

            return output;

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
