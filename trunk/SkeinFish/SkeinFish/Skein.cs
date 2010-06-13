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
using System.Security.Cryptography;

namespace SkeinFish
{
    public partial class Skein : HashAlgorithm
    {
        ThreefishCipher m_Cipher;
        SkeinConfig m_Configuration;

        readonly int m_CipherStateBits;
        readonly int m_CipherStateBytes;
        readonly int m_CipherStateWords;

        readonly int m_OutputBytes;

        byte[] m_InputBuffer;
        int m_BytesFilled;

        ulong[] m_CipherInput;
        ulong[] m_State;

        UBIType m_PayloadType;
        UBITweak m_Tweak;

        public int StateSize
        {
            get { return m_CipherStateBits; }
        }

        public SkeinConfig Configuration
        {
            get { return m_Configuration; }
        }
        
        /// <summary>
        /// Initializes the Skein hash instance.
        /// </summary>
        /// <param name="state_size">The internal state size of the hash in bits.
        /// Supported values are 256, 512, and 1024.</param>
        /// <param name="output_size">The output size of the hash in bits.
        /// Output size must be divisible by 8 and greater than zero.</param>
        public Skein(int state_size, int output_size)
        {
            // Make sure the output bit size > 0
            if (output_size <= 0)
                throw new CryptographicException("Output bit size must be greater than zero.");

            // Make sure output size is divisible by 8
            if (output_size % 8 != 0)
                throw new CryptographicException("Output bit size must be divisible by 8.");

            m_CipherStateBits = state_size;
            m_CipherStateBytes = state_size / 8;
            m_CipherStateWords = state_size / 64;

            base.HashSizeValue = output_size;
            m_OutputBytes = (output_size + 7) / 8;

            // Figure out which cipher we need based on
            // the state size
            m_Cipher = ThreefishCipher.CreateCipher(state_size);
            if (m_Cipher == null) throw new CryptographicException("Unsupported state size.");
            
            // Allocate buffers
            m_InputBuffer = new byte[m_CipherStateBytes];
            m_CipherInput = new ulong[m_CipherStateWords];
            m_State = new ulong[m_CipherStateWords];

            // Allocate tweak
            m_Tweak = new UBITweak();

            // Set default payload type (regular straight hashing)
            m_PayloadType = UBIType.Message;

            // Generate the configuration string
            m_Configuration = new SkeinConfig(this);
            m_Configuration.SetSchema("SHA3");
            m_Configuration.SetVersion(1);
            m_Configuration.GenerateConfiguration();

            // Initialize hash
            Initialize();
        }

        public UBIType UBIPayloadType
        {
            get { return m_PayloadType; }
            set
            {
                m_PayloadType = value;
                Initialize();
            }
        }
        
        void ProcessBlock(int bytes)
        {
            // Set the key to the current state
            m_Cipher.SetKey(m_State);

            // Update tweak
            m_Tweak.IncrementCount(bytes);
            m_Cipher.SetTweak(m_Tweak.Tweak);

            // Encrypt block
            m_Cipher.Encrypt(m_CipherInput, m_State);

            // Feed-forward input with state
            for (int i = 0; i < m_CipherInput.Length; i++)
            {
                m_State[i] ^= m_CipherInput[i];
            }
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int bytes_done = 0;
            int offset = ibStart;

            // Fill input buffer
            while (bytes_done < cbSize && offset < array.Length)
            {
                // Do a transform if the input buffer is filled
                if (m_BytesFilled == m_CipherStateBytes)
                {
                    // Copy input buffer to cipher input buffer
                   // GetBytes(m_InputBuffer, 0, m_CipherInput, m_CipherStateBytes);
                    InputBufferToCipherInput();
                    
                    // Process the block
                    ProcessBlock(m_CipherStateBytes);

                    // Clear first flag, which may be set
                    // by Initialize() if this is the first transform
                    m_Tweak.SetFirstFlag(false);

                    // Reset buffer fill count
                    m_BytesFilled = 0;
                }

                m_InputBuffer[m_BytesFilled++] = array[offset++];
                bytes_done++;
            }
        }

        protected override byte[] HashFinal()
        {
            int i;

            // Pad left over space in input buffer with zeros
            // and copy to cipher input buffer
            for (i = m_BytesFilled; i < m_InputBuffer.Length; i++)
                m_InputBuffer[i] = 0;

            InputBufferToCipherInput();
            
            // Do final message block
            m_Tweak.SetFinalFlag(true);
            ProcessBlock(m_BytesFilled);

            // Clear cipher input
            for (i = 0; i < m_CipherInput.Length; i++)
                m_CipherInput[i] = 0;

            // Do output block counter mode output
            int output_size;
            int j;

            byte[] hash = new byte[m_OutputBytes];
            ulong[] old_state = new ulong[m_CipherStateWords];

            // Save old state
            for (j = 0; j < m_State.Length; j++)
                old_state[j] = m_State[j];

            for (i = 0; i < m_OutputBytes; i += m_CipherStateBytes)
            {
                m_Tweak.StartNewType(UBIType.Out); 
                m_Tweak.SetFinalFlag(true);
                ProcessBlock(8);

                // Output a chunk of the hash
                output_size = m_OutputBytes - i;
                if (output_size > m_CipherStateBytes)
                    output_size = m_CipherStateBytes;

                PutBytes(m_State, hash, i, output_size);

                // Restore old state
                for (j = 0; j < m_State.Length; j++)
                    m_State[j] = old_state[j];

                // Increment counter
                m_CipherInput[0]++;
            }
                                    
            return hash;
        }

        public sealed override void Initialize()
        {
            // Copy the configuration value to the state
            for (int i = 0; i < m_State.Length; i++)
                m_State[i] = m_Configuration.ConfigValue[i];

            // Set up tweak for message block
            m_Tweak.StartNewType(m_PayloadType);

            // Reset bytes filled
            m_BytesFilled = 0;
        }

        // Moves the byte input buffer to the ulong cipher input
        void InputBufferToCipherInput()
        {
            for (int i = 0; i < m_CipherStateWords; i++)
                m_CipherInput[i] = GetUInt64(m_InputBuffer, i * 8);
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

        static void PutBytes(ulong[] input, byte[] output, int offset, int byte_count)
        {
            int j = 0;
            for (int i = 0; i < byte_count; i++)
            {
                //PutUInt64(output, i + offset, input[i / 8]);
                output[offset + i] = (byte) ((input[i / 8] >> j) & 0xff);
                j = (j + 8) % 64;
            }
        }

        #endregion
    }
}
