using System;
using System.Security.Cryptography;

namespace SkeinFish
{
    public class Skein : HashAlgorithm
    {
        ThreefishCipher m_Cipher;

        int m_CipherStateBits;
        int m_CipherStateBytes;
        int m_CipherStateWords;

        int m_OutputBytes;

        byte[] m_InputBuffer;
        int m_BytesFilled;

        ulong[] m_CipherInput;
        ulong[] m_State;

        UBIType m_PayloadType;
        UBITweak m_Tweak;

        public Skein(int state_size, int output_size)
        {
            // Make sure the output bit size > 0
            if (output_size <= 0)
                throw new CryptographicException("Output bit size must be greater than zero.");

            m_CipherStateBits = state_size;
            m_CipherStateBytes = state_size / 8;
            m_CipherStateWords = state_size / 64;

            base.HashSizeValue = output_size;
            m_OutputBytes = (output_size + 7) / 8;

            // Figure out which cipher we need based on
            // the state size
            switch (state_size)
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
                    throw new CryptographicException("Unsupported state size.");
            }

            // Allocate buffers
            m_InputBuffer = new byte[m_CipherStateBytes];
            m_CipherInput = new ulong[m_CipherStateWords];
            m_State = new ulong[m_CipherStateWords];

            // Allocate tweak
            m_Tweak = new UBITweak();

            // Set default payload type (regular straight hashing)
            m_PayloadType = UBIType.Message;

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
                    GetBytes(m_InputBuffer, 0, m_CipherInput, m_CipherStateBytes);

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

            GetBytes(m_InputBuffer, 0, m_CipherInput, m_CipherStateBytes);

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
            ulong[] old_state = new ulong[m_CipherStateBytes];

            for (i = 0; i < m_OutputBytes; i += m_CipherStateBytes)
            {
                // Save old state
                for (j = 0; j < m_State.Length; j++)
                    old_state[j] = m_State[j];

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

        public override void Initialize()
        {
            // Clear state
            for (int i = 0; i < m_State.Length; i++)
                m_State[i] = 0;

            // Initialize configuration block
            m_CipherInput[0] = 0x133414853;
            m_CipherInput[1] = (ulong) base.HashSizeValue;

            // Set up tweak for configuration block
            m_Tweak.StartNewType(UBIType.Config);
            m_Tweak.SetFinalFlag(true);

            // Process config block
            ProcessBlock(32); // config block is actually 32 bytes

            // Set up tweak for message block
            m_Tweak.StartNewType(m_PayloadType);
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

        static void GetBytes(byte[] input, int offset, ulong[] output, int byte_count)
        {
            for (int i = 0; i < byte_count; i += 8)
            {
                output[i / 8] = GetUInt64(input, i + offset);
            }
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
