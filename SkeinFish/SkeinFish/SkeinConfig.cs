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
