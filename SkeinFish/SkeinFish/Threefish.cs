using System;
using System.Security.Cryptography;

namespace SkeinFish
{
    public class Threefish : SymmetricAlgorithm
    {
        const int DEFAULT_CIPHER_SIZE = 256;

        public Threefish()
        {
            // Set up supported key and block sizes for Threefish
            KeySizes[] supported_sizes = 
            {
                new KeySizes(256, 512, 256),
                new KeySizes(1024, 1024, 0)
            };

            base.LegalBlockSizesValue = supported_sizes;
            base.LegalKeySizesValue   = supported_sizes;

            // Set up default sizes
            base.KeySizeValue   = DEFAULT_CIPHER_SIZE;
            base.BlockSizeValue = DEFAULT_CIPHER_SIZE;

            // ECB is the default for the other ciphers in
            // the standard library I think
            base.ModeValue = CipherMode.ECB;
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new ThreefishTransform(rgbKey, rgbIV, ThreefishTransformType.Decrypt, ModeValue);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return new ThreefishTransform(rgbKey, rgbIV, ThreefishTransformType.Encrypt, ModeValue);
        }

        public override void GenerateIV()
        {
            base.IVValue = GenerateRandomBytes(base.BlockSizeValue / 8);
        }

        public override void GenerateKey()
        {
            base.KeyValue = GenerateRandomBytes(base.KeySizeValue / 8);
        }

        static byte[] GenerateRandomBytes(int amount)
        {
            var rng_crypto = new RNGCryptoServiceProvider();

            byte[] bytes = new byte[amount];
            rng_crypto.GetBytes(bytes);

            return bytes;
        }
    }
}
