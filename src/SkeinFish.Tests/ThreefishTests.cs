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

using System.Security.Cryptography;
using NUnit.Framework;

namespace SkeinFish.Tests
{
    [TestFixture]
    public class ThreefishTests
    {
        [Test]
        public void TestThreefish256Ecb()
        {
            // 256 bit = 32 bytes
            byte[] input = {
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] goodCipher = {
                0xe7, 0xfe, 0x5b, 0x77, 0x7f, 0xdb, 0xea, 0x68,
                0x7e, 0x68, 0x7e, 0x83, 0x72, 0xcf, 0xdd, 0xfa,
                0x4e, 0xbd, 0x57, 0x4f, 0x47, 0xd4, 0x2d, 0x8c,
                0x07, 0xe9, 0xf7, 0xf6, 0x1a, 0x0c, 0x13, 0x7a
            };
            var thf = new Threefish
            {
                BlockSize = 256,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            var enc = thf.CreateEncryptor();
            var dec = thf.CreateDecryptor();
            var cipher = enc.TransformFinalBlock(input, 0, input.Length);
            var decipher = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            Assert.AreEqual(goodCipher, cipher, "Encrypt: 256 bit");
            Assert.AreEqual(input, decipher, "Decrypt: 256 bit");
        }
        
        [Test]
        public void TestThreefish512Ecb()
        {
            // 512 bit = 64 bytes
            byte[] input = {
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0,
                4, 0, 0, 0, 0, 0, 0, 0,
                5, 0, 0, 0, 0, 0, 0, 0,
                6, 0, 0, 0, 0, 0, 0, 0,
                7, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] goodCipher = {
                0xf6, 0x0c, 0x84, 0x98, 0x58, 0x2d, 0x09, 0x38,
                0xa5, 0x93, 0x59, 0x70, 0x4c, 0xfb, 0x92, 0x7e,
                0x7b, 0xb6, 0xe7, 0x0a, 0x06, 0x42, 0xcf, 0x45,
                0x36, 0xd6, 0x56, 0x01, 0x87, 0x89, 0xe8, 0x70,
                0x1e, 0xba, 0x54, 0x06, 0x1d, 0xf6, 0x3d, 0x75,
                0x49, 0xe6, 0x82, 0xe3, 0x23, 0x9e, 0x24, 0x08,
                0xf3, 0x70, 0x82, 0x5a, 0x32, 0xbe, 0x4b, 0x59,
                0xcf, 0x89, 0x4d, 0x73, 0x25, 0x37, 0x7a, 0xf2
            };
            var thf = new Threefish
            {
                BlockSize = 512,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            var enc = thf.CreateEncryptor();
            var dec = thf.CreateDecryptor();
            var cipher = enc.TransformFinalBlock(input, 0, input.Length);
            var decipher = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            Assert.AreEqual(goodCipher, cipher, "Encrypt: 512 bit");
            Assert.AreEqual(input, decipher, "Decrypt: 512 bit");
        }

        [Test]
        public void TestThreefish1024Ecb()
        {
            // 1024 bit = 128 bytes
            byte[] input = {
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0,
                4, 0, 0, 0, 0, 0, 0, 0,
                5, 0, 0, 0, 0, 0, 0, 0,
                6, 0, 0, 0, 0, 0, 0, 0,
                7, 0, 0, 0, 0, 0, 0, 0,
                8, 0, 0, 0, 0, 0, 0, 0,
                9, 0, 0, 0, 0, 0, 0, 0,
                10, 0, 0, 0, 0, 0, 0, 0,
                11, 0, 0, 0, 0, 0, 0, 0,
                12, 0, 0, 0, 0, 0, 0, 0,
                13, 0, 0, 0, 0, 0, 0, 0,
                14, 0, 0, 0, 0, 0, 0, 0,
                15, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] goodCipher = {
                0xf1, 0x14, 0x58, 0x92, 0xc9, 0xe6, 0xa8, 0x86,
                0xdb, 0x86, 0x58, 0x5d, 0x7d, 0x32, 0x88, 0xca,
                0xef, 0x8c, 0x6f, 0x3d, 0x01, 0x78, 0x0d, 0x23,
                0x45, 0xb7, 0x36, 0xf3, 0xf7, 0xf4, 0xe1, 0x65,
                0x41, 0x47, 0x8d, 0x09, 0x4f, 0x07, 0x46, 0xd8,
                0x4d, 0x98, 0x4a, 0xa9, 0x64, 0x86, 0x7c, 0x0e,
                0xc1, 0x97, 0x7f, 0x54, 0xed, 0x3d, 0x5c, 0x3d,
                0xd5, 0x27, 0xda, 0xbd, 0xa2, 0x78, 0x48, 0x6f,
                0xa7, 0x1c, 0xcf, 0xf2, 0x8c, 0x69, 0x31, 0x8d,
                0x6d, 0xb5, 0x80, 0x41, 0xc7, 0x28, 0x42, 0xd0,
                0x55, 0xf5, 0x6f, 0x70, 0xe2, 0xcc, 0xc1, 0xdd,
                0x21, 0x26, 0x8d, 0x2e, 0x0e, 0x69, 0x74, 0xcf,
                0x33, 0xa5, 0xab, 0x7d, 0x39, 0xb5, 0x23, 0x3f,
                0xdf, 0x16, 0xe2, 0xdc, 0x49, 0x9c, 0x7c, 0x79,
                0x75, 0xf4, 0xe5, 0xfb, 0x1d, 0x6f, 0x63, 0x82,
                0x58, 0xba, 0x5b, 0xab, 0xf4, 0xd5, 0x3c, 0xc7
            };
            var thf = new Threefish
            {
                BlockSize = 1024,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            var enc = thf.CreateEncryptor();
            var dec = thf.CreateDecryptor();
            var cipher = enc.TransformFinalBlock(input, 0, input.Length);
            var decipher = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            Assert.AreEqual(goodCipher, cipher, "Encrypt: 1024 bit");
            Assert.AreEqual(input, decipher, "Decrypt: 1024 bit");
        }

        [Test]
        public void TestThreefish256EcbPkcs7()
        {
            // 256 bit = 32 bytes
            // remove 4 trailing bytes to test padding
            byte[] input = {
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            };
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0
            };
            var thf = new Threefish {
                BlockSize = 256,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };
            var enc = thf.CreateEncryptor();
            var dec = thf.CreateDecryptor();
            var cipher = enc.TransformFinalBlock(input, 0, input.Length);
            var decipher = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            Assert.AreEqual(input, decipher);
        }

        [Test]
        public void TestThreefish512EcbPkcs7()
        {
            // 512 bit = 64 bytes
            // remove 8 trailing bytes to test padding
            byte[] input = {
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0,
                4, 0, 0, 0, 0, 0, 0, 0,
                5, 0, 0, 0, 0, 0, 0, 0,
                6, 0, 0, 0, 0, 0, 0, 0,
                7, 0, 0, 0, 0, 0, 0, 0
            };
            var thf = new Threefish
            {
                BlockSize = 512,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };
            var enc = thf.CreateEncryptor();
            var dec = thf.CreateDecryptor();
            var cipher = enc.TransformFinalBlock(input, 0, input.Length);
            var decipher = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            Assert.AreEqual(input, decipher);
        }

        [Test]
        public void TestThreefish1024EcbPkcs7()
        {
            // 1024 bit = 128 bytes
            // remove 16 trailing bytes to test padding
            byte[] input = {
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0,
                4, 0, 0, 0, 0, 0, 0, 0,
                5, 0, 0, 0, 0, 0, 0, 0,
                6, 0, 0, 0, 0, 0, 0, 0,
                7, 0, 0, 0, 0, 0, 0, 0,
                8, 0, 0, 0, 0, 0, 0, 0,
                9, 0, 0, 0, 0, 0, 0, 0,
                10, 0, 0, 0, 0, 0, 0, 0,
                11, 0, 0, 0, 0, 0, 0, 0,
                12, 0, 0, 0, 0, 0, 0, 0,
                13, 0, 0, 0, 0, 0, 0, 0,
                14, 0, 0, 0, 0, 0, 0, 0,
                15, 0, 0, 0, 0, 0, 0, 0
            };
            var thf = new Threefish
            {
                BlockSize = 1024,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };
            var enc = thf.CreateEncryptor();
            var dec = thf.CreateDecryptor();
            var cipher = enc.TransformFinalBlock(input, 0, input.Length);
            var decipher = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            Assert.AreEqual(input, decipher);
        }
    }
}
