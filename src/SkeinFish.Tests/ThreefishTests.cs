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

Improvements and tweaks:
Copyright (c) 2015 Pavel Kovalenko
Same licence, etc. applies.
*/

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
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

        [Test]
        public void TestThreefish256EcbPkcs7Stream()
        {
            const string inputString = "Common salt is a mineral composed primarily of sodium chloride (NaCl), " +
                "a chemical compound belonging to the larger class of salts; salt in its natural form as a crystalline " +
                "mineral is known as rock salt or halite. Salt is present in vast quantities in seawater, where it is " +
                "the main mineral constituent; the open ocean has about 35 grams (1.2 oz.) of solids per liter, a " +
                "salinity of 3.5%.";
            var inputBytes = Encoding.UTF8.GetBytes(inputString);
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0
            };
            var thf = new Threefish
            {
                BlockSize = 256,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.PKCS7
            };
            var enc = thf.CreateEncryptor();
            byte[] encBytes;
            long encByteCount;
            using (var cipherMs = new MemoryStream())
            {
                using (var cs = new CryptoStream(cipherMs, enc, CryptoStreamMode.Write))
                {
                    cs.Write(inputBytes, 0, inputBytes.Length);
                    cs.FlushFinalBlock();
                    encBytes = cipherMs.GetBuffer();
                    encByteCount = cipherMs.Length;
                }
            }
            var dec = thf.CreateDecryptor();
            var decMs = new MemoryStream();
            var buf = new byte[4096];
            byte[] decBytes;
            long decByteCount;
            using (var cipherMs = new MemoryStream(encBytes, 0, (int)encByteCount))
            {
                using (var cs = new CryptoStream(cipherMs, dec, CryptoStreamMode.Read))
                {
                    for (int r; (r = cs.Read(buf, 0, buf.Length)) > 0;)
                        decMs.Write(buf, 0, r);
                    decBytes = decMs.GetBuffer();
                    decByteCount = decMs.Length;
                }
            }
            Array.Resize(ref decBytes, (int)decByteCount);
            Assert.AreEqual(inputBytes, decBytes);
        }

        [Test]
        public void TestThreefish256EcbAnsix923Stream()
        {
            const string inputString = "Common salt is a mineral composed primarily of sodium chloride (NaCl), " +
                "a chemical compound belonging to the larger class of salts; salt in its natural form as a crystalline " +
                "mineral is known as rock salt or halite. Salt is present in vast quantities in seawater, where it is " +
                "the main mineral constituent; the open ocean has about 35 grams (1.2 oz.) of solids per liter, a " +
                "salinity of 3.5%.";
            var inputBytes = Encoding.UTF8.GetBytes(inputString);
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0
            };
            var thf = new Threefish
            {
                BlockSize = 256,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.ANSIX923
            };
            var enc = thf.CreateEncryptor();
            byte[] encBytes;
            long encByteCount;
            using (var cipherMs = new MemoryStream())
            {
                using (var cs = new CryptoStream(cipherMs, enc, CryptoStreamMode.Write))
                {
                    cs.Write(inputBytes, 0, inputBytes.Length);
                    cs.FlushFinalBlock();
                    encBytes = cipherMs.GetBuffer();
                    encByteCount = cipherMs.Length;
                }
            }
            var dec = thf.CreateDecryptor();
            var decMs = new MemoryStream();
            var buf = new byte[4096];
            byte[] decBytes;
            long decByteCount;
            using (var cipherMs = new MemoryStream(encBytes, 0, (int)encByteCount))
            {
                using (var cs = new CryptoStream(cipherMs, dec, CryptoStreamMode.Read))
                {
                    for (int r; (r = cs.Read(buf, 0, buf.Length)) > 0; )
                        decMs.Write(buf, 0, r);
                    decBytes = decMs.GetBuffer();
                    decByteCount = decMs.Length;
                }
            }
            Array.Resize(ref decBytes, (int)decByteCount);
            Assert.AreEqual(inputBytes, decBytes);
        }

        [Test]
        public void TestThreefish256EcbIso10126Stream()
        {
            const string inputString = "Common salt is a mineral composed primarily of sodium chloride (NaCl), " +
                "a chemical compound belonging to the larger class of salts; salt in its natural form as a crystalline " +
                "mineral is known as rock salt or halite. Salt is present in vast quantities in seawater, where it is " +
                "the main mineral constituent; the open ocean has about 35 grams (1.2 oz.) of solids per liter, a " +
                "salinity of 3.5%.";
            var inputBytes = Encoding.UTF8.GetBytes(inputString);
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0,
                3, 0, 0, 0, 0, 0, 0, 0
            };
            var thf = new Threefish
            {
                BlockSize = 256,
                Key = key,
                IV = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.ISO10126
            };
            var enc = thf.CreateEncryptor();
            byte[] encBytes;
            long encByteCount;
            using (var cipherMs = new MemoryStream())
            {
                using (var cs = new CryptoStream(cipherMs, enc, CryptoStreamMode.Write))
                {
                    cs.Write(inputBytes, 0, inputBytes.Length);
                    cs.FlushFinalBlock();
                    encBytes = cipherMs.GetBuffer();
                    encByteCount = cipherMs.Length;
                }
            }
            var dec = thf.CreateDecryptor();
            var decMs = new MemoryStream();
            var buf = new byte[4096];
            byte[] decBytes;
            long decByteCount;
            using (var cipherMs = new MemoryStream(encBytes, 0, (int)encByteCount))
            {
                using (var cs = new CryptoStream(cipherMs, dec, CryptoStreamMode.Read))
                {
                    for (int r; (r = cs.Read(buf, 0, buf.Length)) > 0; )
                        decMs.Write(buf, 0, r);
                    decBytes = decMs.GetBuffer();
                    decByteCount = decMs.Length;
                }
            }
            Array.Resize(ref decBytes, (int)decByteCount);
            Assert.AreEqual(inputBytes, decBytes);
        }

        // Test vectors from the Skein 1.3 NIST CD
        [Test]
        public void TestThreefish256Nist00()
        {
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] input = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            ulong[] tweak = {0, 0};
            byte[] goodResult = {
                0x84, 0xDA, 0x2A, 0x1F, 0x8B, 0xEA, 0xEE, 0x94, 0x70, 0x66, 0xAE, 0x3E, 0x31, 0x03, 0xF1, 0xAD,
                0x53, 0x6D, 0xB1, 0xF4, 0xA1, 0x19, 0x24, 0x95, 0x11, 0x6B, 0x9F, 0x3C, 0xE6, 0x13, 0x3F, 0xD8
            };
            var thf = new Threefish
            {
                KeySize = 256,
                BlockSize = 256,
                Key = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            thf.SetTweak(tweak);
            var enc = thf.CreateEncryptor();
            var result = enc.TransformFinalBlock(input, 0, input.Length);
            Assert.AreEqual(goodResult, result);
        }
        
        [Test]
        public void TestThreefish256Nist01()
        {
            byte[] key = {
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
            };
            byte[] input = {
                0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
                0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
                0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0
            };
            ulong[] tweak = {0x0706050403020100, 0x0F0E0D0C0B0A0908};
            byte[] goodResult = {
                0xE0, 0xD0, 0x91, 0xFF, 0x0E, 0xEA, 0x8F, 0xDF,
                0xC9, 0x81, 0x92, 0xE6, 0x2E, 0xD8, 0x0A, 0xD5,
                0x9D, 0x86, 0x5D, 0x08, 0x58, 0x8D, 0xF4, 0x76,
                0x65, 0x70, 0x56, 0xB5, 0x95, 0x5E, 0x97, 0xDF
            };
            var thf = new Threefish
            {
                KeySize = 256,
                BlockSize = 256,
                Key = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            thf.SetTweak(tweak);
            var enc = thf.CreateEncryptor();
            var result = enc.TransformFinalBlock(input, 0, input.Length);
            Assert.AreEqual(goodResult, result);
        }

        [Test]
        public void TestThreefish512Nist00()
        {
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] input = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            ulong[] tweak = {0, 0};
            ulong[] goodResult = {
                0xB1, 0xA2, 0xBB, 0xC6, 0xEF, 0x60, 0x25, 0xBC,
                0x40, 0xEB, 0x38, 0x22, 0x16, 0x1F, 0x36, 0xE3,
                0x75, 0xD1, 0xBB, 0x0A, 0xEE, 0x31, 0x86, 0xFB,
                0xD1, 0x9E, 0x47, 0xC5, 0xD4, 0x79, 0x94, 0x7B,
                0x7B, 0xC2, 0xF8, 0x58, 0x6E, 0x35, 0xF0, 0xCF,
                0xF7, 0xE7, 0xF0, 0x30, 0x84, 0xB0, 0xB7, 0xB1,
                0xF1, 0xAB, 0x39, 0x61, 0xA5, 0x80, 0xA3, 0xE9,
                0x7E, 0xB4, 0x1E, 0xA1, 0x4A, 0x6D, 0x7B, 0xBE
            };
            var thf = new Threefish
            {
                KeySize = 512,
                BlockSize = 512,
                Key = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            thf.SetTweak(tweak);
            var enc = thf.CreateEncryptor();
            var result = enc.TransformFinalBlock(input, 0, input.Length);
            Assert.AreEqual(goodResult, result);
        }

        [Test]
        public void TestThreefish512Nist01()
        {
            byte[] key = {
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F
            };
            byte[] input = {
                0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
                0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
                0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
                0xDF, 0xDE, 0xDD, 0xDC, 0xDB, 0xDA, 0xD9, 0xD8,
                0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0,
                0xCF, 0xCE, 0xCD, 0xCC, 0xCB, 0xCA, 0xC9, 0xC8,
                0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, 0xC0
            };
            ulong[] tweak = {0x0706050403020100, 0x0F0E0D0C0B0A0908};
            byte[] goodResult = {
                0xE3, 0x04, 0x43, 0x96, 0x26, 0xD4, 0x5A, 0x2C,
                0xB4, 0x01, 0xCA, 0xD8, 0xD6, 0x36, 0x24, 0x9A,
                0x63, 0x38, 0x33, 0x0E, 0xB0, 0x6D, 0x45, 0xDD,
                0x8B, 0x36, 0xB9, 0x0E, 0x97, 0x25, 0x47, 0x79,
                0x27, 0x2A, 0x0A, 0x8D, 0x99, 0x46, 0x35, 0x04,
                0x78, 0x44, 0x20, 0xEA, 0x18, 0xC9, 0xA7, 0x25,
                0xAF, 0x11, 0xDF, 0xFE, 0xA1, 0x01, 0x62, 0x34,
                0x89, 0x27, 0x67, 0x3D, 0x5C, 0x1C, 0xAF, 0x3D
            };
            var thf = new Threefish
            {
                KeySize = 512,
                BlockSize = 512,
                Key = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            thf.SetTweak(tweak);
            var enc = thf.CreateEncryptor();
            var result = enc.TransformFinalBlock(input, 0, input.Length);
            Assert.AreEqual(goodResult, result);
        }

        [Test]
        public void TestThreefish1024Nist00()
        {
            byte[] key = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            byte[] input = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
            ulong[] tweak = {0, 0};
            byte[] goodResult= {
                0xF0, 0x5C, 0x3D, 0x0A, 0x3D, 0x05, 0xB3, 0x04,
                0xF7, 0x85, 0xDD, 0xC7, 0xD1, 0xE0, 0x36, 0x01,
                0x5C, 0x8A, 0xA7, 0x6E, 0x2F, 0x21, 0x7B, 0x06,
                0xC6, 0xE1, 0x54, 0x4C, 0x0B, 0xC1, 0xA9, 0x0D, 
    	   	    0xF0, 0xAC, 0xCB, 0x94, 0x73, 0xC2, 0x4E, 0x0F,
                0xD5, 0x4F, 0xEA, 0x68, 0x05, 0x7F, 0x43, 0x32,
                0x9C, 0xB4, 0x54, 0x76, 0x1D, 0x6D, 0xF5, 0xCF,
                0x7B, 0x2E, 0x9B, 0x36, 0x14, 0xFB, 0xD5, 0xA2,
			    0x0B, 0x2E, 0x47, 0x60, 0xB4, 0x06, 0x03, 0x54,
                0x0D, 0x82, 0xEA, 0xBC, 0x54, 0x82, 0xC1, 0x71,
                0xC8, 0x32, 0xAF, 0xBE, 0x68, 0x40, 0x6B, 0xC3,
                0x95, 0x00, 0x36, 0x7A, 0x59, 0x29, 0x43, 0xFA,
                0x9A, 0x5B, 0x4A, 0x43, 0x28, 0x6C, 0xA3, 0xC4,
                0xCF, 0x46, 0x10, 0x4B, 0x44, 0x31, 0x43, 0xD5,
                0x60, 0xA4, 0xB2, 0x30, 0x48, 0x83, 0x11, 0xDF,
                0x4F, 0xEE, 0xF7, 0xE1, 0xDF, 0xE8, 0x39, 0x1E
            };
            var thf = new Threefish
            {
                KeySize = 1024,
                BlockSize = 1024,
                Key = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            thf.SetTweak(tweak);
            var enc = thf.CreateEncryptor();
            var result = enc.TransformFinalBlock(input, 0, input.Length);
            Assert.AreEqual(goodResult, result);
        }

        [Test]
        public void TestThreefish1024Nist01()
        {
            byte[] key = {
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
                0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F
            };
            byte[] input = {
                0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
                0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
                0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
                0xDF, 0xDE, 0xDD, 0xDC, 0xDB, 0xDA, 0xD9, 0xD8,
                0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0,
                0xCF, 0xCE, 0xCD, 0xCC, 0xCB, 0xCA, 0xC9, 0xC8,
                0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, 0xC0,
                0xBF, 0xBE, 0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8,
                0xB7, 0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1, 0xB0,
                0xAF, 0xAE, 0xAD, 0xAC, 0xAB, 0xAA, 0xA9, 0xA8,
                0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1, 0xA0,
                0x9F, 0x9E, 0x9D, 0x9C, 0x9B, 0x9A, 0x99, 0x98,
                0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
                0x8F, 0x8E, 0x8D, 0x8C, 0x8B, 0x8A, 0x89, 0x88,
                0x87, 0x86, 0x85, 0x84, 0x83, 0x82, 0x81, 0x80
            };
            ulong[] tweak = {0x0706050403020100, 0x0F0E0D0C0B0A0908};
            byte[] goodResult = {
                0xA6, 0x65, 0x4D, 0xDB, 0xD7, 0x3C, 0xC3, 0xB0, 
                0x5D, 0xD7, 0x77, 0x10, 0x5A, 0xA8, 0x49, 0xBC, 
                0xE4, 0x93, 0x72, 0xEA, 0xAF, 0xFC, 0x55, 0x68, 
                0xD2, 0x54, 0x77, 0x1B, 0xAB, 0x85, 0x53, 0x1C, 
                0x94, 0xF7, 0x80, 0xE7, 0xFF, 0xAA, 0xE4, 0x30, 
                0xD5, 0xD8, 0xAF, 0x8C, 0x70, 0xEE, 0xBB, 0xE1,
                0x76, 0x0F, 0x3B, 0x42, 0xB7, 0x37, 0xA8, 0x9C, 
                0xB3, 0x63, 0x49, 0x0D, 0x67, 0x03, 0x14, 0xBD, 
                0x8A, 0xA4, 0x1E, 0xE6, 0x3C, 0x2E, 0x1F, 0x45, 
                0xFB, 0xD4, 0x77, 0x92, 0x2F, 0x83, 0x60, 0xB3, 
                0x88, 0xD6, 0x12, 0x5E, 0xA6, 0xC7, 0xAF, 0x0A, 
                0xD7, 0x05, 0x6D, 0x01, 0x79, 0x6E, 0x90, 0xC8, 
                0x33, 0x13, 0xF4, 0x15, 0x0A, 0x57, 0x16, 0xB3, 
                0x0E, 0xD5, 0xF5, 0x69, 0x28, 0x8A, 0xE9, 0x74, 
                0xCE, 0x2B, 0x43, 0x47, 0x92, 0x6F, 0xCE, 0x57, 
                0xDE, 0x44, 0x51, 0x21, 0x77, 0xDD, 0x7C, 0xDE 
            };
            var thf = new Threefish
            {
                KeySize = 1024,
                BlockSize = 1024,
                Key = key,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };
            thf.SetTweak(tweak);
            var enc = thf.CreateEncryptor();
            var result = enc.TransformFinalBlock(input, 0, input.Length);
            Assert.AreEqual(goodResult, result);
        }
    }
}
