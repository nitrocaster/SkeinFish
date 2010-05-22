using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace SkeinFish
{
    class SkeinTreeHash : HashAlgorithm
    {
        private byte[] _leafBuffer;


        public SkeinTreeHash(int nodeSize)
        {
            
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            throw new NotImplementedException();
        }

        protected override byte[] HashFinal()
        {
            throw new NotImplementedException();
        }

        public override void Initialize()
        {
            throw new NotImplementedException();
        }
    }
}
