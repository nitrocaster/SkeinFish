using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace SkeinFish
{
    class SkeinTreeHash : HashAlgorithm
    {
        private byte[] _leafBuffer;
        private int _bytesFilled;
        private SkeinTreeNode _rootNode;
        private int _maxFanOut;

        private ulong[] _levelLengths = new ulong[256];
        private int _maxLevel;


        public SkeinTreeHash(int nodeSize, int maxFanOut)
        {
            
        }

        private SkeinTreeNode GetEmptyNode(SkeinTreeNode rootNode, int startLevel)
        {
            if(startLevel > 1 && rootNode.ParentNodes.Count < _maxFanOut)
            {
                SkeinTreeNode subNode;

                foreach(var node in rootNode.ParentNodes)
                {
                    subNode = GetEmptyNode(node, startLevel - 1);
                    if (subNode != null)
                        return subNode;

                }

                subNode = new SkeinTreeNode(1);
                
            }

            return null;
        }

        private void MoveBufferToTree(byte[] buffer)
        {
            var hasher = new Skein(256, 8);
            var newNode = GetEmptyNode(_rootNode, _rootNode.Level);
            
            newNode.Hash = hasher.ComputeHash(buffer);

            

        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for(int i = 0; i < cbSize; i++)
            {
                if(_bytesFilled == _leafBuffer.Length)
                {
                    // Add buffer to tree
                    _bytesFilled = 0;
                }

                _leafBuffer[_bytesFilled++] = array[ibStart + i];
            }
        }

        protected override byte[] HashFinal()
        {
            throw new NotImplementedException();
        }

        public override void Initialize()
        {
            _rootNode = new SkeinTreeNode(1);
            _bytesFilled = 0;
        }
    }
}
