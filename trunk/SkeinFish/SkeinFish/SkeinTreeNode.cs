using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;
using System.Text;

namespace SkeinFish
{
    public class SkeinTreeNode
    {
        private List<SkeinTreeNode> _parentNodes;
        private byte[] _nodeHash;
        private bool _isLeaf;

        public SkeinTreeNode(int hashSize)
        {
            _parentNodes = new List<SkeinTreeNode>();
            _nodeHash = new byte[hashSize];
        }

        public bool Verify()
        {
            var skein = new Skein(512, 8);
            SkeinTreeNode lastNode = null;

            skein.Initialize();

            foreach(var node in _parentNodes)
            {
                if (lastNode != null)
                {
                    if (node.Verify() == false)
                        return false;
                    skein.TransformBlock(node.Hash, 0, node.Hash.Length, null, 0);
                }

                lastNode = node;
            }

            if (lastNode != null)
            {
                if (lastNode.Verify() == false)
                    return false;
                skein.TransformFinalBlock(lastNode.Hash, 0, lastNode.Hash.Length);            
                
                // Compare hash with ours
                for (int i = 0; i < _nodeHash.Length; i++)
                {
                    if (_nodeHash[i] != skein.Hash[i])
                        return false;
                }
            }
            
            return true;
        }

        private int LevelInternal()
        {
            int maxLevel = 0;

            foreach(var node in _parentNodes)
            {
                int nodeLevel = node.LevelInternal();
                maxLevel = Math.Max(nodeLevel, maxLevel);
            }

            return maxLevel + 1;
        }
        
        public int Level
        {
            get { return LevelInternal(); }
        }

        public List<SkeinTreeNode> ParentNodes
        {
            get { return _parentNodes; }
        }

        public byte[] Hash
        {
            get { return _nodeHash; }
            set { _nodeHash = value;  }
        }

        public bool IsLeaf
        {
            get { return _isLeaf; }
            set { _isLeaf = value; }
        }
    }
}
