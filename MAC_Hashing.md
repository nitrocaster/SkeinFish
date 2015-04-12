# Introduction #

Skein supports a way to implement a MAC without the performance overhead of other MAC hashing modes, such as HMAC.  Although Skein can be implemented as an HMAC, this article will introduce a way to create a MAC with SkeinFish using the method outlined in the Skein paper.

# Details #

Starting with version 0.4.5, it is possible to create arbitrary chaining of the UBI construction used in Skein.  This is done using the new overloaded Initialize() function.

# Example #

The code below implements a sample MAC hash using the method outlined in the Skein paper:

```
// key is 512 bits, since this example uses Skein512.
static byte[] MAC_Hash(byte[] key, byte[] data)
{
    var skein = new Skein512();

    // Hash a block of type 'Key'
    skein.Initialize(SkeinInitializationType.ZeroedState);
    skein.UbiParameters.StartNewBlockType(UbiType.Key);
    skein.TransformFinalBlock(key, 0, key.Length);

    // Chain in a standard Skein hash
    skein.Initialize(SkeinInitializationType.ChainedConfig);
    skein.TransformFinalBlock(data, 0, data.Length);

    return skein.Hash;
}
```