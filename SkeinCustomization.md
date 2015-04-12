# Introduction #

Skein allows one to customize the hash transformation.  This means that the hash can configured to output different hashes for the same messages, just by using "your own" configuration.  For example, an organization may wish to use Skein to define a totally different hash function.

# How To #

The following code demonstrates how to customize Skein:
```
using SkeinFish;

static byte[] hash_skein(byte[] input)
{
        // (state_size, output_size)
        Skein skein = new Skein(512, 512);

	// Set schema name, default for Skein is "SHA3"
	// (must be 4 bytes long)
	skein.Configuration.SetSchema(Encoding.ASCII.GetBytes("ABCD"));

	// Set the schema version, default for Skein is 1
	// (must be between 0 and 3, inclusive)	
	skein.Configuration.SetVersion(1);

	// Generate configuration
	skein.Configuration.GenerateConfiguration();

	// ComputeHash() automatically calls Initialize()
	// but if you're not using ComputeHash(), you should
	// call Initialize() now

        return skein.ComputeHash(input, 0, input.Length);
}

```