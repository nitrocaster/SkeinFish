SkeinFish is an implementation of Skein and Threefish, with a focus on speed and completeness.  Skein is a general purpose hash algorithm and Threefish is a general purpose block cipher.  Both were designed by Bruce Schneier, among others.

This is an implementation of both algorithms in C#.

# Changelog #

### 0.5.0 ###
  * Updated to Skein 1.3

### 0.4.5 ###
  * New Initialize() overloads to enable any custom UBI chaining, such as [MAC Hashing](http://code.google.com/p/skeinfish/wiki/MAC_Hashing)
  * Exposed the UBI tweaking interface.
  * Code refactoring, changes, and cleanups
  * Minor bug fixes

### 0.4.1 ###
  * Fixed some long standing bugs

### 0.4 ###
  * Added supplementary Skein testing project
  * Added benchmarking function
  * Added self-test validation function
  * Added template classes for SHA3 output sizes
  * Small performance improvements
  * Bug fixes

### 0.3.5 ###
  * Implemented Skein 1.2.

# Quick and Dirty usage guide #

First, add a reference to SkeinFish.dll to your project.  Next, use as such:
```
using SkeinFish;

static byte[] hash_skein(byte[] input)
{
	// (state_size, output_size)
	Skein skein = new Skein(512, 512); 
	
	return skein.ComputeHash(input, 0, input.Length);
}

```

# Using Threefish #

The Threefish block cipher is also implemented as part of SkeinFish (hence the name).  To use it, simply instantiate a `Threefish` object and use it as you would any other cipher in the .NET library.  It supports all encryption modes except CTS.  All padding modes are supported.