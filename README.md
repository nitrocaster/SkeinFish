# SkeinFish

[![Build status](https://ci.appveyor.com/api/projects/status/uk7spjrfikb4i26m/branch/master?svg=true)]
(https://ci.appveyor.com/project/nitrocaster/skeinfish/branch/master)

SkeinFish is an implementation of [Skein](https://en.wikipedia.org/wiki/Skein_hash_function) and [Threefish](https://en.wikipedia.org/wiki/Threefish), with a focus on speed and completeness.
Skein is a general purpose hash algorithm and Threefish is a general purpose block cipher.
Both were designed by Bruce Schneier, among others. This is an implementation of both algorithms in C#. 

## Quick and Dirty usage guide

First, add a reference to SkeinFish.dll to your project. Next, use as such:
```cs
    using SkeinFish;
    
    static byte[] hash_skein(byte[] input)
    {
        // (state_size, output_size)
        Skein skein = new Skein(512, 512);
        return skein.ComputeHash(input, 0, input.Length);
    }
```
## Using Threefish

The Threefish block cipher is also implemented as part of SkeinFish (hence the name).
To use it, simply instantiate a Threefish object and use it as you would any other cipher in the .NET library.
It supports all encryption modes except CTS. All padding modes are supported.

## Credits

This repository was originally hosted on [Google Code](http://code.google.com/p/skeinfish) by novachord@gmail.com
under [MIT License](http://opensource.org/licenses/mit-license.php).
