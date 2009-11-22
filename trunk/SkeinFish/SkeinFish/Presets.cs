using System;


namespace SkeinFish
{
    public class Skein256 : Skein
    {
        public Skein256() : base(256, 256) { }
    }

    public class Skein512 : Skein
    {
        public Skein512() : base(512, 512) { }
    }

    public class Skein1024 : Skein
    {
        public Skein1024() : base(1024, 1024) { }
    }
}
