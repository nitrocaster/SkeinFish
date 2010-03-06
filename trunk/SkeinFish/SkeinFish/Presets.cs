using System;


namespace SkeinFish
{
    public class Skein224 : Skein
    {
        public Skein224() : base(256, 224) { }
    }

    public class Skein256 : Skein
    {
        public Skein256() : base(256, 256) { }
    }

    public class Skein384 : Skein
    {
        public Skein384() : base(512, 384) { }
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
