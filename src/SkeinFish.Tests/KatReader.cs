/*
Copyright (c) 2010 Werner Dittmann

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

C# rewrite:
Copyright (c) 2015 Pavel Kovalenko
Same licence, etc. applies.
*/

using System;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;

namespace SkeinFish.Tests
{
    internal class KatResult
    {
        public int StateSize;
        public int HashBitLength;
        public int MsgLength; // message length in bits
        public byte[] Msg;
        public int MsgFill;
        public byte[] Result;
        public int ResultFill;
        public int MacKeyLen; // MAC length in bytes
        public byte[] MacKey;
        public int MacKeyFill;
        public string TrailingChars;
    }

    internal sealed class KatReader
    {
        private enum ScannerState
        {
            Start,
            Message,
            Result,
            MacKeyHeader,
            MacKey,
            Done
        }

        private static readonly char[] ByteSeparators = {' ', '\t'};
        private readonly StreamReader reader;
        private ScannerState state = ScannerState.Start;

        public KatReader(string fileName)
        { reader = new StreamReader(fileName); }

        public int CurrentLine { get; private set; }

        /// <summary>
        /// Fill in data from KAT file, one complete element at a time.
        /// </summary>
        /// <param name="kr">The resulting KAT data.</param>
        /// <returns></returns>
        public bool FillResult(KatResult kr)
        {
            var dataFound = false;
            while (state!=ScannerState.Done && !reader.EndOfStream)
            {
                CurrentLine++;
                ParseLine(reader.ReadLine(), kr);
                dataFound = true;
            }
            state = ScannerState.Start;
            return dataFound;
        }

        private void ParseLine(string line, KatResult kr)
        {
            line = line.Trim();
            if (line.Length<=1)
                return;
            if (line.StartsWith("Message"))
            {
                state = ScannerState.Message;
                return;
            }
            if (line.StartsWith("Result"))
            {
                state = ScannerState.Result;
                return;
            }
            if (line.StartsWith("MAC"))
                state = ScannerState.MacKeyHeader;
            else if (line.StartsWith("------"))
            {
                state = ScannerState.Done;
                return;
            }
            switch (state)
            {
            case ScannerState.Start:
                if (line.StartsWith(":Skein-"))
                    ParseHeaderLine(line, kr);
                else
                    throw new FormatException(String.Format("Invalid entry format (line {0})", CurrentLine));
                break;
            case ScannerState.Message:
                ParseMessageLine(line, kr);
                break;
            case ScannerState.Result:
                ParseResultLine(line, kr);
                break;
            case ScannerState.MacKey:
                ParseMacKeyLine(line, kr);
                break;
            case ScannerState.MacKeyHeader:
                ParseMacKeyHeaderLine(line, kr);
                break;
            }
        }

        private void ParseMessageLine(string line, KatResult kr)
        {
            if (line.Contains("(none)"))
            {
                kr.Msg[kr.MsgFill++] = 0;
                return;
            }
            var msgBytes = line.Split(ByteSeparators, StringSplitOptions.RemoveEmptyEntries);
            foreach (var sb in msgBytes)
            {
                byte b;
                if (byte.TryParse(sb, NumberStyles.HexNumber, null, out b))
                    kr.Msg[kr.MsgFill++] = b;
                else
                    throw new FormatException(String.Format("Invalid message format (line {0})", CurrentLine));
            }
        }

        private void ParseMacKeyLine(string line, KatResult kr)
        {
            if (line.Contains("(none)"))
                return;
            var macBytes = line.Split(ByteSeparators, StringSplitOptions.RemoveEmptyEntries);
            foreach (var sb in macBytes)
            {
                byte b;
                if (byte.TryParse(sb, NumberStyles.HexNumber, null, out b))
                    kr.MacKey[kr.MacKeyFill++] = b;
                else
                    throw new FormatException(String.Format("Invalid message format (line {0})", CurrentLine));
            }
        }

        private void ParseMacKeyHeaderLine(string line, KatResult kr)
        {
            var rx = new Regex(".*=\\s*(\\d+) .*");
            Match result = rx.Match(line);
            if (!result.Success)
                throw new FormatException(String.Format("Invalid MAC key header line format (line {0})", CurrentLine));
            kr.MacKeyLen = int.Parse(result.Groups[1].Value);
            kr.MacKey = new byte[kr.MacKeyLen];
            state = ScannerState.MacKey;
        }

        private void ParseResultLine(string line, KatResult kr)
        {
            var resultBytes = line.Split(ByteSeparators, StringSplitOptions.RemoveEmptyEntries);
            foreach (var sb in resultBytes)
            {
                byte b;
                if (byte.TryParse(sb, NumberStyles.HexNumber, null, out b))
                    kr.Result[kr.ResultFill++] = b;
                else
                    throw new FormatException(String.Format("Invalid result format (line {0})", CurrentLine));
            }
        }

        private void ParseHeaderLine(string line, KatResult kr)
        {
            var rx = new Regex(":Skein-(\\d+):\\s*(\\d+)-.*=\\s*(\\d+) bits(.*)");
            Match result = rx.Match(line);
            if (!result.Success)
                throw new FormatException(String.Format("Invalid header format (line {0})", CurrentLine));
            kr.StateSize = int.Parse(result.Groups[1].Value);
            kr.HashBitLength = int.Parse(result.Groups[2].Value);
            kr.MsgLength = int.Parse(result.Groups[3].Value);
            kr.TrailingChars = result.Groups[4].Value;
            if (kr.MsgLength==0 || kr.MsgLength%8!=0)
                kr.Msg = new byte[(kr.MsgLength>>3)+1];
            else
                kr.Msg = new byte[kr.MsgLength>>3];
            if (kr.HashBitLength%8!=0)
                kr.Result = new byte[(kr.HashBitLength>>3)+1];
            else
                kr.Result = new byte[kr.HashBitLength>>3];
            kr.MsgFill = 0;
            kr.ResultFill = 0;
            kr.MacKeyFill = 0;
        }
    }
}
