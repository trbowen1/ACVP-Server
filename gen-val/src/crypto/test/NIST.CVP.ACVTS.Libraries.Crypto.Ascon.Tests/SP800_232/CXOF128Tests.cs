﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Tests.Core.TestCategoryAttributes;
using NIST.CVP.ACVTS.Libraries.Math.Helpers;
using NUnit.Framework;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace NIST.CVP.ACVTS.Libraries.Crypto.Ascon.Tests.SP800_232;

[TestFixture]
[FastCryptoTest]
public class CXOF128Tests
{
    private Crypto.Ascon.Ascon ascon = new Crypto.Ascon.Ascon();

    [Test]
    //1
    [TestCase("", "", 0, "4F50159EF70BB3DAD8807E034EAEBD44C4FA2CBBC8CF1F05511AB66CDCC529905CA12083FC186AD899B270B1473DC5F7EC88D1052082DCDFE69FB75D269E7B74", 512)]
    //2
    [TestCase("", "10", 8, "0C93A483E7D574D49FE52CCE03EE646117977D57A8AA57704AB4DAF44B501430FF6AC11A5D1FD6F2154B5C65728268270C8BB578508487B8965718ADA6272FD6", 512)]
    //9
    [TestCase("", "1011121314151617", 64, "61324766441DD6C11E1736BAD1D2185820885ED76FE2CE537775A6E855EEAFD2A6651B5E862A44982765F8B4C7CBE9C8B354F569EAD6ABC62CC9B7CDD72E0CB3", 512)]
    //10
    [TestCase("", "101112131415161718", 72, "32FDE6B9D290F56FC74AAC9368F32C69973E1BAB35D96118DB7181AAE577687673C01A9E35327ADED556987EED3441D4F42EC36B0C198498D9E7F357B948D560", 512)]
    //34
    [TestCase("00", "", 0, "7F0C0DDD4BC9603DEED19510CDB954D65CF254F59234BFBF5A730D03D2712DAAB9161C6553F65FA72A25B3174AC13A33218C393577A85B6D6F4319D1EF8A7541", 512)]
    //35
    [TestCase("00", "10", 8, "63FA8BA86382F2D544580F51322D080424B42C556EB74503CD73CF052BB993BD6F5210984C71C9C445F43CCC5B158226E509BD339CD634414377F79411AA8D5C", 512)]
    //265
    [TestCase("0001020304050607", "", 0, "2C076D8A559299E39D9C42D271B40CFD1072BEBFAC53C939B93150888588744036579FB25BF87A8A08924BC6194A6A6349DBF3D0046B03661E36466F46002532", 512)]
    //266
    [TestCase("0001020304050607", "10", 8, "72C1F546BD462150BB0F1C5F2A3A3693FD62909A79A411E5BB2DBAC12578A72AA6DB2CC91F88FF6D686CA05D357E69A98C9E85DD345B090AC34D066C86B4FCF2", 512)]
    //298
    [TestCase("000102030405060708", "", 0, "F4BDE749129C676DC47B76060AC2EECB8E42B169C22783DF441DD351ED944A806F30BA8E3D5210927E332459692A40969708183B1E50ADCD88C42D664476808E", 512)]
    //299
    [TestCase("000102030405060708", "10", 8, "4D925A93B21B32E47FC78BFBE5F883361F0EAD5AE3F6DA3BDA966CD2EC5855304A279B58F45E60FBC3E1D48566530C3A8B0C74DD6F0D72608750F3A710BA8E50", 512)]
    //1016
    [TestCase("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D", "101112131415161718191A1B1C1D1E1F202122232425262728", 200, "C784D871ABDA7BCDC84DCAFF1C8F5A322C3F619C85C174F1E44941BAB72C3F57B1C632A83BC95CDAD86AF7571F30BB715814BDE4AD62871E9A8BD3A1FE3CBC24", 512)]
    public void ShouldCXOFByteOrientedCorrectly(string messageString, string csString, int csLength, string digestString, int digestLength)
    {
        byte[] message = StringToHexBytes(messageString);
        byte[] cs = StringToHexBytes(csString); 
        int messageBitLength = message.Length * 8;

        byte[] digestBytes = ascon.CXof128(message, messageBitLength, cs, csLength, digestLength);

        string digest = "";

        for (int i = 0; i < digestBytes.Length; i++)
        {
            digest = digest + digestBytes[i].ToString("X2");
        }

        Assert.That(digest, Is.EqualTo(digestString));
    }

    [Test]
    [TestCase("01", 1, "", 0, "A6212C4EB567315CE280CD5D93BEEAA65AC8E0741BCF48745F11E7D76EF0609CD553790BBC5DFED0FC305E659987C273D479AA2BA678CA7436C0E035F9BD93DA", 512)]
    [TestCase("01", 1, "", 0, "A6212C4EB567315CE280CD5D93BEEAA65AC8E0741BCF48745F11E7D76EF0609CD553790BBC5DFED0FC305E659987C273D479AA2BA678CA7436C0E035F9BD935A", 511)]
    [TestCase("", 0, "01", 1, "A2D3B8FA6EA0461B8033FEF35AAA67F36FE90DAAEC42E059CD63EE4430DF64ED122901AFB880E259299FDEAD97042E10E04F986DDEDFBF1DC993BD1A18BD0B46", 512)]
    [TestCase("", 0, "01", 1, "A2D3B8FA6EA0461B8033FEF35AAA67F36FE90DAAEC42E059CD63EE4430DF64ED122901AFB880E259299FDEAD97042E10E04F986DDEDFBF1DC993BD1A18BD0B06", 510)]
    [TestCase("01", 1, "01", 1, "A4716404A21D93DF391BFF9B1084FEF2DC28FDF127E9ABFA5E9382260EEF7FE68DB638678570933C5F51B94E6E6E5649EC146D5E1478B2484ABA80AA6C848192", 512)]
    [TestCase("01", 1, "01", 1, "A4716404A21D93DF391BFF9B1084FEF2DC28FDF127E9ABFA5E9382260EEF7FE68DB638678570933C5F51B94E6E6E5649EC146D5E1478B2484ABA80AA6C848112", 511)]
    [TestCase("01", 1, "02", 2, "4070C4BDEA5FB536EF9DADE0C2D15C23499CC841367431125B4C4CA4E3112CC9287C1292EC50710364F0B547037DA4A5251E6F81D9B71350A6C916B337149CCD", 512)]
    public void ShouldCXOFBitOrientedCorrectly(string messageString, int messageBitLength, string csString, int csLength, string digestString, int digestLength)
    {
        byte[] message = StringToHexBytes(messageString);
        byte[] cs = StringToHexBytes(csString);

        byte[] digestBytes = ascon.CXof128(message, messageBitLength, cs, csLength, digestLength);

        string digest = "";

        for (int i = 0; i < digestBytes.Length; i++)
        {
            digest = digest + digestBytes[i].ToString("X2");
        }

        Assert.That(digest, Is.EqualTo(digestString));
    }

    [Test, Ignore("Debugging only")]
    [TestCase("000102030405060708090A0B0C0D0E0F", 128, "000102030405060708090A0B0C0D0E0F", 128, "30B0682E8BEC6515DB72978A32F0A43A", 128)]
    [TestCase("000102030405060708090A0B0C0D0E0F01", 129, "000102030405060708090A0B0C0D0E0F01", 129, "1170EED48E3F0C7960589AF689C9EBE200", 129)]
    public void GenerateIntermediateValuesCXOFBitOriented(string messageString, int messageBitLength, string csString, int csLength, string digestString, int digestLength)
    {
        byte[] message = StringToHexBytes(messageString);
        byte[] cs = StringToHexBytes(csString);

        Console.WriteLine("Ascon CXOF128\n");

        Console.WriteLine("message = " + messageString);
        Console.WriteLine("messageLen = " + messageBitLength);
        Console.WriteLine("customizationString = " + csString);
        Console.WriteLine("customizationStringLen = " + csLength);
        Console.WriteLine("digestLen = " + digestLength + "\n");

        byte[] digestBytes = ascon.CXof128(message, messageBitLength, cs, csLength, digestLength);

        string digest = "";

        for (int i = 0; i < digestBytes.Length; i++)
        {
            digest = digest + digestBytes[i].ToString("X2");
        }

        Console.WriteLine("\ndigest = " + digest);

        Assert.That(digest, Is.EqualTo(digestString));
    }

    [Test]
    public void ShouldCXOFAllValuesNoAnswers()
    {
        for (int i = 1; i <= 128; i++)
        {
            var m = new BitArray(i, true);
            var cs = new BitArray(i, true);
            ascon.CXof128(m.ToBytes(), i, cs.ToBytes(), i, i);
        }
    }

    private byte[] StringToHexBytes(string input)
    {
        byte[] output = new byte[input.Length / 2];
        for (int i = 0; i < input.Length; i = i + 2)
        {
            int num = Convert.ToInt32(input.Substring(i, 2), 16);
            output[i / 2] = (byte)num;
        }
        return output;
    }
}

