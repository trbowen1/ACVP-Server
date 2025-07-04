﻿using System.Collections.Generic;
using NIST.CVP.ACVTS.Libraries.Generation.HMAC.v1_0;
using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Generation.Tests.HMAC.v1_0
{
    public static class TestDataMother
    {
        public static TestVectorSet GetTestGroups(int groups = 1)
        {
            var vectorSet = new TestVectorSet();

            var testGroups = new List<TestGroup>();
            vectorSet.TestGroups = testGroups;
            for (int groupIdx = 0; groupIdx < groups; groupIdx++)
            {
                var tg = new TestGroup
                {
                    KeyLength = 128 + groupIdx * 2,
                    MessageLength = 52 + groupIdx * 8,
                    MacLength = 64,
                    TestType = "AFT"
                };
                testGroups.Add(tg);

                var tests = new List<TestCase>();
                tg.Tests = tests;

                for (int testId = 15 * groupIdx + 1; testId <= (groupIdx + 1) * 15; testId++)
                {
                    tests.Add(new TestCase
                    {
                        Message = new BitString("FACE"),
                        Mac = new BitString("CAFE"),
                        Key = new BitString("9998ADCD"),
                        TestCaseId = testId,
                        ParentGroup = tg
                    });
                }
            }
            return vectorSet;
        }
    }
}
