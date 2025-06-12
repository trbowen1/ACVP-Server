﻿using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Generation.Core;

namespace NIST.CVP.ACVTS.Libraries.Generation.Ascon.SP800_232.XOF128;

public class TestGroupGenerator : ITestGroupGeneratorAsync<Parameters, TestGroup, TestCase>
{
    public Task<List<TestGroup>> BuildTestGroupsAsync(Parameters parameters)
    {
        var testGroups = new List<TestGroup>();

        TestGroup tg = new TestGroup();
        tg.TestType = "AFT";
        tg.MessageLength = parameters.MessageLength;
        tg.DigestLength = parameters.OutputLength;
        testGroups.Add(tg);

        return Task.FromResult(testGroups);
    }
}
