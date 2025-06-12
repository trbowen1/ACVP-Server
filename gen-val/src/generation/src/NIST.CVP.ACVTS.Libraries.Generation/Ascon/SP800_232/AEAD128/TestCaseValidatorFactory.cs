﻿using System.Collections.Generic;
using System.Linq;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;

namespace NIST.CVP.ACVTS.Libraries.Generation.Ascon.SP800_232.AEAD128;

public class TestCaseValidatorFactory : ITestCaseValidatorFactoryAsync<TestVectorSet, TestGroup, TestCase>
{
    public List<ITestCaseValidatorAsync<TestGroup, TestCase>> GetValidators(TestVectorSet testVectorSet)
    {
        var list = new List<ITestCaseValidatorAsync<TestGroup, TestCase>>();

        foreach (var group in testVectorSet.TestGroups.Select(g => g))
        {
            if(group.Direction == Crypto.Common.Symmetric.Enums.BlockCipherDirections.Encrypt)
            {
                list.AddRange(group.Tests.Select(test => new TestCaseValidatorEncrypt(test)));
            }
            else
            {
                list.AddRange(group.Tests.Select(test => new TestCaseValidatorDecrypt(test)));
            }
        }

        return list;
    }
}
