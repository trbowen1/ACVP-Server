﻿using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Common.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.DSA.FFC.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Helpers;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.DSA.v1_0.PqgVer.TestCaseExpectations;

namespace NIST.CVP.ACVTS.Libraries.Generation.DSA.v1_0.PqgVer
{
    public class TestGroupGeneratorG : ITestGroupGeneratorAsync<Parameters, TestGroup, TestCase>
    {
        public const string TEST_TYPE = "GDT";

        public Task<List<TestGroup>> BuildTestGroupsAsync(Parameters parameters)
        {
            var testGroups = new List<TestGroup>();

            foreach (var capability in parameters.Capabilities)
            {
                foreach (var gGen in capability.GGen)
                {
                    foreach (var hashAlg in capability.HashAlg)
                    {
                        var testGroup = new TestGroup
                        {
                            GGenMode = EnumHelpers.GetEnumFromEnumDescription<GeneratorGenMode>(gGen),
                            PQGenMode = PrimeGenMode.None,
                            L = capability.L,
                            N = capability.N,
                            HashAlg = ShaAttributes.GetHashFunctionFromName(hashAlg),
                            GTestCaseExpectationProvider = new GExpectationProvider(parameters.IsSample),

                            TestType = TEST_TYPE
                        };

                        testGroups.Add(testGroup);
                    }
                }
            }

            return Task.FromResult(testGroups);
        }
    }
}
