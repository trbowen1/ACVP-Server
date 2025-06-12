﻿using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Generation.KDA.Shared.Hkdf;

namespace NIST.CVP.ACVTS.Libraries.Generation.KDA.Sp800_56Cr1.Hkdf
{
    public class TestCaseGeneratorFactory : ITestCaseGeneratorFactoryAsync<TestGroup, TestCase>
    {
        private readonly IOracle _oracle;

        public TestCaseGeneratorFactory(IOracle oracle)
        {
            _oracle = oracle;
        }

        public ITestCaseGeneratorAsync<TestGroup, TestCase> GetCaseGenerator(TestGroup testGroup)
        {
            switch (testGroup.TestType.ToLower())
            {
                case "aft":
                    return new TestCaseGeneratorAft(_oracle);
                case "val":
                    return new TestCaseGeneratorVal(_oracle);
                default:
                    return new TestCaseGeneratorNull();
            }
        }
    }
}
