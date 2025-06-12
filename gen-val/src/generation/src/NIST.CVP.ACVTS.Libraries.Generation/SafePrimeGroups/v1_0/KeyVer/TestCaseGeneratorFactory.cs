﻿using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Generation.SafePrimeGroups.v1_0.KeyVer.TestCaseExpectations;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;

namespace NIST.CVP.ACVTS.Libraries.Generation.SafePrimeGroups.v1_0.KeyVer
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
            var validityTestCaseOptions = new KeyExpectationProvider(testGroup.IsSample);
            return new TestCaseGenerator(_oracle, validityTestCaseOptions);
        }
    }
}
