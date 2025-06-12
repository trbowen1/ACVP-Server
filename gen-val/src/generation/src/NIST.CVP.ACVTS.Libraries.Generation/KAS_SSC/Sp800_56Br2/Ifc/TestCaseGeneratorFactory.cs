﻿using System;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Generation.KAS_SSC.TestCaseExpectations;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;

namespace NIST.CVP.ACVTS.Libraries.Generation.KAS_SSC.Sp800_56Br2.Ifc
{
    public class TestCaseGeneratorFactory : ITestCaseGeneratorFactoryAsync<TestGroup, TestCase>
    {
        private readonly IOracle _oracle;

        private const string AftTest = "AFT";
        private const string ValTest = "VAL";

        public TestCaseGeneratorFactory(IOracle oracle)
        {
            _oracle = oracle;
        }

        public ITestCaseGeneratorAsync<TestGroup, TestCase> GetCaseGenerator(TestGroup testGroup)
        {
            if (testGroup.TestType.Equals(AftTest, StringComparison.OrdinalIgnoreCase)
                && testGroup.IsSample)
            {
                // When running in sample mode, the ACVP server needs produce vectors as if it were both parties.
                // Since VAL tests do this anyway, we can fall back on its test case generator for producing sample AFT tests.
                testGroup.KasSscExpectationProvider = new KasSscExpectationProvider(testGroup.IsSample, false);
                return new TestCaseGeneratorVal(_oracle);
            }

            if (testGroup.TestType.Equals(AftTest, StringComparison.OrdinalIgnoreCase))
            {
                return new TestCaseGeneratorAft(_oracle);
            }

            if (testGroup.TestType.Equals(ValTest, StringComparison.OrdinalIgnoreCase))
            {
                testGroup.KasSscExpectationProvider = new KasSscExpectationProvider(testGroup.IsSample, true);
                return new TestCaseGeneratorVal(_oracle);
            }

            return new TestCaseGeneratorNull();
        }
    }
}
