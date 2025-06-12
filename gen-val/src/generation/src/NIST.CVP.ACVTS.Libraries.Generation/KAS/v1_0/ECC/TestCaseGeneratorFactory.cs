﻿using System;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KAS.Scheme;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Generation.KAS.v1_0.TestCaseExpectations;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;

namespace NIST.CVP.ACVTS.Libraries.Generation.KAS.v1_0.ECC
{
    public class TestCaseGeneratorFactory : ITestCaseGeneratorFactoryAsync<TestGroup, TestCase>
    {
        private const string aftTest = "aft";
        private const string valTest = "val";

        private readonly IOracle _oracle;

        public TestCaseGeneratorFactory(IOracle oracle)
        {
            _oracle = oracle;
        }

        public ITestCaseGeneratorAsync<TestGroup, TestCase> GetCaseGenerator(TestGroup testGroup)
        {
            if (testGroup.TestType.Equals(aftTest, StringComparison.OrdinalIgnoreCase))
            {
                return new TestCaseGeneratorAft(_oracle);
            }

            if (testGroup.TestType.Equals(valTest, StringComparison.OrdinalIgnoreCase))
            {
                testGroup.KasExpectationProvider = new KasExpectationProvider<TestGroup, TestCase, KasDsaAlgoAttributesEcc>(testGroup);
                return new TestCaseGeneratorVal(_oracle);
            }

            return new TestCaseGeneratorNull();
        }
    }
}
