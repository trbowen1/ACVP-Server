﻿using System;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.DispositionTypes;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.ECDSA.v1_0.KeyVer
{
    public class TestCaseGenerator : ITestCaseGeneratorWithPrep<TestGroup, TestCase>
    {
        private readonly IOracle _oracle;

        // Placeholder, depends on the sample flag via dispositions
        public int NumberOfTestCasesToGenerate { get; private set; } = 12;

        public TestCaseGenerator(IOracle oracle)
        {
            _oracle = oracle;
        }

        public GenerateResponse PrepareGenerator(TestGroup group, bool isSample)
        {
            NumberOfTestCasesToGenerate = group.TestCaseExpectationProvider.ExpectationCount;
            return new GenerateResponse();
        }

        public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample, int caseNo = 0)
        {
            var param = new EcdsaKeyParameters
            {
                Curve = group.Curve,
                Disposition = group.TestCaseExpectationProvider.GetRandomReason()
            };

            try
            {
                var result = await _oracle.GetEcdsaKeyAsync(param);

                var testCase = new TestCase
                {
                    Reason = param.Disposition,
                    KeyPair = result.Key,
                    TestPassed = param.Disposition == EcdsaKeyDisposition.None
                };

                return new TestCaseGenerateResponse<TestGroup, TestCase>(testCase);
            }
            catch (Exception ex)
            {
                ThisLogger.Error(ex);
                return new TestCaseGenerateResponse<TestGroup, TestCase>($"Error generating key: {ex.Message}");
            }
        }

        private static ILogger ThisLogger => LogManager.GetCurrentClassLogger();
    }
}
