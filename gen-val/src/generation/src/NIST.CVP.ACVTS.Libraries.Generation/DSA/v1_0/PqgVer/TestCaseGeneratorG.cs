﻿using System;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Common.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.DSA.FFC.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.DispositionTypes;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ResultTypes;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.DSA.v1_0.PqgVer
{
    public class TestCaseGeneratorG : ITestCaseGeneratorWithPrep<TestGroup, TestCase>
    {
        private readonly IOracle _oracle;

        public int NumberOfTestCasesToGenerate { get; private set; } = 5;

        public TestCaseGeneratorG(IOracle oracle)
        {
            _oracle = oracle;
        }

        public GenerateResponse PrepareGenerator(TestGroup @group, bool isSample)
        {
            NumberOfTestCasesToGenerate = group.GTestCaseExpectationProvider.ExpectationCount;
            return new GenerateResponse();
        }

        public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample, int caseNo = 0)
        {
            // Get a PQ pair for the test case
            var pqParam = new DsaDomainParametersParameters
            {
                PQGenMode = PrimeGenMode.Probable,
                GGenMode = GeneratorGenMode.Unverifiable, // need to provide a GGenMode in order to get a potential pool value
                HashAlg = group.HashAlg,
                L = group.L,
                N = group.N
            };

            DsaDomainParametersResult pqResult = null;
            try
            {
                pqResult = await _oracle.GetDsaPQAsync(pqParam);
            }
            catch (Exception ex)
            {
                ThisLogger.Error(ex);
                return new TestCaseGenerateResponse<TestGroup, TestCase>("Error generating PQ for test case");
            }

            // Get a G
            var reason = group.GTestCaseExpectationProvider.GetRandomReason();
            var gParam = new DsaDomainParametersParameters
            {
                Disposition = EnumHelpers.GetEnumDescriptionFromEnum(reason),   // string because the field is shared with the PQ dispositions
                GGenMode = group.GGenMode,
                HashAlg = group.HashAlg,
                L = group.L,
                N = group.N
            };

            try
            {
                var gResult = await _oracle.GetDsaGAsync(gParam, pqResult);

                // Assign values of the TestCase
                var testCase = new TestCase
                {
                    P = pqResult.P != 0 ? new BitString(pqResult.P, group.L) : null,
                    Q = pqResult.Q != 0 ? new BitString(pqResult.Q, group.N) : null,
                    Seed = pqResult.Seed,
                    Counter = pqResult.Counter,
                    Index = gResult.Index,
                    Reason = EnumHelpers.GetEnumDescriptionFromEnum(reason),
                    TestPassed = reason == DsaGDisposition.None,
                    G = gResult.G != 0 ? new BitString(gResult.G, group.L) : null,
                    H = gResult.H
                };

                return new TestCaseGenerateResponse<TestGroup, TestCase>(testCase);
            }
            catch (Exception ex)
            {
                ThisLogger.Error(ex);
                return new TestCaseGenerateResponse<TestGroup, TestCase>("Error generating G for test case");
            }
        }

        private static ILogger ThisLogger => LogManager.GetCurrentClassLogger();
    }
}
