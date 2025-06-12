﻿using System;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.DSA.ECC.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ResultTypes;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.ECDSA.v1_0.SigVer
{
    public class TestCaseGenerator : ITestCaseGeneratorWithPrep<TestGroup, TestCase>
    {
        private readonly IOracle _oracle;

        // Changes if sample flag is set
        public int NumberOfTestCasesToGenerate { get; private set; } = 21;

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
            var keyParam = new EcdsaKeyParameters
            {
                Curve = group.Curve
            };

            EcdsaKeyResult keyResult = null;
            try
            {
                keyResult = await _oracle.GetEcdsaKeyAsync(keyParam);
            }
            catch (Exception ex)
            {
                ThisLogger.Error(ex);
                return new TestCaseGenerateResponse<TestGroup, TestCase>("Unable to generate key");
            }

            try
            {
                var param = new EcdsaSignatureParameters
                {
                    Curve = group.Curve,
                    Disposition = group.TestCaseExpectationProvider.GetRandomReason(),
                    HashAlg = group.HashAlg,
                    Key = keyResult.Key,
                    IsMessageRandomized = group.IsMessageRandomized,
                    NonceProviderType = NonceProviderTypes.Random        // Always the case for FIPS 186-4, choice for 186-5, but DetECDSA is handled in a separate set of gen/vals
                };

                var result = await _oracle.GetEcdsaVerifyResultAsync(param);

                var testCase = new TestCase
                {
                    Message = result.VerifiedValue.Message,
                    RandomValue = result.VerifiedValue.RandomValue,
                    RandomValueLen = result.VerifiedValue.RandomValue?.BitLength ?? 0,
                    KeyPair = result.VerifiedValue.Key,
                    Reason = param.Disposition,
                    TestPassed = result.Result,
                    Signature = result.VerifiedValue.Signature
                };

                return new TestCaseGenerateResponse<TestGroup, TestCase>(testCase);
            }
            catch (Exception ex)
            {
                ThisLogger.Error(ex);
                return new TestCaseGenerateResponse<TestGroup, TestCase>($"Error generating case: {ex.Message}");
            }
        }

        private static ILogger ThisLogger => LogManager.GetCurrentClassLogger();
    }
}
