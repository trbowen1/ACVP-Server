﻿using System;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.DSA.ECC.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ResultTypes;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.ECDSA.v1_0.SigGen
{
    public class TestCaseGenerator : ITestCaseGeneratorAsync<TestGroup, TestCase>
    {
        private readonly IOracle _oracle;

        public int NumberOfTestCasesToGenerate { get; private set; } = 10;

        public TestCaseGenerator(IOracle oracle)
        {
            _oracle = oracle;
        }

        public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample, int caseNo = 0)
        {
            var param = new EcdsaSignatureParameters
            {
                Curve = group.Curve,
                HashAlg = group.HashAlg,
                PreHashedMessage = group.ComponentTest,
                Key = group.KeyPair,
                IsMessageRandomized = group.IsMessageRandomized,
                NonceProviderType = NonceProviderTypes.Random        // Always the case for FIPS 186-4, choice for 186-5, but DetECDSA is handled in a separate set of gen/vals
            };

            try
            {
                TestCase testCase = null;
                EcdsaSignatureResult result = null;
                if (isSample)
                {
                    result = await _oracle.GetEcdsaSignatureAsync(param);
                    testCase = new TestCase
                    {
                        Message = result.Message,
                        RandomValue = result.RandomValue,
                        RandomValueLen = result.RandomValue?.BitLength ?? 0,
                        K = result.K,
                        Signature = result.Signature,
                        Deferred = false
                    };

                }
                else
                {
                    result = await _oracle.GetDeferredEcdsaSignatureAsync(param);
                    testCase = new TestCase
                    {
                        Message = result.Message,
                        Deferred = true
                    };
                }

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
