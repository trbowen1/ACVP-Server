﻿using System;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.DSA.ECC;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes.Kas.Sp800_56Ar1;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.KAS.v1_0.ECC
{
    public class TestCaseGeneratorVal : ITestCaseGeneratorAsync<TestGroup, TestCase>
    {
        protected readonly IOracle _oracle;

        public int NumberOfTestCasesToGenerate => 25;

        public TestCaseGeneratorVal(IOracle oracle)
        {
            _oracle = oracle;
        }

        public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample, int caseNo = 0)
        {
            try
            {
                var param = new KasValParametersEcc
                {
                    AesCcmNonceLen = group.AesCcmNonceLen,
                    Curve = group.Curve,
                    EccParameterSet = group.ParmSet,
                    EccScheme = group.Scheme,
                    HashFunction = group.HashAlg,
                    IdIut = SpecificationMapping.IutId,
                    IdServer = SpecificationMapping.ServerId,
                    IutKeyAgreementRole = group.KasRole,
                    IutKeyConfirmationRole = group.KcRole,
                    KasMode = group.KasMode,
                    KasValTestDisposition = group.KasExpectationProvider.GetRandomReason(),
                    KeyConfirmationDirection = group.KcType,
                    KeyLen = group.KeyLen,
                    MacLen = group.MacLen,
                    MacType = group.MacType,
                    OiPattern = group.OiPattern
                };
                
                var result = await _oracle.GetKasValTestEccAsync(param);

                var testCase = new TestCase
                {
                    Deferred = false,
                    TestPassed = result.TestPassed,
                    Dkm = result.Dkm,
                    DkmNonceIut = result.DkmNonceIut,
                    DkmNonceServer = result.DkmNonceServer,
                    EphemeralNonceIut = result.EphemeralNonceIut,
                    EphemeralNonceServer = result.EphemeralNonceServer,
                    EphemeralKeyIut = new EccKeyPair(new EccPoint(result.EphemeralPublicKeyIutX, result.EphemeralPublicKeyIutY), result.EphemeralPrivateKeyIut),
                    StaticKeyIut = new EccKeyPair(new EccPoint(result.StaticPublicKeyIutX, result.StaticPublicKeyIutY), result.StaticPrivateKeyIut),
                    EphemeralKeyServer = new EccKeyPair(new EccPoint(result.EphemeralPublicKeyServerX, result.EphemeralPublicKeyServerY), result.EphemeralPrivateKeyServer),
                    StaticKeyServer = new EccKeyPair(new EccPoint(result.StaticPublicKeyServerX, result.StaticPublicKeyServerY), result.StaticPrivateKeyServer),
                    HashZ = result.HashZ,
                    IdIut = result.IdIut,
                    IdIutLen = result.IdIutLen,
                    MacData = result.MacData,
                    NonceAesCcm = result.NonceAesCcm,
                    NonceNoKc = result.NonceNoKc,
                    OiLen = result.OiLen,
                    OtherInfo = result.OtherInfo,
                    Tag = result.Tag,
                    TestCaseDisposition = param.KasValTestDisposition,
                    Z = result.Z

                };

                return new TestCaseGenerateResponse<TestGroup, TestCase>(testCase);
            }
            catch (Exception ex)
            {
                Logger.Error(ex);
                return new TestCaseGenerateResponse<TestGroup, TestCase>(ex.Message);
            }
        }
        
        private static Logger Logger => LogManager.GetCurrentClassLogger();
    }
}
