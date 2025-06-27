using System;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.SPDM
{
    public class TestCaseGenerator : ITestCaseGeneratorWithPrep<TestGroup, TestCase>
    {
        private readonly IOracle _oracle;

        public int NumberOfTestCasesToGenerate { get; private set; } = 25;

        public TestCaseGenerator(IOracle oracle)
        {
            _oracle = oracle;
        }

        public GenerateResponse PrepareGenerator(TestGroup @group, bool isSample)
        {
            if (isSample)
            {
                NumberOfTestCasesToGenerate = 5;
            }
            return new GenerateResponse();
        }

        public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample, int caseNo = 0)
        {
            var param = new SpdmKdfParameters
            {
                SpdmVersion = group.SpdmVersion,
                RunningMode = group.RunningMode,
                HashAlg = group.HashAlg,
            };

            try
            {
                var result = await _oracle.GetSpdmCaseAsync(param);

                var testCase = new TestCase
                {
                    SharedSecret = result.SharedSecret,
                    TranscriptHash1Random = result.TranscriptHash1Random,
                    TranscriptHash2Random = result.TranscriptHash2Random,

                    RequestDirectionHandshakeSecret = result.DerivedKeyingMaterial.HandshakeSecretResult.RequestDirectionHandshakeSecret,
                    ResponseDirectionHandshakeSecret = result.DerivedKeyingMaterial.HandshakeSecretResult.ResponseDirectionHandshakeSecret,

                    RequestDirectionDataSecret = result.DerivedKeyingMaterial.MasterSecretResult.RequestDirectionDataSecret,
                    ResponseDirectionDataSecret = result.DerivedKeyingMaterial.MasterSecretResult.ResponseDirectionDataSecret,
                    ExportMasterSecret = result.DerivedKeyingMaterial.MasterSecretResult.ExportMasterSecret,
                };

                return new TestCaseGenerateResponse<TestGroup, TestCase>(testCase);
            }
            catch (Exception ex)
            {
                ThisLogger.Error(ex);
                return new TestCaseGenerateResponse<TestGroup, TestCase>($"Failed to generate. {ex.Message}");
            }
        }

        public ILogger ThisLogger => LogManager.GetCurrentClassLogger();
    }
}
