using System.Collections.Generic;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;

namespace NIST.CVP.ACVTS.Libraries.Generation.SPDM
{
    public class TestCaseValidator : ITestCaseValidatorAsync<TestGroup, TestCase>
    {
        private readonly TestCase _serverTestCase;
        public int TestCaseId => _serverTestCase.TestCaseId;

        public TestCaseValidator(TestCase serverTestCase)
        {
            _serverTestCase = serverTestCase;
        }

        public Task<TestCaseValidation> ValidateAsync(TestCase iutResult, bool showExpected = false)
        {
            var errors = new List<string>();
            var expected = new Dictionary<string, string>();
            var provided = new Dictionary<string, string>();

            ValidateResultPresent(iutResult, errors);
            if (errors.Count == 0)
            {
                CheckResults(iutResult, errors, expected, provided);
            }

            if (errors.Count > 0)
            {
                return Task.FromResult(new TestCaseValidation
                {
                    TestCaseId = TestCaseId,
                    Result = Core.Enums.Disposition.Failed,
                    Reason = string.Join("; ", errors),
                    Expected = expected.Count != 0 && showExpected ? expected : null,
                    Provided = provided.Count != 0 && showExpected ? provided : null
                });
            }

            return Task.FromResult(new TestCaseValidation { TestCaseId = TestCaseId, Result = Core.Enums.Disposition.Passed });
        }

        private void ValidateResultPresent(TestCase suppliedResult, List<string> errors)
        {
            if (suppliedResult.RequestDirectionHandshakeSecret == null)
            {
                errors.Add($"{nameof(suppliedResult.RequestDirectionHandshakeSecret)} was not present in the {nameof(TestCase)}");
            }

            if (suppliedResult.ResponseDirectionHandshakeSecret == null)
            {
                errors.Add($"{nameof(suppliedResult.ResponseDirectionHandshakeSecret)} was not present in the {nameof(TestCase)}");
            }
                        
            if (suppliedResult.RequestDirectionDataSecret == null)
            {
                errors.Add($"{nameof(suppliedResult.RequestDirectionDataSecret)} was not present in the {nameof(TestCase)}");
            }

            if (suppliedResult.ResponseDirectionDataSecret == null)
            {
                errors.Add($"{nameof(suppliedResult.ResponseDirectionDataSecret)} was not present in the {nameof(TestCase)}");
            }

            if (suppliedResult.ExportMasterSecret == null)
            {
                errors.Add($"{nameof(suppliedResult.ExportMasterSecret)} was not present in the {nameof(TestCase)}");
            }             
        }

        private void CheckResults(TestCase suppliedResult, List<string> errors, Dictionary<string, string> expected, Dictionary<string, string> provided)
        {
            if (!_serverTestCase.RequestDirectionHandshakeSecret.Equals(suppliedResult.RequestDirectionHandshakeSecret))
            {
                errors.Add($"{nameof(suppliedResult.RequestDirectionHandshakeSecret)} does not match");
                expected.Add(nameof(_serverTestCase.RequestDirectionHandshakeSecret), _serverTestCase.RequestDirectionHandshakeSecret.ToHex());
                provided.Add(nameof(suppliedResult.RequestDirectionHandshakeSecret), suppliedResult.RequestDirectionHandshakeSecret.ToHex());
            }

            if (!_serverTestCase.ResponseDirectionHandshakeSecret.Equals(suppliedResult.ResponseDirectionHandshakeSecret))
            {
                errors.Add($"{nameof(suppliedResult.ResponseDirectionHandshakeSecret)} does not match");
                expected.Add(nameof(_serverTestCase.ResponseDirectionHandshakeSecret), _serverTestCase.ResponseDirectionHandshakeSecret.ToHex());
                provided.Add(nameof(suppliedResult.ResponseDirectionHandshakeSecret), suppliedResult.ResponseDirectionHandshakeSecret.ToHex());
            }

            if (!_serverTestCase.RequestDirectionDataSecret.Equals(suppliedResult.RequestDirectionDataSecret))
            {
                errors.Add($"{nameof(suppliedResult.RequestDirectionDataSecret)} does not match");
                expected.Add(nameof(_serverTestCase.RequestDirectionDataSecret), _serverTestCase.RequestDirectionDataSecret.ToHex());
                provided.Add(nameof(suppliedResult.RequestDirectionDataSecret), suppliedResult.RequestDirectionDataSecret.ToHex());
            }

            if (!_serverTestCase.ResponseDirectionHandshakeSecret.Equals(suppliedResult.ResponseDirectionHandshakeSecret))
            {
                errors.Add($"{nameof(suppliedResult.ResponseDirectionHandshakeSecret)} does not match");
                expected.Add(nameof(_serverTestCase.ResponseDirectionHandshakeSecret), _serverTestCase.ResponseDirectionHandshakeSecret.ToHex());
                provided.Add(nameof(suppliedResult.ResponseDirectionHandshakeSecret), suppliedResult.ResponseDirectionHandshakeSecret.ToHex());
            }

            if (!_serverTestCase.ExportMasterSecret.Equals(suppliedResult.ExportMasterSecret))
            {
                errors.Add($"{nameof(suppliedResult.ExportMasterSecret)} does not match");
                expected.Add(nameof(_serverTestCase.ExportMasterSecret), _serverTestCase.ExportMasterSecret.ToHex());
                provided.Add(nameof(suppliedResult.ExportMasterSecret), suppliedResult.ExportMasterSecret.ToHex());
            }
        }
    }
}
