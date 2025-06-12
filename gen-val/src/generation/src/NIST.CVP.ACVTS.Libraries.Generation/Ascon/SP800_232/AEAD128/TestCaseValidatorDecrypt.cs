﻿using System.Collections.Generic;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Generation.Core;

namespace NIST.CVP.ACVTS.Libraries.Generation.Ascon.SP800_232.AEAD128;
public class TestCaseValidatorDecrypt : ITestCaseValidatorAsync<TestGroup, TestCase>
{
    public int TestCaseId => _expectedResult.TestCaseId;

    private readonly TestCase _expectedResult;

    public TestCaseValidatorDecrypt(TestCase expectedResult)
    {
        _expectedResult = expectedResult;
    }

    public Task<TestCaseValidation> ValidateAsync(TestCase suppliedResult, bool showExpected = false)
    {
        var errors = new List<string>();
        var expected = new Dictionary<string, string>();
        var provided = new Dictionary<string, string>();

        if (_expectedResult.TestPassed != null && !_expectedResult.TestPassed.Value)
        {
            if (!suppliedResult.TestPassed.HasValue ||
                    (suppliedResult.TestPassed != null && suppliedResult.TestPassed.Value))
            {
                errors.Add("Expected tag validation failure");
                expected.Add(nameof(_expectedResult.TestPassed), _expectedResult.TestPassed.Value.ToString());
                provided.Add(nameof(suppliedResult.TestPassed), suppliedResult.TestPassed.ToString());
            }
        }
        else
        {
            ValidateResultPresent(suppliedResult, errors);
            if (errors.Count == 0)
            {
                CheckResults(suppliedResult, errors, expected, provided);
            }
        }

        if (errors.Count > 0)
        {
            return Task.FromResult(new TestCaseValidation
            {
                TestCaseId = suppliedResult.TestCaseId,
                Result = Core.Enums.Disposition.Failed,
                Reason = string.Join("; ", errors),
                Expected = expected.Count != 0 && showExpected ? expected : null,
                Provided = provided.Count != 0 && showExpected ? provided : null
            });
        }

        return Task.FromResult(new TestCaseValidation
        {
            TestCaseId = TestCaseId,
            Result = Core.Enums.Disposition.Passed
        });
    }

    private void ValidateResultPresent(TestCase suppliedResult, List<string> errors)
    {
        if (suppliedResult.Plaintext == null)
        {
            errors.Add($"{nameof(suppliedResult.Plaintext)} was not present in the {nameof(TestCase)}");
        }
    }

    private void CheckResults(TestCase suppliedResult, List<string> errors, Dictionary<string, string> expected, Dictionary<string, string> provided)
    {
        if (!_expectedResult.Plaintext.Equals(suppliedResult.Plaintext))
        {
            errors.Add($"{nameof(suppliedResult.Plaintext)} does not match");
            expected.Add(nameof(_expectedResult.Plaintext), _expectedResult.Plaintext.ToHex());
            provided.Add(nameof(suppliedResult.Plaintext), suppliedResult.Plaintext.ToHex());
        }
    }
}
