﻿using System.Collections.Generic;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Enums;

namespace NIST.CVP.ACVTS.Libraries.Generation.ML_KEM.FIPS203.EncapDecap;

public class TestCaseValidatorKeyCheck : ITestCaseValidatorAsync<TestGroup, TestCase>
{
    private readonly TestCase _expectedResult;
    public int TestCaseId => _expectedResult.TestCaseId;

    public TestCaseValidatorKeyCheck(TestCase expectedResult)
    {
        _expectedResult = expectedResult;
    }

    public Task<TestCaseValidation> ValidateAsync(TestCase suppliedResult, bool showExpected = false)
    {
        if (_expectedResult.TestPassed != suppliedResult.TestPassed)
        {
            var expected = new Dictionary<string, string>
            {
                { nameof(_expectedResult.TestPassed), _expectedResult.TestPassed.Value.ToString() }
            };

            var provided = new Dictionary<string, string>
            {
                { nameof(suppliedResult.TestPassed), suppliedResult.TestPassed.Value.ToString() }
            };

            return Task.FromResult(new TestCaseValidation
            {
                TestCaseId = suppliedResult.TestCaseId,
                Result = Disposition.Failed,
                Reason = _expectedResult.Reason,
                Expected = expected,
                Provided = provided
            });
        }

        return Task.FromResult(new TestCaseValidation
        {
            TestCaseId = suppliedResult.TestCaseId,
            Result = Disposition.Passed
        });
    }
}
