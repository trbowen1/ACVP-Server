﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes.Ascon;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NLog;
using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Generation.Ascon.SP800_232.CXOF128;

public class TestCaseGenerator : ITestCaseGeneratorWithPrep<TestGroup, TestCase>
{
    private readonly IOracle _oracle;

    public int NumberOfTestCasesToGenerate => 60;

    ShuffleQueue<int> messageLengths, digestLengths, csLengths;

    public TestCaseGenerator(IOracle oracle)
    {
        _oracle = oracle;
    }

    public GenerateResponse PrepareGenerator(TestGroup group, bool isSample)
    {
        List<int> mlengths = new List<int>();
        List<int> dlengths = new List<int>();
        List<int> cslengths = new List<int>();

        mlengths.AddRange(group.MessageLength.GetDomainMinMaxAsEnumerable());
        dlengths.AddRange(group.DigestLength.GetDomainMinMaxAsEnumerable());
        cslengths.AddRange(group.CSLength.GetDomainMinMaxAsEnumerable());
        for (int i = 0; i < 8; i++)
        {
            mlengths.AddRange(group.MessageLength.GetRandomValues(x => x % 8 == i, 5));
            dlengths.AddRange(group.DigestLength.GetRandomValues(x => x % 8 == i, 5));
            cslengths.AddRange(group.CSLength.GetRandomValues(x => x % 8 == i, 5));
        }
        //Testing breakpoints and surrounding values for chunk sizes
        for (int i = 3; i < 8; i++)
        {
            mlengths.AddRange(group.MessageLength.GetSequentialValuesInIncrement((1 << i) - 1, 3));
            dlengths.AddRange(group.DigestLength.GetSequentialValuesInIncrement((1 << i) - 1, 3));
            cslengths.AddRange(group.CSLength.GetSequentialValuesInIncrement((1 << i) - 1, 3));
        }
        messageLengths = new ShuffleQueue<int>(mlengths);
        digestLengths = new ShuffleQueue<int>(dlengths);
        csLengths = new ShuffleQueue<int>(cslengths);

        return new GenerateResponse();
    }

    public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample, int caseNo = -1)
    {
        var param = new AsconHashParameters
        {
            MessageBitLength = messageLengths.Pop(),
            DigestBitLength = digestLengths.Pop(),
            CSBitLength = csLengths.Pop(),
        };

        try
        {
            var result = await _oracle.GetAsconCXOF128CaseAsync(param);

            return new TestCaseGenerateResponse<TestGroup, TestCase>(new TestCase
            {
                Message = result.Message,
                MessageBitLength = param.MessageBitLength,
                Digest = result.Digest,
                DigestBitLength = param.DigestBitLength,
                CS = result.CS,
                CSBitLength = param.CSBitLength,
            });
        }
        catch (Exception ex)
        {
            ThisLogger.Error(ex);
            return new TestCaseGenerateResponse<TestGroup, TestCase>($"Error performing CXOF128: {ex.Message}");
        }
    }

    private static ILogger ThisLogger => LogManager.GetCurrentClassLogger();
}
