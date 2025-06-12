using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes.ML_DSA;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.ML_DSA.FIPS204.SigVer;

public class TestCaseGenerator : ITestCaseGeneratorWithPrep<TestGroup, TestCase>
{
    private readonly IOracle _oracle;
    private ShuffleQueue<int> _messageLengths;
    private ShuffleQueue<int> _contextLengths;
    private ShuffleQueue<HashFunctions> _hashFunctions;
    
    // Set up to use 3 of each possible disposition, 15 is a placeholder
    public int NumberOfTestCasesToGenerate { get; private set; } = 15;

    public TestCaseGenerator(IOracle oracle)
    {
        _oracle = oracle;
    }
    
    public GenerateResponse PrepareGenerator(TestGroup group, bool isSample)
    {
        NumberOfTestCasesToGenerate = group.TestCaseExpectationProvider.ExpectationCount;   // 15

        // Add min, max and fill rest with random values
        var messageLengthList = new List<int>
        {
            group.MessageLength.GetDomainMinMax().Minimum,
            group.MessageLength.GetDomainMinMax().Maximum
        };
        
        messageLengthList.AddRange(group.MessageLength.GetRandomValues(_ => true, NumberOfTestCasesToGenerate - 2));
        _messageLengths = new ShuffleQueue<int>(messageLengthList);
        
        // Add min, max and fill rest with random values
        if (group.SignatureInterface == SignatureInterface.External)
        {
            var contextLengthList = new List<int>
            {
                group.ContextLength.GetDomainMinMax().Minimum,
                group.ContextLength.GetDomainMinMax().Maximum
            };
        
            contextLengthList.AddRange(group.ContextLength.GetRandomValues(_ => true, NumberOfTestCasesToGenerate - 2));
            _contextLengths = new ShuffleQueue<int>(contextLengthList);

            if (group.PreHash == PreHash.PreHash)
            {
                _hashFunctions = new ShuffleQueue<HashFunctions>(group.HashFunctions.ToList());
                
                // It is not a requirement but a recommendation to filter by hash functions strong enough for the parameter set, we want to test all valid possibilities though not just the recommended ones
                // var lambda = new DilithiumParameters(group.ParameterSet).Lambda;
                //
                // // Filter out hash functions that do not meet the collision and second pre-image strength for lambda on the parameter set
                // _hashFunctions = new ShuffleQueue<HashFunctions>(group.HashFunctions.Where(hf => ShaAttributes.GetHashFunctionFromEnum(hf).OutputLen >= lambda).ToList());
            }
        }
        
        return new GenerateResponse();
    }
    
    public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample, int caseNo = -1)
    {
        try
        {
            var keyParam = new MLDSAKeyGenParameters { ParameterSet = group.ParameterSet };
            var keyResult = await _oracle.GetMLDSAKeyCaseAsync(keyParam);
            
            var param = new MLDSASignatureParameters
            {
                ParameterSet = group.ParameterSet,
                MessageLength = _messageLengths.Pop(),  // Assumption that messageLength only contains multiples of 8 from ParameterValidator
                Deterministic = true,                   // Not relevant to SigVer, easier to set to true
                PreHash = group.PreHash,
                ExternalMu = group.ExternalMu,
                SignatureInterface = group.SignatureInterface,
                PrivateKey = keyResult.PrivateKey,
                HashFunction = group.PreHash == PreHash.PreHash ? _hashFunctions.Pop() : HashFunctions.None,    // Only used on PreHash
                ContextLength = group.SignatureInterface == SignatureInterface.External ? _contextLengths.Pop() : 0, // Only used on External interface
                Disposition = group.TestCaseExpectationProvider.GetRandomReason()
            };
            
            var result = await _oracle.GetMLDSAVerifyResultAsync(param);

            var testCase = new TestCase
            {
                PublicKey = keyResult.PublicKey,
                PrivateKey = keyResult.PrivateKey,
                Message = result.VerifiedValue.Message,
                Mu = result.VerifiedValue.Mu,                 // Null for ExternalMu = false
                Context = result.VerifiedValue.Context,       // Null for Internal interface
                HashAlg = param.HashFunction,                 // None for any non-preHash
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
