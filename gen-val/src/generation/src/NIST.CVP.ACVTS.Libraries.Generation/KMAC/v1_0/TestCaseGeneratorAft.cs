﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Common.ExtensionMethods;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Libraries.Math.Domain;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes;
using NLog;

namespace NIST.CVP.ACVTS.Libraries.Generation.KMAC.v1_0
{
    public class TestCaseGeneratorAft : ITestCaseGeneratorWithPrep<TestGroup, TestCase>
    {
        private readonly IOracle _oracle;
        private readonly IRandom800_90 _rand;

        private int _capacity = 0;
        private IList<(int macSize, int keySize, int messageSize, int customizationLength)> _lengths { get; } = new List<(int, int, int, int)>();

        public int NumberOfTestCasesToGenerate => 100;

        public TestCaseGeneratorAft(IOracle oracle, IRandom800_90 rand)
        {
            _oracle = oracle;
            _rand = rand;
        }

        public GenerateResponse PrepareGenerator(TestGroup group, bool isSample)
        {
            var blockAlignedTestCasesToGenerate = 5;

            _capacity = 2 * group.DigestSize;

            #region MessageLengths
            var inputAllowed = group.MsgLengths.GetDeepCopy();
            var minMax = inputAllowed.GetDomainMinMax();

            var messageLengths = new List<int>
            {
                minMax.Minimum,
                minMax.Maximum
            };

            messageLengths.AddRange(inputAllowed.GetRandomValues(x => x <= _capacity, NumberOfTestCasesToGenerate / 2));
            messageLengths.AddRange(inputAllowed.GetRandomValues(x => x > _capacity, NumberOfTestCasesToGenerate / 2));
            #endregion MessageLengths

            #region MacLengths
            // For every input length, just pick a random output length (min/max always included)
            var macAllowed = group.MacLengths.GetDeepCopy();
            var macMinMax = macAllowed.GetDomainMinMax();
            var macLengths = new List<int>
            {
                macMinMax.Minimum,
                macMinMax.Maximum
            };
            macLengths.AddRange(macAllowed.GetRandomValues(x => true, NumberOfTestCasesToGenerate));
            #endregion MacLengths

            #region KeyLengths
            // For every input length, just pick a random key length (min/max always included)
            var keyAllowed = group.KeyLengths.GetDeepCopy();
            var keyMinMax = keyAllowed.GetDomainMinMax();
            var keyLengths = new List<int>
            {
                keyMinMax.Minimum,
                keyMinMax.Maximum
            };
            
            // Due to the way bytepad works, there are extra padding bits added that makes the "amount of key bits" in order to hit the block aligned test... odd.
            // These cases specifically cover KMAC under data directly aligned to a block, i.e. no padding in "bytepad" should be performed.
            // See Sha3DerivedHelpersTests.ShouldGetBlockAlignedDataWithSpecificKeyLengthForKmac tests for some more detail.
            keyLengths.AddRangeIfNotNullOrEmpty(group.DigestSize == 128
                ? keyAllowed.GetRandomValues(x => (x % 168) == 163, blockAlignedTestCasesToGenerate)
                : keyAllowed.GetRandomValues(x => (x % 136) == 131, blockAlignedTestCasesToGenerate));

            // These cases specifically cover KMAC under data directly not aligned to a block, i.e. both padding branches in "bytepad" should be performed.
            keyLengths.AddRangeIfNotNullOrEmpty(group.DigestSize == 128
                ? keyAllowed.GetRandomValues(x => (x % 168) != 163 && (x % 8) != 0, blockAlignedTestCasesToGenerate)
                : keyAllowed.GetRandomValues(x => (x % 136) != 131 && (x % 8) != 0, blockAlignedTestCasesToGenerate));
            
            keyLengths.AddRange(keyAllowed.GetRandomValues(x => true, NumberOfTestCasesToGenerate - (2 * blockAlignedTestCasesToGenerate)));
            #endregion KeyLengths

            var macLengthQueue = new ShuffleQueue<int>(macLengths);
            var keyLengthQueue = new ShuffleQueue<int>(keyLengths);
            var messageLengthQueue = new ShuffleQueue<int>(messageLengths);

            for (var i = 0; i < NumberOfTestCasesToGenerate; i++)
            {
                // Customization length will be bits if for hex, or bytes if for ascii
                _lengths.Add((macLengthQueue.Pop(), keyLengthQueue.Pop(), messageLengthQueue.Pop(), _rand.GetRandomInt(0, 129)));
            }

            return new GenerateResponse();
        }

        public async Task<TestCaseGenerateResponse<TestGroup, TestCase>> GenerateAsync(TestGroup group, bool isSample, int caseNo = 0)
        {
            try
            {
                var oracleResult = await _oracle.GetKmacCaseAsync(new KmacParameters
                {
                    CustomizationLength = _lengths[caseNo].customizationLength,
                    HexCustomization = group.HexCustomization,
                    KeyLength = _lengths[caseNo].keySize,
                    MacLength = _lengths[caseNo].macSize,
                    MessageLength = _lengths[caseNo].messageSize,
                    XOF = group.XOF,
                    DigestSize = _capacity / 2
                });

                return new TestCaseGenerateResponse<TestGroup, TestCase>(new TestCase
                {
                    Key = oracleResult.Key,
                    Message = oracleResult.Message,
                    Mac = oracleResult.Tag,
                    Customization = oracleResult.Customization,
                    CustomizationHex = oracleResult.CustomizationHex,
                    MacLength = oracleResult.Tag.BitLength
                });
            }
            catch (Exception ex)
            {
                ThisLogger.Error(ex);
                return new TestCaseGenerateResponse<TestGroup, TestCase>($"Failed to generate. {ex.Message}");
            }
        }

        private static ILogger ThisLogger => LogManager.GetCurrentClassLogger();
    }
}
