﻿using System;
using System.Collections.Generic;
using System.Linq;
using NIST.CVP.ACVTS.Libraries.Common.ExtensionMethods;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Generation.Core;

namespace NIST.CVP.ACVTS.Libraries.Generation.HMAC.v2_0
{
    public class ParameterValidator : ParameterValidatorBase, IParameterValidator<Parameters>
    {
        public const int MinKeyLength = 8;
        public const int MaxKeyLength = 524288;

        public const int MinMsgLength = 0;
        public const int MaxMsgLength = 4096;

        private int _minMacLength = 32;
        private int _maxMacLength = 0;      // Set by the SetAlgorithmShaOptions method, equal to the hash output length

        public ParameterValidateResponse Validate(Parameters parameters)
        {
            List<string> errorResults = new List<string>();

            ValidateAlgorithm(parameters, errorResults);

            ModeValues shaMode = ModeValues.SHA1;
            DigestSizes shaDigestSize = DigestSizes.d160;
            SetAlgorithmShaOptions(parameters, errorResults, ref shaMode, ref shaDigestSize, ref _minMacLength, ref _maxMacLength);

            // Cannot validate the rest of the parameters as they are dependent on the successful validation of the mechanism and mode.
            if (errorResults.Count > 0)
            {
                return new ParameterValidateResponse(errorResults);
            }

            ValidateKeyLen(parameters, errorResults);
            ValidateMacLen(parameters, errorResults);
            ValidateMessageLen(parameters, errorResults);

            return new ParameterValidateResponse(errorResults);
        }

        private void ValidateAlgorithm(Parameters parameters, List<string> errorResults)
        {
            var validAlgorithmValues = AlgorithmSpecificationToDomainMapping.Mapping
                .Select(s => s.specificationAlgorithm)
                .ToArray();

            var algoCheck = ValidateValue(parameters.Algorithm, validAlgorithmValues, "Algorithm");
            errorResults.AddIfNotNullOrEmpty(algoCheck);
        }

        private void SetAlgorithmShaOptions(Parameters parameters, List<string> errorResults, ref ModeValues shaMode, ref DigestSizes shaDigestSize, ref int minMacLength, ref int maxMacLength)
        {
            try
            {
                var result = AlgorithmSpecificationToDomainMapping.GetMappingFromAlgorithm(parameters.Algorithm);

                shaMode = result.shaMode;
                shaDigestSize = result.shaDigestSize;
                //minMacLength = result.minMacLength;
                maxMacLength = result.maxMacLength;
            }
            catch (ArgumentException ex)
            {
                errorResults.AddIfNotNullOrEmpty(ex.Message);
            }
        }

        private void ValidateKeyLen(Parameters parameters, List<string> errorResults)
        {
            var segmentCheck = ValidateSegmentCountGreaterThanZero(parameters.KeyLen, "KeyLen Domain");
            errorResults.AddIfNotNullOrEmpty(segmentCheck);
            if (!string.IsNullOrEmpty(segmentCheck))
            {
                return;
            }

            var fullDomain = parameters.KeyLen.GetDomainMinMax();
            var rangeCheck = ValidateRange(
                new long[] { fullDomain.Minimum, fullDomain.Maximum },
                MinKeyLength,
                MaxKeyLength,
                "KeyLen Range"
            );
            errorResults.AddIfNotNullOrEmpty(rangeCheck);

            var modCheck = ValidateMultipleOf(parameters.KeyLen, 8, "KeyLen Modulus");
            errorResults.AddIfNotNullOrEmpty(modCheck);
        }

        private void ValidateMacLen(Parameters parameters, List<string> errorResults)
        {
            var segmentCheck = ValidateSegmentCountGreaterThanZero(parameters.MacLen, "MacLen Domain");
            errorResults.AddIfNotNullOrEmpty(segmentCheck);
            if (!string.IsNullOrEmpty(segmentCheck))
            {
                return;
            }

            var fullDomain = parameters.MacLen.GetDomainMinMax();
            var rangeCheck = ValidateRange(
                new long[] { fullDomain.Minimum, fullDomain.Maximum },
                _minMacLength,
                _maxMacLength,
                "MacLen Range"
            );
            errorResults.AddIfNotNullOrEmpty(rangeCheck);
        }
        
        private void ValidateMessageLen(Parameters parameters, List<string> errorResults)
        {
            var segmentCheck = ValidateSegmentCountGreaterThanZero(parameters.MessageLen, "MessageLen Domain");
            errorResults.AddIfNotNullOrEmpty(segmentCheck);
            if (!string.IsNullOrEmpty(segmentCheck))
            {
                return;
            }

            var fullDomain = parameters.MessageLen.GetDomainMinMax();
            var rangeCheck = ValidateRange(
                new long[] { fullDomain.Minimum, fullDomain.Maximum },
                MinMsgLength,
                MaxMsgLength,
                "MessageLen Range"
            );
            errorResults.AddIfNotNullOrEmpty(rangeCheck);
        }
    }
}
