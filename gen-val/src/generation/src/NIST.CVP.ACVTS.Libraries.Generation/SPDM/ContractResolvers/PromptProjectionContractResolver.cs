﻿using System;
using System.Linq;
using Newtonsoft.Json.Serialization;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.Core.ContractResolvers;

namespace NIST.CVP.ACVTS.Libraries.Generation.SPDM.ContractResolvers
{
    public class PromptProjectionContractResolver : ProjectionContractResolverBase<TestGroup, TestCase>
    {
        protected override Predicate<object> TestGroupSerialization(JsonProperty jsonProperty)
        {
            var includeProperties = new[]
            {
                nameof(TestGroup.TestGroupId),
                nameof(TestGroup.Tests),
                nameof(TestGroup.TestType),
                nameof(TestGroup.SpdmVersion),
                nameof(TestGroup.HashAlg),
                nameof(TestGroup.RunningMode)

            };

            if (includeProperties.Contains(jsonProperty.UnderlyingName, StringComparer.OrdinalIgnoreCase))
            {
                return jsonProperty.ShouldSerialize =
                    instance => true;
            }

            return jsonProperty.ShouldSerialize = instance => false;
        }

        protected override Predicate<object> TestCaseSerialization(JsonProperty jsonProperty)
        {
            var includeProperties = new[]
            {
                nameof(TestCase.TestCaseId),
                nameof(TestCase.SharedSecret),
                nameof(TestCase.TranscriptHash1Random),
                nameof(TestCase.TranscriptHash2Random)
            };

            if (includeProperties.Contains(jsonProperty.UnderlyingName, StringComparer.OrdinalIgnoreCase))
            {
                return jsonProperty.ShouldSerialize =
                    instance => true;
            }

            return jsonProperty.ShouldSerialize = instance => false;
        }
    }
}
