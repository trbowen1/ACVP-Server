using System.Collections.Generic;
using NIST.CVP.ACVTS.Libraries.Common;
using NIST.CVP.ACVTS.Libraries.Common.ExtensionMethods;
using NIST.CVP.ACVTS.Libraries.Common.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.Core;

namespace NIST.CVP.ACVTS.Libraries.Generation.SPDM
{
    public class ParameterValidator : ParameterValidatorBase, IParameterValidator<Parameters>
    {
        private static readonly AlgoMode ValidAlgoMode = AlgoMode.Spdm_v1_x;
        private static readonly List<HashFunctions> ValidHashFunctions = new List<HashFunctions>()
        {
            HashFunctions.Sha2_d256,
            HashFunctions.Sha2_d384,
            HashFunctions.Sha2_d512,
            HashFunctions.Sha3_d256,
            HashFunctions.Sha3_d384,
            HashFunctions.Sha3_d512
        };
        private static readonly List<SpdmModes> ValidSpdmModes = EnumHelpers.GetEnumsWithoutDefault<SpdmModes>();

        private static readonly List<SpdmVersions> ValidSpdmVersions = EnumHelpers.GetEnumsWithoutDefault<SpdmVersions>();

        public ParameterValidateResponse Validate(Parameters parameters)
        {
            List<string> errors = new List<string>();

            ValidateAlgoModeRevision(parameters, errors);
            ValidateSpdmVersions(parameters.SpdmVersion, errors);
            ValidateRunningModes(parameters.RunningMode, errors);
            ValidateHashAlgs(parameters.HashAlg, errors);

            return new ParameterValidateResponse(errors);
        }

        private void ValidateAlgoModeRevision(Parameters parameters, List<string> errors)
        {
            ValidateAlgoMode(parameters, new[] { ValidAlgoMode }, errors);
        }

        private void ValidateHashAlgs(HashFunctions[] parametersHashAlg, List<string> errors)
        {
            errors.AddIfNotNullOrEmpty(
                ValidateArray(parametersHashAlg, ValidHashFunctions, "hashAlg"));
        }

        private void ValidateRunningModes(SpdmModes[] runningModes, List<string> errors)
        {
            errors.AddIfNotNullOrEmpty(
                ValidateArray(runningModes, ValidSpdmModes, "runningModes"));
        }

        private void ValidateSpdmVersions(SpdmVersions[] spdmVersions, List<string> errors)
        {
            errors.AddIfNotNullOrEmpty(
                ValidateArray(spdmVersions, ValidSpdmVersions, "spdmVersions"));
        }
    }
}
