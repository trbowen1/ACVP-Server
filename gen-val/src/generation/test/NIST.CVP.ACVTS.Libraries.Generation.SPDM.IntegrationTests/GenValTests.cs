using NIST.CVP.ACVTS.Libraries.Common;
using NIST.CVP.ACVTS.Libraries.Common.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.Tests;
using NIST.CVP.ACVTS.Libraries.Generation.SPDM;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Tests.Core.TestCategoryAttributes;
using NUnit.Framework;

namespace NIST.CVP.ACVTS.Libraries.Generation.SPDM.IntegrationTests
{
    [TestFixture, LongRunningIntegrationTest]
    public class GenValTests : GenValTestsSingleRunnerBase
    {
        public override string Algorithm => "SPDM-v1.x";
        public override string Mode => "KDF";
        public override string Revision => "DSP0274";
        public override AlgoMode AlgoMode => AlgoMode.Spdm_v1_x;

        public override IRegisterInjections RegistrationsGenVal => new RegisterInjections();


        protected override void ModifyTestCaseToFail(dynamic testCase)
        {
            var rand = new Random800_90();

            if (testCase.ExportMasterSecret != null)
            {
                var bs = new BitString(testCase.ExportMasterSecret.ToString());
                bs = rand.GetDifferentBitStringOfSameSize(bs);

                testCase.ExportMasterSecret = bs.ToHex();
            }
        }

        protected override string GetTestFileFewTestCases(string folderName)
        {
            var p = new Parameters
            {
                Algorithm = Algorithm,
                Mode = Mode,
                Revision = Revision,
                SpdmVersion = EnumHelpers.GetEnumsWithoutDefault<SpdmVersions>().ToArray(),
                RunningMode = EnumHelpers.GetEnumsWithoutDefault<SpdmModes>().ToArray(),
                HashAlg = new[]
                {
                    HashFunctions.Sha2_d256,
                    HashFunctions.Sha2_d384,
                },             
                IsSample = true
            };

            return CreateRegistration(folderName, p);
        }

        protected override string GetTestFileLotsOfTestCases(string folderName)
        {
            var p = new Parameters
            {
                Algorithm = Algorithm,
                Mode = Mode,
                Revision = Revision,
                SpdmVersion = EnumHelpers.GetEnumsWithoutDefault<SpdmVersions>().ToArray(),
                RunningMode = EnumHelpers.GetEnumsWithoutDefault<SpdmModes>().ToArray(),
                HashAlg = new[]
                {
                    HashFunctions.Sha2_d256,
                    HashFunctions.Sha2_d384,
                },
                IsSample = false
            };

            return CreateRegistration(folderName, p);
        }
    }
}
