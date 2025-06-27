using NIST.CVP.ACVTS.Libraries.Common.ExtensionMethods;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Libraries.Math.Domain;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NIST.CVP.ACVTS.Libraries.Generation.SPDM
{
    public class TestGroupGenerator : ITestGroupGeneratorAsync<Parameters, TestGroup, TestCase>
    {
        public Task<List<TestGroup>> BuildTestGroupsAsync(Parameters parameters)
        {
            var list = new List<TestGroup>();

            foreach (var spdmVersion in parameters.SpdmVersion)
            {
                foreach (var runningMode in parameters.RunningMode)
                {
                    foreach (var hashAlg in parameters.HashAlg)
                    {
                        list.Add(new TestGroup
                        {
                            SpdmVersion = spdmVersion,
                            RunningMode = runningMode,
                            HashAlg = hashAlg,
                        });
                    }
                    
                }
            }

            return Task.FromResult(list);
        }
    }
}
