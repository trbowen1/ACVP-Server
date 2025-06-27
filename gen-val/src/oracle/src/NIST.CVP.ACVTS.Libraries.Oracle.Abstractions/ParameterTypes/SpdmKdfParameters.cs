using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;

namespace NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes
{
    public class SpdmKdfParameters
    {
        public SpdmVersions SpdmVersion { get; set; }
        public SpdmModes RunningMode { get; set; }
        public HashFunctions HashAlg { get; set; }
        
        
    }
}
