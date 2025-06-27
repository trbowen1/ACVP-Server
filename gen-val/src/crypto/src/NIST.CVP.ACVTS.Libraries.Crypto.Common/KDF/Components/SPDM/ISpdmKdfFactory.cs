using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;

namespace NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM
{
    public interface ISpdmKdfFactory
    {
        ISpdmKdf GetSpdmKdfInstance(SpdmModes spdmMode, SpdmVersions spdmVersion, HashFunctions hashFunction);
    }
}
