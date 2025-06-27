using System.ComponentModel;
using System.Runtime.Serialization;

namespace NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums
{
    public enum SpdmVersions
    {
        [EnumMember(Value = "v1.1")]
        v11,

        [EnumMember(Value = "v1.2")]
        v12,

        [EnumMember(Value = "v1.3")]
        v13,

        [EnumMember(Value = "v1.4")]
        v14,
    }
}
