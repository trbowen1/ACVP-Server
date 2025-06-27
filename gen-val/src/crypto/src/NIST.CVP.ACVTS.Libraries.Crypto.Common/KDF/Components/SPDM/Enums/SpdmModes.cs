using System.Runtime.Serialization;

namespace NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums
{
    public enum SpdmModes
    {
        None,
        [EnumMember(Value = "ECDHEOrKEM")]
        ECDHEOrKEM,
        [EnumMember(Value = "PSK")]
        PSK
    }
}
