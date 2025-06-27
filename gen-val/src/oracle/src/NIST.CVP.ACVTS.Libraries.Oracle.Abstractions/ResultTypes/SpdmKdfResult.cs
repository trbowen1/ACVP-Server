using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM;
using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ResultTypes
{
    public class SpdmKdfResult
    {
        public SpdmKdfFullResult DerivedKeyingMaterial { get; set; }

        public BitString SharedSecret { get; set; }
        
        public BitString TranscriptHash1Random { get; set; }
        public BitString TranscriptHash2Random { get; set; }
    }
}
