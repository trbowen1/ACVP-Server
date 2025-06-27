using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM
{
    public class SpdmKdfFullResult
    {
        public SpdmKdfHandshakeSecretResult HandshakeSecretResult { get; set; }
        public SpdmKdfMasterSecretResult MasterSecretResult { get; set; }
    }
    
    public class SpdmKdfHandshakeSecretResult
    {
        public BitString HandshakeSecret { get; set; }
        public BitString RequestDirectionHandshakeSecret { get; set; }
        public BitString ResponseDirectionHandshakeSecret { get; set; }
        public BitString Salt_1 { get; set; }
    }
    public class SpdmKdfMasterSecretResult
    {
        public BitString MasterSecret { get; set; }
        public BitString RequestDirectionDataSecret { get; set; }
        public BitString ResponseDirectionDataSecret { get; set; }
        public BitString ExportMasterSecret { get; set; }
    }
}
