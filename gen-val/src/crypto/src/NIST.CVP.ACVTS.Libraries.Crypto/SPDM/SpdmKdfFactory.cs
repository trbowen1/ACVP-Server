using System;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.HKDF;
using NIST.CVP.ACVTS.Libraries.Math;
using System.Text;

namespace NIST.CVP.ACVTS.Libraries.Crypto.SPDM
{
    public class SpdmKdfFactory : ISpdmKdfFactory
    {
        private readonly IHkdfFactory _hkdfFactory;
        private readonly IShaFactory _shaFactory;


        public SpdmKdfFactory(IHkdfFactory hkdfFactory, IShaFactory shaFacory)
        {
            _hkdfFactory = hkdfFactory;
            _shaFactory = shaFacory;
        }

        public ISpdmKdf GetSpdmKdfInstance(SpdmModes spdmMode, SpdmVersions spdmVersion, HashFunctions hashFunction)
        {
            //BitString version;
            //switch (spdmVersion)
            //{
            //    case SpdmVersions.v11:
            //        version = new BitString(Encoding.ASCII.GetBytes("spdm1.1 "));
            //        break;
            //    case SpdmVersions.v12:
            //        version = new BitString(Encoding.ASCII.GetBytes("spdm1.2 "));
            //        break;
            //    case SpdmVersions.v13:
            //        version = new BitString(Encoding.ASCII.GetBytes("spdm1.3 "));
            //        break;
            //    case SpdmVersions.v14:
            //        version = new BitString(Encoding.ASCII.GetBytes("spdm1.4 "));
            //        break;
            //    default:
            //        throw new ArgumentException("Invalid SPDM version");
            //}

            var hf = ShaAttributes.GetHashFunctionFromEnum(hashFunction);

            return new SpdmKdf(spdmVersion, _hkdfFactory.GetKdf(hf), _shaFactory.GetShaInstance(hf), hf.OutputLen);
        }
    }
}
