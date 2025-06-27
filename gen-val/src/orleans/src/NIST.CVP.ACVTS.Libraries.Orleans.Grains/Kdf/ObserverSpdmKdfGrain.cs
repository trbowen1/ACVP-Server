using System;
using System.Linq;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Common;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Libraries.Math.Entropy;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ParameterTypes;
using NIST.CVP.ACVTS.Libraries.Oracle.Abstractions.ResultTypes;
using NIST.CVP.ACVTS.Libraries.Orleans.Grains.Interfaces.Kdf;

namespace NIST.CVP.ACVTS.Libraries.Orleans.Grains.Kdf
{
    public class ObserverSpdmKdfGrain : ObservableOracleGrainBase<SpdmKdfResult>, IObserverSpdmKdfGrain
    {
        private readonly ISpdmKdfFactory _spdmFactory;
        private readonly IEntropyProvider _entropyProvider;

        private SpdmKdfParameters _param;

        public ObserverSpdmKdfGrain(
            LimitedConcurrencyLevelTaskScheduler nonOrleansScheduler,
            ISpdmKdfFactory spdmFactory,
            IEntropyProviderFactory entropyProviderFactory)
            : base(nonOrleansScheduler)
        {
            _spdmFactory = spdmFactory;
            _entropyProvider = entropyProviderFactory.GetEntropyProvider(EntropyProviderTypes.Random);
        }

        public async Task<bool> BeginWorkAsync(SpdmKdfParameters param)
        {
            _param = param;

            await BeginGrainWorkAsync();
            return await Task.FromResult(true);
        }

        protected override async Task DoWorkAsync()
        {
            try
            {
                var kdf = _spdmFactory.GetSpdmKdfInstance(_param.RunningMode, _param.SpdmVersion, _param.HashAlg);

                var digestLengthBits = ShaAttributes.GetHashFunctionFromEnum(_param.HashAlg).OutputLen;

                var sharedSecret = _entropyProvider.GetEntropy(digestLengthBits);

                bool isPsk = false;

                if (new[] { SpdmModes.PSK }.Contains(_param.RunningMode))
                {
                    isPsk = true;
                }

                var transcriptHash1Random = _entropyProvider.GetEntropy(digestLengthBits);
                var transcriptHash2Random = _entropyProvider.GetEntropy(digestLengthBits);

                var dkm = kdf.GetFullKdf(sharedSecret, isPsk, transcriptHash1Random, transcriptHash2Random);

                await Notify(new SpdmKdfResult()
                {
                    SharedSecret = sharedSecret,

                    TranscriptHash1Random = transcriptHash1Random,
                    TranscriptHash2Random = transcriptHash2Random,

                    DerivedKeyingMaterial = dkm,
                });
            }
            catch (Exception e)
            {
                await Throw(e);
            }
        }
    }
}
