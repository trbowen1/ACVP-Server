using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.HKDF;
using NIST.CVP.ACVTS.Libraries.Crypto.TLS;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Libraries.Math.Helpers;
using System;
using System.Reflection.Emit;
using System.Text;

namespace NIST.CVP.ACVTS.Libraries.Crypto.SPDM
{
    /// <summary>
    /// SPDM KDF from DSP0274 section 12: https://www.dmtf.org/dsp/dsp0274
    /// </summary>
    public class SpdmKdf : ISpdmKdf
    {
        private readonly IHkdf _hkdf;
        private readonly ISha _sha;
        private readonly int _hashOutputLengthBits;
        private readonly BitString _bitstringHashLengthBytesLSB;
        private readonly BitString _bitstringSpdmVersion;
        private readonly SpdmVersions _spdmVersion;

        public SpdmKdf(SpdmVersions spdmVersion, IHkdf hkdf, ISha sha, int hashOutputLengthBits)
        {
            _hkdf = hkdf;
            _sha = sha;
            _hashOutputLengthBits = hashOutputLengthBits;


            // store hash size in bytes in little endian/LSB format which requires byte swapping (performed via ToBytes method)
            _bitstringHashLengthBytesLSB = new BitString(BitString.To16BitString((short)(_hashOutputLengthBits / 8)).ToBytes(true));
            _spdmVersion = spdmVersion;

            switch (spdmVersion)
            {
                case SpdmVersions.v11:
                    _bitstringSpdmVersion = new BitString(Encoding.ASCII.GetBytes("spdm1.1 "));
                    break;
                case SpdmVersions.v12:
                    _bitstringSpdmVersion = new BitString(Encoding.ASCII.GetBytes("spdm1.2 "));
                    break;
                case SpdmVersions.v13:
                    _bitstringSpdmVersion = new BitString(Encoding.ASCII.GetBytes("spdm1.3 "));
                    break;
                case SpdmVersions.v14:
                    _bitstringSpdmVersion = new BitString(Encoding.ASCII.GetBytes("spdm1.4 "));
                    break;
                default:
                    throw new ArgumentException("Invalid SPDM version");
            }

        }

        public SpdmKdfHandshakeSecretResult GetDerivedHandshakeSecret(BitString sharedSecret, bool isPSK, BitString transcriptHash1)
        {

            var salt_0 = BitString.Zeroes(_hashOutputLengthBits); // most cases salt_0 should be all 0s

            if ((_spdmVersion == SpdmVersions.v13 && isPSK == true) || (_spdmVersion == SpdmVersions.v14 && isPSK == true))
            {
                salt_0 = BitString.Ones(_hashOutputLengthBits);
            }



            var handshakeSecret = _hkdf.Extract(salt_0, sharedSecret);


            var bin_str0 = BinConcat(_bitstringHashLengthBytesLSB, _bitstringSpdmVersion, new BitString(Encoding.ASCII.GetBytes("derived")));
            var bin_str1 = BinConcat(_bitstringHashLengthBytesLSB, _bitstringSpdmVersion, new BitString(Encoding.ASCII.GetBytes("req hs data")), transcriptHash1);
            var bin_str2 = BinConcat(_bitstringHashLengthBytesLSB, _bitstringSpdmVersion, new BitString(Encoding.ASCII.GetBytes("rsp hs data")), transcriptHash1);

            var requestDirectionHandshakeSecret = _hkdf.Expand(handshakeSecret, bin_str1, _hashOutputLengthBits / 8);

            var responseDirectionHandshakeSecret = _hkdf.Expand(handshakeSecret, bin_str2, _hashOutputLengthBits / 8);

            var salt_1 = _hkdf.Expand(handshakeSecret, bin_str0, _hashOutputLengthBits / 8);

            return new SpdmKdfHandshakeSecretResult()
            {
                HandshakeSecret = handshakeSecret,
                RequestDirectionHandshakeSecret = requestDirectionHandshakeSecret,
                ResponseDirectionHandshakeSecret = responseDirectionHandshakeSecret,
                Salt_1 = salt_1,
            };
        }

        public SpdmKdfMasterSecretResult GetDerivedMasterSecret(BitString salt_1, BitString transcriptHash2)
        {
            var masterSecret = _hkdf.Extract(salt_1, BitString.Zeroes(_hashOutputLengthBits));

            var bin_str3 = BinConcat(_bitstringHashLengthBytesLSB, _bitstringSpdmVersion, new BitString(Encoding.ASCII.GetBytes("req app data")), transcriptHash2);
            var bin_str4 = BinConcat(_bitstringHashLengthBytesLSB, _bitstringSpdmVersion, new BitString(Encoding.ASCII.GetBytes("rsp app data")), transcriptHash2);
            var bin_str8 = BinConcat(_bitstringHashLengthBytesLSB, _bitstringSpdmVersion, new BitString(Encoding.ASCII.GetBytes("exp master")), transcriptHash2);


            var requestDirectionDataSecret = _hkdf.Expand(masterSecret, bin_str3, _hashOutputLengthBits / 8);

            var responseDirectionDataSecret = _hkdf.Expand(masterSecret, bin_str4, _hashOutputLengthBits / 8);

            var exportMasterSecret = _hkdf.Expand(masterSecret, bin_str8, _hashOutputLengthBits / 8);



            return new SpdmKdfMasterSecretResult()
            {
                MasterSecret = masterSecret,
                RequestDirectionDataSecret = requestDirectionDataSecret,
                ResponseDirectionDataSecret = responseDirectionDataSecret,
                ExportMasterSecret = exportMasterSecret
            };
        }

        public SpdmKdfFullResult GetFullKdf(BitString sharedSecret, bool isPSK, BitString transcriptHash1, BitString transcriptHash2)
        {
            var handshakeSecretResult = GetDerivedHandshakeSecret(sharedSecret, isPSK, transcriptHash1);
            var masterSecretResult = GetDerivedMasterSecret(handshakeSecretResult.Salt_1, transcriptHash2);

            return new SpdmKdfFullResult()
            {
                HandshakeSecretResult = handshakeSecretResult,
                MasterSecretResult = masterSecretResult
            };
        }


        /// <summary>
        /// Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
        /// </summary>
        /// <param name="messages"></param>
        /// <returns></returns>
        public BitString TranscriptHash(params BitString[] messages)
        {
            var concatenatedMessages = BitString.Empty();
            foreach (var message in messages)
            {
                concatenatedMessages = concatenatedMessages.ConcatenateBits(message);
            }

            return _sha.HashMessage(concatenatedMessages).Digest;
        }

        /// <summary>
        /// Binary Concatenation function based off of DSP0274 BinConcat function.
        /// To properly match BinConcat definition of DSP0274, the following data should be provided:
        /// 16 bits Length identifying the number of bytes of the hash function in use
        /// 8 Bytes identifying the SPDM protocol version
        /// Variable sized label
        /// Variable sized context such as a transcript hash
        /// </summary>
        /// <param name="data_array"></param>
        /// <returns></returns>
        public BitString BinConcat(params BitString[] data_array)
        {
            var concatenatedData = BitString.Empty();
            foreach (var data in data_array)
            {
                concatenatedData = concatenatedData.ConcatenateBits(data);
            }

            return concatenatedData;
        }


    }
}
