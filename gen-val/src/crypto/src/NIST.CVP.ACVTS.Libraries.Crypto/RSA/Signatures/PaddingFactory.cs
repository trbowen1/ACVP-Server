﻿using System;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.RSA.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.RSA.Signatures;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Crypto.RSA.Signatures.Ansx;
using NIST.CVP.ACVTS.Libraries.Crypto.RSA.Signatures.Pkcs;
using NIST.CVP.ACVTS.Libraries.Crypto.RSA.Signatures.Pss;
using NIST.CVP.ACVTS.Libraries.Math.Entropy;

namespace NIST.CVP.ACVTS.Libraries.Crypto.RSA.Signatures
{
    public class PaddingFactory : IPaddingFactory
    {
        private readonly IMaskFactory _maskFactory;

        public PaddingFactory(IMaskFactory maskFactory)
        {
            _maskFactory = maskFactory;
        }

        /// Always correct
        public IPaddingScheme GetPaddingScheme(SignatureSchemes sigMode, ISha sha, PssMaskTypes maskType = PssMaskTypes.None, IEntropyProvider entropyProvider = null, int saltLength = 0, int outputLen = 0)
        {
            switch (sigMode)
            {
                case SignatureSchemes.Ansx931:
                    return new AnsxPadder(sha);

                case SignatureSchemes.Pkcs1v15:
                    return new PkcsPadder(sha);

                case SignatureSchemes.Pss:
                    var mask = _maskFactory.GetMaskInstance(maskType, sha.HashFunction, outputLen);
                    return new PssPadder(sha, mask, entropyProvider, saltLength, outputLen);

                default:
                    throw new ArgumentException("Invalid signature scheme");
            }
        }
        
        /// Could introduce errors
        public IPaddingScheme GetSigningPaddingScheme(SignatureSchemes sigMode, ISha sha, RSASignatureModifications errors, PssMaskTypes maskType = PssMaskTypes.None, IEntropyProvider entropyProvider = null, int saltLength = 0, int outputLen = 0)
        {
            if (sigMode == SignatureSchemes.Ansx931)
            {
                switch (errors)
                {
                    case RSASignatureModifications.None:
                        return new AnsxPadder(sha);

                    case RSASignatureModifications.E:
                        return new AnsxPadderWithModifiedPublicExponent(sha);

                    case RSASignatureModifications.Message:
                        return new AnsxPadderWithModifiedMessage(sha);

                    case RSASignatureModifications.ModifyTrailer:
                        return new AnsxPadderWithModifiedTrailer(sha);

                    case RSASignatureModifications.MoveIr:
                        return new AnsxPadderWithMovedIr(sha);

                    case RSASignatureModifications.Signature:
                        return new AnsxPadderWithModifiedSignature(sha);

                    default:
                        throw new ArgumentException("Signature modification does not exist for selected scheme");
                }
            }
            else if (sigMode == SignatureSchemes.Pkcs1v15)
            {
                switch (errors)
                {
                    case RSASignatureModifications.None:
                        return new PkcsPadder(sha);

                    case RSASignatureModifications.E:
                        return new PkcsPadderWithModifiedPublicExponent(sha);

                    case RSASignatureModifications.Message:
                        return new PkcsPadderWithModifiedMessage(sha);

                    case RSASignatureModifications.ModifyTrailer:
                        return new PkcsPadderWithModifiedTrailer(sha);

                    case RSASignatureModifications.MoveIr:
                        return new PkcsPadderWithMovedIr(sha);

                    case RSASignatureModifications.Signature:
                        return new PkcsPadderWithModifiedSignature(sha);

                    default:
                        throw new ArgumentException("Signature modification does not exist for selected scheme");
                }
            }
            else if (sigMode == SignatureSchemes.Pss)
            {
                var mask = _maskFactory.GetMaskInstance(maskType, sha.HashFunction, outputLen);

                switch (errors)
                {
                    case RSASignatureModifications.None:
                        return new PssPadder(sha, mask, entropyProvider, saltLength, outputLen);

                    case RSASignatureModifications.E:
                        return new PssPadderWithModifiedPublicExponent(sha, mask, entropyProvider, saltLength, outputLen);

                    case RSASignatureModifications.Message:
                        return new PssPadderWithModifiedMessage(sha, mask, entropyProvider, saltLength, outputLen);

                    case RSASignatureModifications.ModifyTrailer:
                        return new PssPadderWithModifiedTrailer(sha, mask, entropyProvider, saltLength, outputLen);

                    case RSASignatureModifications.MoveIr:
                        return new PssPadderWithMovedIr(sha, mask, entropyProvider, saltLength, outputLen);

                    case RSASignatureModifications.Signature:
                        return new PssPadderWithModifiedSignature(sha, mask, entropyProvider, saltLength, outputLen);

                    default:
                        throw new ArgumentException("Signature modification does not exist for selected scheme");
                }
            }

            throw new ArgumentException("Invalid signature scheme");
        }
    }
}
