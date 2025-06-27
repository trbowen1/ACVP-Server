using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM
{
    public interface ISpdmKdf
    {


        /// <summary>
        /// Compute the Handshake Secret and get all intermediate values associated with its computation.
        /// </summary>
        /// <param name="sharedSecret">The shared secret as a result of ECDHE, pre-shared key, or KEM K or KEM K'.</param>
        /// <param name="isPSK">Indicates if the shared secret is a PSK or not.</param>
        /// <param name="transcriptHash1">Transcript Hash digest that is used in generation of handshake secrets.</param>
        /// <returns>Salt_1 and handshake secrets.</returns>
        SpdmKdfHandshakeSecretResult GetDerivedHandshakeSecret(BitString sharedSecret, bool isPSK, BitString transcriptHash1);

        /// <summary>
        /// Compute the master secret and get all intermediate values associated with its computation.
        /// </summary>
        /// <param name="salt_1">the derived salt_1.</param>
        /// <param name="transcriptHash2">Transcript Hash digest that is used in generation of application secrets.</param>
        /// <returns></returns>
        SpdmKdfMasterSecretResult GetDerivedMasterSecret(BitString salt_1, BitString transcriptHash2);

        /// <summary>
        /// Perform the full KDF from the individual parts.  Return all intermediate values.
        /// </summary>
        /// <param name="sharedSecret">The shared secret as a result of (EC)DHE.</param>
        /// <param name="isPSK">Indicates if the shared secret is a PSK or not.</param>
        /// <param name="transcriptHash1">Transcript Hash digest that is used in generation of handshake secrets.</param>
        /// <param name="transcriptHash2">Transcript Hash digest that is used in generation of application secrets.</param>
        /// <returns>The full KDF result and its intermediate values.</returns>
        SpdmKdfFullResult GetFullKdf(BitString sharedSecret, bool isPSK, BitString transcriptHash1, BitString transcriptHash2);
    }
}
