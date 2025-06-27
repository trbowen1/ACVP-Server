using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.Components.SPDM.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KDF.HKDF;
using NIST.CVP.ACVTS.Libraries.Crypto.HKDF;
using NIST.CVP.ACVTS.Libraries.Crypto.HMAC;
using NIST.CVP.ACVTS.Libraries.Crypto.KTS;
using NIST.CVP.ACVTS.Libraries.Crypto.SHA.NativeFastSha;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Tests.Core.TestCategoryAttributes;
using NUnit.Framework;
using System.Text;

namespace NIST.CVP.ACVTS.Libraries.Crypto.SPDM.Tests
{
    [TestFixture, FastCryptoTest]
    public class SpdmKdfTests
    {
        private readonly ISpdmKdfFactory _spdmFactory =
            new SpdmKdfFactory(new HkdfFactory(new HmacFactory(new NativeShaFactory())), new NativeShaFactory());

        /// <summary>
        /// Test SPDM KDF with SHA384 using test sample test vectors generated from spdm-emu using libspdm"
        /// </summary>
        [Test]
        public void TestVectorSpdmEmu_SimpleHandshake_SHA384()
        {
            var kdf = (SpdmKdf)_spdmFactory.GetSpdmKdfInstance(SpdmModes.ECDHEOrKEM, SpdmVersions.v13, HashFunctions.Sha2_d384); // test vector selected SHA384 during algorithm negotiation

            // reference input vectors generated from spdm-emu
            var getVersion = new BitString("10 84 00 00");
            var version = new BitString("10 04 00 00 00 04 00 10 00 11 00 12 00 13");
            var getCapabilities = new BitString("13 e1 00 00 00 00 00 00 c6 f7 82 08 00 12 00 00 00 12 00 00");
            var capabilities = new BitString("13 61 00 00 00 00 00 00 f7 fb 9a 39 00 12 00 00 00 12 00 00");
            var negotiateAlgorithms = new BitString("13 e3 04 00 30 00 01 12 90 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 02 20 1b 00 03 20 06 00 04 20 0f 00 05 20 01 00");
            var algorithms = new BitString("13 63 04 00 34 00 01 12 08 00 00 00 80 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 02 20 10 00 03 20 02 00 04 20 08 00 05 20 01 00");

            var vca = getVersion.ConcatenateBits(version).ConcatenateBits(getCapabilities).ConcatenateBits(capabilities).ConcatenateBits(negotiateAlgorithms).ConcatenateBits(algorithms);

            var getDigests = new BitString("13 81 00 00");
            var digests = new BitString("13 01 07 07 dc 02 4e 78 fa 5e 45 d8 2e 45 c6 7f b5 fc e2 b9 98 7a df ee 9e a3 3e 56 d5 ed 83 47 e8 aa a3 d0 18 91 72 7f 3c 5d d7 a2 e1 ab 7f d3 61 38 37 5d 0d 0d 5c f1 c3 ba 90 2c d5 9c 95 f2 5e 29 15 0f a3 78 70 8e a1 cd 97 82 da 82 ff c3 ea c4 8e 13 48 22 0e 89 ab 97 f8 bb 92 8a 82 4e 9e f5 95 1f dc 02 4e 78 fa 5e 45 d8 2e 45 c6 7f b5 fc e2 b9 98 7a df ee 9e a3 3e 56 d5 ed 83 47 e8 aa a3 d0 18 91 72 7f 3c 5d d7 a2 e1 ab 7f d3 61 38 37 5d a0 a1 a2 01 01 01 0f 00 0f 00 0f 00");

            var certificate = new BitString("37 06 00 00 71 0b a5 94 61 1d 3a 37 c9 10 a1 44 38 f6 d9 2e 7d b9 bb aa 6b ab 66 de bc ea b1 cf 23 a3 38 90 73 24 2e 5f 6c e9 f6 7b c9 8a 7f a2 fa 38 46 e2 30 82 01 d4 30 82 01 5a a0 03 02 01 02 02 14 21 41 dd 4e ec f8 19 62 24 2e 7e d6 ae 64 cb 29 5d c4 90 51 30 0a 06 08 2a 86 48 ce 3d 04 03 03 30 21 31 1f 30 1d 06 03 55 04 03 0c 16 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 43 41 30 1e 17 0d 32 33 30 34 32 30 30 31 31 33 35 34 5a 17 0d 33 33 30 34 31 37 30 31 31 33 35 34 5a 30 21 31 1f 30 1d 06 03 55 04 03 0c 16 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 43 41 30 76 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 22 03 62 00 04 15 1c 0b 41 fb 87 d5 20 e0 7a f8 58 67 ef c0 ed 61 af 58 bf 92 52 33 ae 87 a9 7f 46 8b d4 b6 ef aa 2c 5b 0f 84 19 a0 8c 10 9b 81 4c d7 64 7e 32 6e 02 c5 fc 3d 25 7c a3 bc b5 ca a6 ce 04 11 8d bd ba 19 73 92 98 56 cc 99 24 48 17 ef b2 fb 54 3f f0 31 1d b4 a3 04 ea dc 22 ca c8 9a 2d fd fc a3 53 30 51 30 1d 06 03 55 1d 0e 04 16 04 14 4a e2 a4 0a c0 5d ae a2 30 aa d0 57 70 d0 51 58 5f 5c a3 52 30 1f 06 03 55 1d 23 04 18 30 16 80 14 4a e2 a4 0a c0 5d ae a2 30 aa d0 57 70 d0 51 58 5f 5c a3 52 30 0f 06 03 55 1d 13 01 01 ff 04 05 30 03 01 01 ff 30 0a 06 08 2a 86 48 ce 3d 04 03 03 03 68 00 30 65 02 30 2a 32 95 2c ff aa 1f 33 52 6f 6c fd 40 72 ff 17 89 6e 03 5f bb 42 03 c4 6e 17 86 aa 98 a8 c1 20 12 d9 04 7c 16 ea 1f ae 8a ef 85 11 41 57 df fc 02 31 00 a8 4c b9 90 4b 2f 6a 4f c2 8e d8 23 ad 81 de 4c 51 50 0b 27 17 8f 46 26 89 3b 9f f9 ce 48 e0 ee 28 fd 3f 06 e1 b3 4d 8f 6c 48 1c 2a 94 a9 d0 de 30 82 01 dc 30 82 01 61 a0 03 02 01 02 02 01 01 30 0a 06 08 2a 86 48 ce 3d 04 03 03 30 21 31 1f 30 1d 06 03 55 04 03 0c 16 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 43 41 30 1e 17 0d 32 33 30 34 32 30 30 31 31 34 30 35 5a 17 0d 33 33 30 34 31 37 30 31 31 34 30 35 5a 30 30 31 2e 30 2c 06 03 55 04 03 0c 25 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 69 6e 74 65 72 6d 65 64 69 61 74 65 20 63 65 72 74 30 76 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 22 03 62 00 04 31 7d 01 41 1a f7 e9 ea 5c 39 1e 37 6a 16 8d 2c 6e d9 7e ea 19 25 c5 97 40 dc ce 39 7f 92 46 cb fb 4b 44 d8 f7 3d db 47 a6 44 bf 55 77 02 35 d1 37 27 68 a4 e8 04 4e 87 75 8f 59 57 a9 80 b8 b4 3c 97 ca fa 1b 13 a8 50 dc 0d 7a be 13 3d 31 5b fd d8 9f d6 fc aa 27 33 b8 92 5c 5b b8 0c 24 ca a3 5e 30 5c 30 0c 06 03 55 1d 13 04 05 30 03 01 01 ff 30 0b 06 03 55 1d 0f 04 04 03 02 01 fe 30 1d 06 03 55 1d 0e 04 16 04 14 00 0f 6f a7 6b 1f 34 03 0e 5a 21 c7 38 eb f1 a5 57 d5 57 cd 30 20 06 03 55 1d 25 01 01 ff 04 16 30 14 06 08 2b 06 01 05 05 07 03 01 06 08 2b 06 01 05 05 07 03 02 30 0a 06 08 2a 86 48 ce 3d 04 03 03 03 69 00 30 66 02 31 00 99 03 64 47 66 6c 30 6a b7 9d d3 5a 99 21 68 ae 09 50 6f eb b4 fd ef 69 0b cf b2 56 4f b6 8f 1f 43 11 0c de f6 fd 77 fd a9 34 25 81 7e 97 64 4c 02 31 00 f9 c7 5c 54 3d 43 92 9a 30 3d 61 1a 1e f8 65 51 d4 d5 20 90 d2 85 f0 44 de 40 85 ea 34 61 dd 6b fe 60 bd 0a c0 db 3d 43 2c ad d4 c4 e9 fa 22 33 30 82 02 47 30 82 01 cc a0 03 02 01 02 02 01 03 30 0a 06 08 2a 86 48 ce 3d 04 03 03 30 30 31 2e 30 2c 06 03 55 04 03 0c 25 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 69 6e 74 65 72 6d 65 64 69 61 74 65 20 63 65 72 74 30 1e 17 0d 32 33 30 39 31 32 30 37 31 31 33 33 5a 17 0d 33 33 30 39 30 39 30 37 31 31 33 33 5a 30 2d 31 2b 30 29 06 03 55 04 03 0c 22 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 72 65 73 70 6f 6e 64 65 72 20 63 65 72 74 30 76 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 22 03 62 00 04 0d 1c b9 20 1c dc ed c8 64 e9 70 a3 62 12 da d4 fe 59 94 ce bd ae d7 d2 94 e4 e3 11 88 78 b9 88 c0 ed 5b e1 41 4a df 28 db 49 0f 38 81 52 68 b5 4c 6a 11 0b 58 b1 9c c1 4d 47 41 14 1f 6d d6 57 ac a3 9f d1 b9 64 de 07 11 e8 31 78 de 75 3a b7 2c 15 56 ea f5 20 63 93 0f 33 a9 71 a3 7e 78 19 a3 81 bc 30 81 b9 30 0c 06 03 55 1d 13 01 01 ff 04 02 30 00 30 0b 06 03 55 1d 0f 04 04 03 02 05 e0 30 1d 06 03 55 1d 0e 04 16 04 14 14 3c 4f 66 c7 d7 60 40 7f 67 c1 95 68 b3 87 28 3e c5 23 83 30 31 06 03 55 1d 11 04 2a 30 28 a0 26 06 0a 2b 06 01 04 01 83 1c 82 12 01 a0 18 0c 16 41 43 4d 45 3a 57 49 44 47 45 54 3a 31 32 33 34 35 36 37 38 39 30 30 2a 06 03 55 1d 25 01 01 ff 04 20 30 1e 06 08 2b 06 01 05 05 07 03 01 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 09 30 1e 06 0a 2b 06 01 04 01 83 1c 82 12 06 04 10 30 0e 30 0c 06 0a 2b 06 01 04 01 83 1c 82 12 02 30 0a 06 08 2a 86 48 ce 3d 04 03 03 03 69 00 30 66 02 31 00 af 75 02 a9 b3 a6 47 4a 6e f4 0c b0 85 07 fc 3c 53 9d 29 b0 09 c2 b9 b3 f3 96 b9 99 be c5 75 9c ac 4f c3 8a 7a 24 7d 17 f7 cb 2a 71 14 57 3e 92 02 31 00 d3 57 af 94 68 e1 02 b6 51 50 0c 4a 74 97 72 37 b5 03 ff 58 80 e0 f5 eb ae 1e 81 d8 d5 84 3d 18 83 60 fe 07 cd 43 2d 27 bd f5 a4 a5 19 7f 5d 09");
            var certificateHash = kdf.TranscriptHash(certificate);
            
            var keyExchange = new BitString("13 e4 ff 00 ff ff 01 00 ad 39 70 fa 40 4b 29 10 06 57 10 81 03 2e 53 02 06 dd 00 58 c6 ef de 5f 3d c3 68 d2 5a 37 07 6c 15 63 b3 c7 aa 4d c3 02 f7 9d 1e 98 58 e4 c1 31 6f e3 6a e5 80 a7 6c 4b a2 68 80 b6 6c e2 56 14 29 10 89 49 cd 4c f4 e0 ff 95 be 99 14 83 83 6c d0 3c 95 7a 1a 44 7e 94 63 42 5c 49 f3 25 54 90 44 21 a6 fd b1 08 b9 ba 54 ec 22 1b 68 14 2a 84 75 36 cd d2 cd 7d 90 94 52 8f af 12 c0 53 b5 4c 14 00 01 00 00 00 00 00 09 00 01 01 03 00 10 00 11 00 12 00 00 00");
            var keyExchangeRsp = new BitString("13 64 f0 00 ff ff 00 00 5c cc 91 d5 82 c2 f4 5e 30 45 3c b5 96 7e 3d 3d 8f 99 09 0f 39 72 a3 7e e7 26 44 5f 84 03 ab 18 e5 6d 49 95 5d 31 71 47 c9 28 ee 05 f0 c8 99 fa f0 05 4b fe d0 d4 6a b5 68 40 ec dd a5 d6 48 25 b7 f1 59 9e 52 79 bb 1a 6c a0 f9 77 0a 16 ad e1 88 95 32 c0 a6 26 11 6b 15 2f cd 06 67 0d da 76 54 02 dd e9 3e 47 34 41 d9 37 24 7c d8 19 9a 55 9c 05 b3 6a e9 2e 84 69 f9 bc 1d b2 60 76 f2 8e fd ab e1 6b 17 de df 3e 76 2a 76 f1 c5 d9 ee 01 5e 9f 50 b7 5b d7 5e a1 8d b5 d3 98 b8 80 25 8b 46 fc c8 1a e5 3a 9a a3 5f 49 f4 c2 4f 4e d5 a2 0c 00 01 00 00 00 00 00 04 00 01 00 00 12 5b 9d fd ce 71 a1 c7 b5 48 dd 63 9b 09 e4 82 3f ee 72 d5 45 55 74 09 2c da cb b8 df 66 89 7d 21 6c f5 11 06 37 30 eb a2 6c 38 b4 54 6a 23 32 39 3b e7 61 0e 0c 14 6f e4 5f d3 32 8c 71 3c 0b 62 31 9f 2d 56 a0 ca 41 b2 60 50 40 0e 7e 1f 5f 6e c9 b1 00 00 e9 9e 04 ca 15 50 b9 76 05 e0 7d 8f");

            var referenceTh1 = new BitString("b2 16 d2 e7 37 7c e2 f5 d6 73 8c f1 20 e4 86 9e 33 85 f4 2b 08 17 e9 9e 45 84 a6 09 d1 e8 23 35 f6 26 57 65 38 fe b5 be a3 7d 0c c8 fd 25 cf ad");

            var calculatedTh1 = kdf.TranscriptHash(vca, digests, certificateHash, keyExchange, keyExchangeRsp);

            var dheSecret = new BitString("d4 26 32 37 9e 85 7b fa 3f 72 e0 0b 53 60 19 a0 a1 d5 1e 80 02 1a 6e e7 57 39 76 3a c8 88 17 db 7b c7 bb bf 25 fc 4d 69 4d 86 f8 31 97 4f e7 40");

            Assert.That(calculatedTh1.ToHex(), Is.EqualTo(referenceTh1.ToHex()), "Check that TH1 is equal");


            // Calculate handshake secrets using reference inputs
            var handshakeSecrets = kdf.GetDerivedHandshakeSecret(dheSecret, false, calculatedTh1);


            // reference expected handshake secrets
            var referenceHandshakeSecret = new BitString("0c a6 6d 2d c1 78 02 a5 29 cb d3 86 f1 a0 4e d1 fe 14 e9 b0 2f 7c 1d e7 7b 44 43 2c 43 32 50 c3 49 79 b4 1a 30 78 f5 d6 b2 e0 b5 cc ae 4a 65 38");

            var referenceRequestHandshakeSecret = new BitString("73 c2 56 98 d1 50 33 fa fb 55 42 c1 08 7e 87 53 d9 94 5b 92 e3 e6 5d e1 70 41 81 65 b6 c9 e9 e6 ed d8 67 6a e5 fb 22 c9 9a e8 8b 75 12 e2 56 aa");

            var referenceResponderHandshakeSecret = new BitString("62 f2 65 5e 23 e6 f4 c7 08 52 91 72 ce dc 3b cb 7c 5b 25 84 9f 29 4b 70 e4 c4 95 41 89 c4 57 fe 44 f4 e5 9b b4 65 6d 7b e9 c3 31 ac 00 4a 6c 35");

            var referenceSalt1 = new BitString("37 f0 42 ed 8b d2 1d 75 b4 e6 1a 03 b9 7e 0e 3a 06 66 38 76 ed 23 d1 bb 6e 62 fc 39 9a 8f c3 67 4a a1 cd da ac 94 6c 61 d6 92 39 4e 94 d6 da cc");


            // test that calculated handhskae secrets match reference handshake secrets
            Assert.That(handshakeSecrets.HandshakeSecret.ToHex(), Is.EqualTo(referenceHandshakeSecret.ToHex()), "Check that handshake secret is equal");
            Assert.That(handshakeSecrets.RequestDirectionHandshakeSecret.ToHex(), Is.EqualTo(referenceRequestHandshakeSecret.ToHex()), "Check that request direction handshake secret is equal");
            Assert.That(handshakeSecrets.ResponseDirectionHandshakeSecret.ToHex(), Is.EqualTo(referenceResponderHandshakeSecret.ToHex()), "Check that response direction handshake secret is equal");
            Assert.That(handshakeSecrets.Salt_1.ToHex(), Is.EqualTo(referenceSalt1.ToHex()), "Check that salt1 is equal");


            // reference finish messages
            var finish = new BitString("13 e5 00 00 eb f5 e7 a5 d4 08 90 d7 91 c1 b4 6d 43 f5 e4 1f cc 5f ce d6 e2 c4 82 1a 1a 9f 17 c1 e3 9a 93 1d 37 1d 44 63 da 04 65 93 36 2c 1d 91 62 e9 5b 71");

            var finishRsp = new BitString("13 65 00 00 1d 97 c1 07 6c 10 50 90 37 45 3a d2 e9 38 c7 77 0c 6c e0 30 dc 57 77 01 35 af 37 f7 57 9a 57 8f 5d 03 eb b7 d9 ce 51 d0 4b 82 f5 d7 ed 11 87 d3");


            var referenceTh2 = new BitString("71 75 29 16 4c 42 66 06 d8 84 15 c5 a9 8d 48 5c 83 52 5d 5e aa 17 c1 11 bd 5b 97 f6 87 11 e7 e5 33 ef 4d e8 34 9c c3 c5 ce ee b9 cc b5 da 65 0a");

            var calculatedTh2 = kdf.TranscriptHash(vca, digests, certificateHash, keyExchange, keyExchangeRsp, finish, finishRsp);

            Assert.That(calculatedTh2.ToHex(), Is.EqualTo(referenceTh2.ToHex()), "Check that TH2 is equal");

            // Calculate master and data secrets
            var masterSecrets = kdf.GetDerivedMasterSecret(handshakeSecrets.Salt_1, calculatedTh2);

            // reference expected master and data secrets
            var referenceMasterSecret = new BitString("85 4c 16 5f fa 61 77 e3 e8 3c 3c 0d e3 9f d5 26 e7 97 9d f3 35 96 03 4c 62 c5 16 2f 04 46 1c 17 08 64 a5 4f 37 24 10 f7 53 41 70 7a 1b 71 b1 eb");

            var referenceRequestDataSecret = new BitString("3e 71 01 72 5f 21 b3 e4 06 5b 69 98 0d 25 73 11 87 2c f6 32 8a 7e f3 68 71 3a 9f b9 c7 41 2f cb 9f 7c aa b6 0b 7e bc 17 1c 8b c7 a8 f3 96 a8 16");

            var referenceResponseDataSecret = new BitString("d4 c5 cc d2 25 56 4a 50 02 fa 28 4c 94 1d 1f e7 e1 ec ab 59 72 0f d7 20 c6 01 e8 d7 d3 04 ea f4 34 b0 e9 c8 88 fe be 9e 74 6f f4 ce 1a 1a 0a 48");

            var referenceExportMasterSecret = new BitString("cd 99 ae 62 04 f9 77 9f 27 4f 06 bb 94 8b b0 ee 95 a0 00 58 5a df 69 31 7e 4c bb d1 6e 96 29 e1 97 be dd f8 1f e3 33 2c 87 fe 13 79 33 82 92 52");

            // test that calculated master and data secrets match reference secrets
            Assert.That(masterSecrets.MasterSecret.ToHex(), Is.EqualTo(referenceMasterSecret.ToHex()), "Check that master secret is equal");
            Assert.That(masterSecrets.RequestDirectionDataSecret.ToHex(), Is.EqualTo(referenceRequestDataSecret.ToHex()), "Check that request direction data secret is equal");
            Assert.That(masterSecrets.ResponseDirectionDataSecret.ToHex(), Is.EqualTo(referenceResponseDataSecret.ToHex()), "Check that response direction data secret is equal");
            Assert.That(masterSecrets.ExportMasterSecret.ToHex(), Is.EqualTo(referenceExportMasterSecret.ToHex()), "Check that export master secret is equal");

            
        }

        /// <summary>
        /// Test SPDM KDF with SHA256 using test sample test vectors generated from spdm-emu using libspdm"
        /// </summary>
        [Test]
        public void TestVectorSpdmEmu_SimpleHandshake_SHA256()
        {
            var kdf = (SpdmKdf)_spdmFactory.GetSpdmKdfInstance(SpdmModes.ECDHEOrKEM, SpdmVersions.v13, HashFunctions.Sha2_d256); // test vector selected SHA256 during algorithm negotiation

            // reference input vectors generated from spdm-emu
            var getVersion = new BitString("10 84 00 00");
            var version = new BitString("10 04 00 00 00 04 00 10 00 11 00 12 00 13");
            var getCapabilities = new BitString("13 e1 00 00 00 00 00 00 c6 f7 82 08 00 12 00 00 00 12 00 00");
            var capabilities = new BitString("13 61 00 00 00 00 00 00 f7 fb 9a 39 00 12 00 00 00 12 00 00");
            var negotiateAlgorithms = new BitString("13 e3 04 00 30 00 01 12 90 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 02 20 1b 00 03 20 06 00 04 20 0f 00 05 20 01 00");
            var algorithms = new BitString("13 63 04 00 34 00 01 12 08 00 00 00 80 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 02 20 10 00 03 20 02 00 04 20 08 00 05 20 01 00");

            var vca = getVersion.ConcatenateBits(version).ConcatenateBits(getCapabilities).ConcatenateBits(capabilities).ConcatenateBits(negotiateAlgorithms).ConcatenateBits(algorithms);

            var getDigests = new BitString("13 81 00 00");
            var digests = new BitString("13 01 07 07 8c 89 96 3b 04 37 70 47 d4 e6 85 08 6b 0b 7e 04 b7 2b 4a ad 55 f2 4a e3 89 f6 fa 54 47 b5 06 bf 0b a5 5c c9 a4 1d 12 ec 08 79 16 17 be f5 19 cd de bf dc 44 5c 33 95 8e 51 3e b2 96 35 f8 90 8e 8c 89 96 3b 04 37 70 47 d4 e6 85 08 6b 0b 7e 04 b7 2b 4a ad 55 f2 4a e3 89 f6 fa 54 47 b5 06 bf a0 a1 a2 01 01 01 0f 00 0f 00 0f 00");

            var certificate = new BitString("27 06 00 00 59 9a c5 b3 8f fd f7 3b 55 e3 97 f8 cf c1 c3 3e bb 7b cc 5a fa b2 e4 2a 89 dd ed 53 36 6b 4e ec 30 82 01 d4 30 82 01 5a a0 03 02 01 02 02 14 21 41 dd 4e ec f8 19 62 24 2e 7e d6 ae 64 cb 29 5d c4 90 51 30 0a 06 08 2a 86 48 ce 3d 04 03 03 30 21 31 1f 30 1d 06 03 55 04 03 0c 16 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 43 41 30 1e 17 0d 32 33 30 34 32 30 30 31 31 33 35 34 5a 17 0d 33 33 30 34 31 37 30 31 31 33 35 34 5a 30 21 31 1f 30 1d 06 03 55 04 03 0c 16 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 43 41 30 76 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 22 03 62 00 04 15 1c 0b 41 fb 87 d5 20 e0 7a f8 58 67 ef c0 ed 61 af 58 bf 92 52 33 ae 87 a9 7f 46 8b d4 b6 ef aa 2c 5b 0f 84 19 a0 8c 10 9b 81 4c d7 64 7e 32 6e 02 c5 fc 3d 25 7c a3 bc b5 ca a6 ce 04 11 8d bd ba 19 73 92 98 56 cc 99 24 48 17 ef b2 fb 54 3f f0 31 1d b4 a3 04 ea dc 22 ca c8 9a 2d fd fc a3 53 30 51 30 1d 06 03 55 1d 0e 04 16 04 14 4a e2 a4 0a c0 5d ae a2 30 aa d0 57 70 d0 51 58 5f 5c a3 52 30 1f 06 03 55 1d 23 04 18 30 16 80 14 4a e2 a4 0a c0 5d ae a2 30 aa d0 57 70 d0 51 58 5f 5c a3 52 30 0f 06 03 55 1d 13 01 01 ff 04 05 30 03 01 01 ff 30 0a 06 08 2a 86 48 ce 3d 04 03 03 03 68 00 30 65 02 30 2a 32 95 2c ff aa 1f 33 52 6f 6c fd 40 72 ff 17 89 6e 03 5f bb 42 03 c4 6e 17 86 aa 98 a8 c1 20 12 d9 04 7c 16 ea 1f ae 8a ef 85 11 41 57 df fc 02 31 00 a8 4c b9 90 4b 2f 6a 4f c2 8e d8 23 ad 81 de 4c 51 50 0b 27 17 8f 46 26 89 3b 9f f9 ce 48 e0 ee 28 fd 3f 06 e1 b3 4d 8f 6c 48 1c 2a 94 a9 d0 de 30 82 01 dc 30 82 01 61 a0 03 02 01 02 02 01 01 30 0a 06 08 2a 86 48 ce 3d 04 03 03 30 21 31 1f 30 1d 06 03 55 04 03 0c 16 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 43 41 30 1e 17 0d 32 33 30 34 32 30 30 31 31 34 30 35 5a 17 0d 33 33 30 34 31 37 30 31 31 34 30 35 5a 30 30 31 2e 30 2c 06 03 55 04 03 0c 25 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 69 6e 74 65 72 6d 65 64 69 61 74 65 20 63 65 72 74 30 76 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 22 03 62 00 04 31 7d 01 41 1a f7 e9 ea 5c 39 1e 37 6a 16 8d 2c 6e d9 7e ea 19 25 c5 97 40 dc ce 39 7f 92 46 cb fb 4b 44 d8 f7 3d db 47 a6 44 bf 55 77 02 35 d1 37 27 68 a4 e8 04 4e 87 75 8f 59 57 a9 80 b8 b4 3c 97 ca fa 1b 13 a8 50 dc 0d 7a be 13 3d 31 5b fd d8 9f d6 fc aa 27 33 b8 92 5c 5b b8 0c 24 ca a3 5e 30 5c 30 0c 06 03 55 1d 13 04 05 30 03 01 01 ff 30 0b 06 03 55 1d 0f 04 04 03 02 01 fe 30 1d 06 03 55 1d 0e 04 16 04 14 00 0f 6f a7 6b 1f 34 03 0e 5a 21 c7 38 eb f1 a5 57 d5 57 cd 30 20 06 03 55 1d 25 01 01 ff 04 16 30 14 06 08 2b 06 01 05 05 07 03 01 06 08 2b 06 01 05 05 07 03 02 30 0a 06 08 2a 86 48 ce 3d 04 03 03 03 69 00 30 66 02 31 00 99 03 64 47 66 6c 30 6a b7 9d d3 5a 99 21 68 ae 09 50 6f eb b4 fd ef 69 0b cf b2 56 4f b6 8f 1f 43 11 0c de f6 fd 77 fd a9 34 25 81 7e 97 64 4c 02 31 00 f9 c7 5c 54 3d 43 92 9a 30 3d 61 1a 1e f8 65 51 d4 d5 20 90 d2 85 f0 44 de 40 85 ea 34 61 dd 6b fe 60 bd 0a c0 db 3d 43 2c ad d4 c4 e9 fa 22 33 30 82 02 47 30 82 01 cc a0 03 02 01 02 02 01 03 30 0a 06 08 2a 86 48 ce 3d 04 03 03 30 30 31 2e 30 2c 06 03 55 04 03 0c 25 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 69 6e 74 65 72 6d 65 64 69 61 74 65 20 63 65 72 74 30 1e 17 0d 32 33 30 39 31 32 30 37 31 31 33 33 5a 17 0d 33 33 30 39 30 39 30 37 31 31 33 33 5a 30 2d 31 2b 30 29 06 03 55 04 03 0c 22 44 4d 54 46 20 6c 69 62 73 70 64 6d 20 45 43 50 33 38 34 20 72 65 73 70 6f 6e 64 65 72 20 63 65 72 74 30 76 30 10 06 07 2a 86 48 ce 3d 02 01 06 05 2b 81 04 00 22 03 62 00 04 0d 1c b9 20 1c dc ed c8 64 e9 70 a3 62 12 da d4 fe 59 94 ce bd ae d7 d2 94 e4 e3 11 88 78 b9 88 c0 ed 5b e1 41 4a df 28 db 49 0f 38 81 52 68 b5 4c 6a 11 0b 58 b1 9c c1 4d 47 41 14 1f 6d d6 57 ac a3 9f d1 b9 64 de 07 11 e8 31 78 de 75 3a b7 2c 15 56 ea f5 20 63 93 0f 33 a9 71 a3 7e 78 19 a3 81 bc 30 81 b9 30 0c 06 03 55 1d 13 01 01 ff 04 02 30 00 30 0b 06 03 55 1d 0f 04 04 03 02 05 e0 30 1d 06 03 55 1d 0e 04 16 04 14 14 3c 4f 66 c7 d7 60 40 7f 67 c1 95 68 b3 87 28 3e c5 23 83 30 31 06 03 55 1d 11 04 2a 30 28 a0 26 06 0a 2b 06 01 04 01 83 1c 82 12 01 a0 18 0c 16 41 43 4d 45 3a 57 49 44 47 45 54 3a 31 32 33 34 35 36 37 38 39 30 30 2a 06 03 55 1d 25 01 01 ff 04 20 30 1e 06 08 2b 06 01 05 05 07 03 01 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 09 30 1e 06 0a 2b 06 01 04 01 83 1c 82 12 06 04 10 30 0e 30 0c 06 0a 2b 06 01 04 01 83 1c 82 12 02 30 0a 06 08 2a 86 48 ce 3d 04 03 03 03 69 00 30 66 02 31 00 af 75 02 a9 b3 a6 47 4a 6e f4 0c b0 85 07 fc 3c 53 9d 29 b0 09 c2 b9 b3 f3 96 b9 99 be c5 75 9c ac 4f c3 8a 7a 24 7d 17 f7 cb 2a 71 14 57 3e 92 02 31 00 d3 57 af 94 68 e1 02 b6 51 50 0c 4a 74 97 72 37 b5 03 ff 58 80 e0 f5 eb ae 1e 81 d8 d5 84 3d 18 83 60 fe 07 cd 43 2d 27 bd f5 a4 a5 19 7f 5d 09");
            var certificateHash = kdf.TranscriptHash(certificate);



            var keyExchange = new BitString("13 e4 ff 00 ff ff 01 00 8c 93 d5 b0 6f 37 94 9e 92 c5 2e da c6 ce 3d b2 37 64 8c 2a 74 dc bb a1 5a 2c d1 11 b0 d0 d6 74 0d 29 81 8e 11 fc 16 b8 16 65 26 1d 43 d2 c9 19 05 69 ae e4 ee ed 58 b4 9b ad 01 82 0c 92 89 c1 34 ff 73 95 9f 28 a6 f4 e7 5f bb 7e 05 d3 17 0d f3 a0 4c ad 4c 1f 08 93 07 82 bb d9 e7 c6 bb a5 6f 8d e9 c5 eb 14 81 5a 35 ac 18 fc a5 e0 21 22 bf 5f 64 b9 ef 56 11 bb f3 da eb 3a 99 12 57 f5 14 00 01 00 00 00 00 00 09 00 01 01 03 00 10 00 11 00 12 00 00 00");

            var keyExchangeRsp = new BitString("13 64 f0 00 ff ff 00 00 82 64 5f 2a 3b 25 4f fe fe 58 74 41 d9 46 50 df bc e6 24 5d 20 d1 60 9a a0 6e aa 1a 92 cb ea e9 9f f8 e1 1d bc 5d 78 c7 e2 20 4f a1 63 11 a5 2d 56 c5 2f 80 21 82 2e 8b c0 70 30 91 8b 8c b5 93 63 7f a0 23 cb b7 7e cf f5 8f a3 56 07 2d 1c e2 f2 1a 16 20 c6 60 44 a3 24 fb 57 77 36 b5 6b 8c 88 ce 4c 52 d4 bb c2 f9 46 8f b6 c6 cb a6 80 bf f3 af 75 2f 22 ba ad 70 0e 45 75 d7 70 31 46 d1 f2 a1 46 84 e8 fa e9 ff 0e 3e bf f2 a3 80 f4 35 c0 fe e5 b0 c8 19 9d 3f df ed 31 b2 25 2f 51 d8 0c 00 01 00 00 00 00 00 04 00 01 00 00 12 d6 23 52 73 95 3a f9 61 ba 31 2b 25 b1 af 51 94 c4 34 f6 08 fd 9d 6a 07 d8 3b 01 11 b1 42 95 ae 28 0d a0 09 ec 7b de c8 f4 ea d9 88 0e b7 bb fc de ab d1 26 5f 94 95 b5 98 89 36 0f 95 1d 64 e7 0c 1e a5 4c 19 ee 4f 9b 5e d3 7d 81 5e 69 b0 87 40 77 6d 74 dd ab 0a 98 2e 8d 42 03 4e 36 ad bc");

            var referenceTh1 = new BitString("48 e4 47 61 2a 3e cf d6 96 2b 15 44 e4 41 44 fd f5 a4 1f db 73 71 a8 7b 40 0f 66 66 5a 37 9d 20");

            var calculatedTh1 = kdf.TranscriptHash(vca, digests, certificateHash, keyExchange, keyExchangeRsp);

            var dheSecret = new BitString("0e 31 8b cd 8f 6e 36 10 29 8e af 6b bd c2 d4 83 76 d8 04 85 52 b1 21 81 d3 d7 a8 2c c7 9e ef 3a 1f cf 6c 72 93 03 96 bb a1 9f 46 8e 68 6b fe 29");

            Assert.That(calculatedTh1.ToHex(), Is.EqualTo(referenceTh1.ToHex()), "Check that TH1 is equal");


            // Calculate handshake secrets using reference inputs
            var handshakeSecrets = kdf.GetDerivedHandshakeSecret(dheSecret, false, calculatedTh1);


            // reference expected handshake secrets
            var referenceHandshakeSecret = new BitString("de 76 9d a1 32 24 bc 1a f1 4d 0e d6 7b 57 79 60 00 fb 55 ab ae d5 bc 0e 75 1e 9f c4 da e9 b1 0d");

            var referenceRequestHandshakeSecret = new BitString("9c ef 00 fc 90 3c c0 aa 23 b4 bf 4d a7 f9 21 5f cb 68 a4 e9 23 17 8d 9d 7f 97 a4 5b 5a f2 61 d6");

            var referenceResponderHandshakeSecret = new BitString("b4 a1 cc 84 bf 30 c1 78 6d 00 17 37 d7 81 0e 72 de fa dc b3 fa 47 54 b5 e6 47 18 e2 e7 92 87 97");

            var referenceSalt1 = new BitString("54 8b 48 0f f4 32 7d 91 c3 7d 52 8d 7f 1b e0 10 75 5c a0 20 2a 6e 60 bc 7f a5 0b 15 13 ce 95 fc");


            // test that calculated handhskae secrets match reference handshake secrets
            Assert.That(handshakeSecrets.HandshakeSecret.ToHex(), Is.EqualTo(referenceHandshakeSecret.ToHex()), "Check that handshake secret is equal");
            Assert.That(handshakeSecrets.RequestDirectionHandshakeSecret.ToHex(), Is.EqualTo(referenceRequestHandshakeSecret.ToHex()), "Check that request direction handshake secret is equal");
            Assert.That(handshakeSecrets.ResponseDirectionHandshakeSecret.ToHex(), Is.EqualTo(referenceResponderHandshakeSecret.ToHex()), "Check that response direction handshake secret is equal");
            Assert.That(handshakeSecrets.Salt_1.ToHex(), Is.EqualTo(referenceSalt1.ToHex()), "Check that salt1 is equal");


            // reference finish messages


            var finish = new BitString("13 e5 00 00 b4 4d aa ca 6d d1 a5 c4 7d 31 63 a2 fb b6 80 86 e1 6b 72 8c e6 13 f6 12 3f 73 4a ca 13 10 ad 35");

            var finishRsp = new BitString("13 65 00 00 ce 23 55 01 39 f2 7d 20 c8 81 f6 9a 17 c9 6e 86 e8 6d 01 ad bc 37 1c 89 c7 6e 51 8e 3a d9 c1 c1");


            var referenceTh2 = new BitString("55 3e 8d 56 b6 62 7a ac 9e 9d ac b4 36 a2 da a4 38 5d d3 f2 9b ae eb f2 3b 14 7a b9 ea 69 ac d1");

            var calculatedTh2 = kdf.TranscriptHash(vca, digests, certificateHash, keyExchange, keyExchangeRsp, finish, finishRsp);

            Assert.That(calculatedTh2.ToHex(), Is.EqualTo(referenceTh2.ToHex()), "Check that TH2 is equal");

            // Calculate master and data secrets
            var masterSecrets = kdf.GetDerivedMasterSecret(handshakeSecrets.Salt_1, calculatedTh2);

            // reference expected master and data secrets
            var referenceMasterSecret = new BitString("de 5b db 35 0e ae b6 56 cb bb ba ec 9e ce 64 7f ef a3 f2 86 46 d3 a2 45 88 af d2 e4 27 11 e2 bb");

            var referenceRequestDataSecret = new BitString("65 76 b6 84 20 9e b0 4c 4f 0f 9b e8 a2 32 9f c8 e7 0c 9a 3d 6e 81 49 8b 49 da dc b0 34 7b 76 d5");

            var referenceResponseDataSecret = new BitString("c1 f7 92 d9 2f a9 17 de fc d9 e9 fd 3c e5 d2 0c 72 c7 ce 5a 2a aa 92 ef 8d 75 50 c2 f8 50 8d 9b");

            var referenceExportMasterSecret = new BitString("bb c5 e3 dd 20 43 4b 06 b4 d4 44 1d 30 21 12 e7 1c 0c 0b 4e 55 ad f2 be d7 86 22 eb 6f 66 85 96");

            // test that calculated master and data secrets match reference secrets
            Assert.That(masterSecrets.MasterSecret.ToHex(), Is.EqualTo(referenceMasterSecret.ToHex()), "Check that master secret is equal");
            Assert.That(masterSecrets.RequestDirectionDataSecret.ToHex(), Is.EqualTo(referenceRequestDataSecret.ToHex()), "Check that request direction data secret is equal");
            Assert.That(masterSecrets.ResponseDirectionDataSecret.ToHex(), Is.EqualTo(referenceResponseDataSecret.ToHex()), "Check that response direction data secret is equal");
            Assert.That(masterSecrets.ExportMasterSecret.ToHex(), Is.EqualTo(referenceExportMasterSecret.ToHex()), "Check that export master secret is equal");


        }



        /// <summary>
        /// Test SPDM v1.3 key derivation via PSK using test sample test vectors generated from spdm-emu using libspdm"
        /// </summary>
        [Test]
        public void TestVectorSpdmEmu_SimpleHandshakePSK_SPDMv13()
        {
            var kdf = (SpdmKdf)_spdmFactory.GetSpdmKdfInstance(SpdmModes.PSK, SpdmVersions.v13, HashFunctions.Sha2_d384); // test vector selected SHA384 during algorithm negotiation

            // reference input vectors generated from spdm-emu
            var getVersion = new BitString("10 84 00 00");
            var version = new BitString("10 04 00 00 00 04 00 10 00 11 00 12 00 13");
            var getCapabilities = new BitString("13 e1 00 00 00 00 00 00 c6 f7 82 08 00 12 00 00 00 12 00 00");
            var capabilities = new BitString("13 61 00 00 00 00 00 00 f7 fb 9a 39 00 12 00 00 00 12 00 00");
            var negotiateAlgorithms = new BitString("13 e3 04 00 30 00 01 12 90 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 02 20 1b 00 03 20 06 00 04 20 0f 00 05 20 01 00");
            var algorithms = new BitString("13 63 04 00 34 00 01 12 08 00 00 00 80 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 02 20 10 00 03 20 02 00 04 20 08 00 05 20 01 00");

            var vca = getVersion.ConcatenateBits(version).ConcatenateBits(getCapabilities).ConcatenateBits(capabilities).ConcatenateBits(negotiateAlgorithms).ConcatenateBits(algorithms);

            var pskKeyExchange = new BitString("13 e6 ff 01 ff ff 0c 00 40 00 14 00 54 65 73 74 50 73 6b 48 69 6e 74 00 51 87 97 f9 b3 31 e9 3a 0a 9c 26 89 68 10 fc 1a e5 e0 0f 36 1c 34 17 92 e2 3f 99 94 f8 88 06 85 7d e5 58 d4 c7 fc 2a 13 52 92 2c 21 7e fd 05 c4 48 8f 12 f1 08 98 eb 45 9f 1e f6 b4 2f eb af ec 01 00 00 00 00 00 09 00 01 01 03 00 10 00 11 00 12 00 00 00");

            // TH1 includes all of pskKeyExchangeRsp except "ResponderVerifyData"
            
            
            var pskKeyExchangeRspPartial = new BitString("13 66 f0 00 ff ff 00 00 40 00 0c 00 fd ab e1 6b 17 de df 3e 76 2a 76 f1 c5 d9 ee 01 5e 9f 50 b7 5b d7 5e a1 8d b5 d3 98 b8 80 25 8b 46 fc c8 1a e5 3a 9a a3 5f 49 f4 c2 4f 4e d5 a2 1f e1 bc b3 09 4f e8 d9 33 50 bb a7 e4 c9 4c ec d3 c4 c7 14 03 1a f6 65 56 37 41 70 42 53 ca 1d cd d1 77 60 e6 ce e3 ba 14 e6 99 3b c5 34 6b dc 4d fd 2c b4 6a e1 a6 46 6a 53 65 49 ba 7f a2 78 01 00 00 00 00 00 04 00 01 00 00 12");
            // TH2 includes all of pskKeyExchangeRsp including ResponderVerifyData
            var pskKeyExchangeRsp_responderVerifyData = new BitString("ec 65 3f b8 a5 f7 24 13 54 68 ea 7d b0 da b7 35 36 de 68 39 a4 c5 e2 b3 38 7e 44 01 c0 f7 fc 0c 70 6f e1 3d 95 68 92 ba 6d 11 13 98 b7 94 c6 fc");
            var referenceTh1 = new BitString("39 66 aa 3b 7a 4e 4a 76 1f 47 08 3e 03 a2 f3 2f a7 89 07 b3 eb 50 c9 9c 23 b5 3e a7 c8 cd a0 7c 9d 0a 8a b6 6b d4 26 ba d7 e4 80 d8 3a 2d 6b f2");

            var calculatedTh1 = kdf.TranscriptHash(vca, pskKeyExchange, pskKeyExchangeRspPartial);

            var psk = new BitString("54 65 73 74 50 73 6b 44 61 74 61 00");

            Assert.That(calculatedTh1.ToHex(), Is.EqualTo(referenceTh1.ToHex()), "Check that TH1 is equal");


            // Calculate handshake secrets using reference inputs
            var handshakeSecrets = kdf.GetDerivedHandshakeSecret(psk, true, calculatedTh1);


            // reference expected handshake secrets
            var referenceHandshakeSecret = new BitString("83 59 7e fe d2 28 9c 01 c4 e6 26 77 d1 66 5e 26 9a 22 0a ee 92 47 b1 5b 2c a7 2b da 07 a3 eb fc 77 06 00 48 7c 33 58 22 40 34 f0 2d 62 7c a9 7e");

            var referenceRequestHandshakeSecret = new BitString("8e 87 c4 b3 1a 3d 76 9e 62 54 bf 0f e8 88 8c 75 5e 4a b7 bf 62 7d 0f 2a 6c 52 7c 7b 7c 74 d2 b2 99 76 7b 34 58 8e 3a 03 36 9c 60 59 18 84 51 00");

            var referenceResponderHandshakeSecret = new BitString("5c 6d 94 ac d0 6e 4b a0 be 9e cd e0 d6 7d e4 b5 9a e6 b8 98 6d a3 35 3d 68 50 4e 20 7b de dd c0 6d 4a 1f e9 0d 40 ac 1b ab b9 2c 64 56 47 61 7c");

            var referenceSalt1 = new BitString("e1 f5 98 82 52 0c 78 7c a3 72 8b 9f be d4 d9 d8 00 40 bf 90 e3 af 3c 29 fd ed 72 05 9e 86 6b 46 3d 22 55 a2 37 a7 fd da c5 4a 52 b3 06 29 7d 24");


            // test that calculated handhskae secrets match reference handshake secrets
            Assert.That(handshakeSecrets.HandshakeSecret.ToHex(), Is.EqualTo(referenceHandshakeSecret.ToHex()), "Check that handshake secret is equal");
            Assert.That(handshakeSecrets.RequestDirectionHandshakeSecret.ToHex(), Is.EqualTo(referenceRequestHandshakeSecret.ToHex()), "Check that request direction handshake secret is equal");
            Assert.That(handshakeSecrets.ResponseDirectionHandshakeSecret.ToHex(), Is.EqualTo(referenceResponderHandshakeSecret.ToHex()), "Check that response direction handshake secret is equal");
            Assert.That(handshakeSecrets.Salt_1.ToHex(), Is.EqualTo(referenceSalt1.ToHex()), "Check that salt1 is equal");


            // reference finish messages


            var pskFinish = new BitString("13 e7 00 00 0c 85 c5 1b 56 9d af 4a cf e0 b4 5e f4 b6 c1 ef 26 01 b3 2c 95 44 f9 a5 30 ba 19 74 b8 c4 3f d3 cc 36 f4 98 f0 85 13 da d0 01 b8 7f 1c 34 16 61");

            var pskFinishRsp = new BitString("13 67 00 00 ");


            var referenceTh2 = new BitString("5f 91 5d 03 43 ea 05 6d d8 7e 37 53 a5 c4 64 8b ff e3 4a fa f3 2a 4d 25 b2 97 2a 35 92 93 aa 26 b2 62 3d 4f 0d 32 bb 99 7f 76 5d 20 07 fa cf 0e");

            var calculatedTh2 = kdf.TranscriptHash(vca, pskKeyExchange, pskKeyExchangeRspPartial.ConcatenateBits(pskKeyExchangeRsp_responderVerifyData), pskFinish, pskFinishRsp);

            Assert.That(calculatedTh2.ToHex(), Is.EqualTo(referenceTh2.ToHex()), "Check that TH2 is equal");

            // Calculate master and data secrets
            var masterSecrets = kdf.GetDerivedMasterSecret(handshakeSecrets.Salt_1, calculatedTh2);

            // reference expected master and data secrets
            var referenceMasterSecret = new BitString("fa a1 36 88 d1 b9 10 e1 c3 b1 b2 2f f4 27 f1 dd 02 1a 8b 86 d4 05 db 47 73 78 74 51 38 df b8 67 5e 22 ba 79 b3 8e 49 f7 fb af 3e 1e 3b 01 30 40");

            var referenceRequestDataSecret = new BitString("16 16 68 c4 35 7d 3d dc d2 71 8b 5a 79 20 e0 4b dd 54 17 f1 0c e4 5b 28 25 dd 52 6e 64 8a 8c 3e 8b 2d 5e cb 53 20 7a 7b 4f aa a1 ad 49 74 25 4b");

            var referenceResponseDataSecret = new BitString("5c a5 8f 53 0c 48 8b 83 15 7f d3 e5 ca 59 2d 68 03 d8 96 4c f6 35 2e 49 0a 65 31 23 55 37 ae 7f 9b 13 86 d1 46 7a 9d 03 76 5c f1 42 80 ad eb 0e");

            var referenceExportMasterSecret = new BitString("dc 3d 74 f4 a1 ec 8f 2d 04 7f 05 09 1b ac 75 a5 83 51 f4 60 2f 64 c8 f3 a1 2e 5e 43 cb 78 1a 55 84 d9 65 07 84 d4 1b 5b 9a 1b 30 35 fc 14 5d 60");

            // test that calculated master and data secrets match reference secrets
            Assert.That(masterSecrets.MasterSecret.ToHex(), Is.EqualTo(referenceMasterSecret.ToHex()), "Check that master secret is equal");
            Assert.That(masterSecrets.RequestDirectionDataSecret.ToHex(), Is.EqualTo(referenceRequestDataSecret.ToHex()), "Check that request direction data secret is equal");
            Assert.That(masterSecrets.ResponseDirectionDataSecret.ToHex(), Is.EqualTo(referenceResponseDataSecret.ToHex()), "Check that response direction data secret is equal");
            Assert.That(masterSecrets.ExportMasterSecret.ToHex(), Is.EqualTo(referenceExportMasterSecret.ToHex()), "Check that export master secret is equal");


        }

        /// <summary>
        /// Test SPDM v1.2 key derivation via PSK using test sample test vectors generated from spdm-emu using libspdm"
        /// </summary>
        [Test]
        public void TestVectorSpdmEmu_SimpleHandshakePSK_SPDMv12()
        {
            var kdf = (SpdmKdf)_spdmFactory.GetSpdmKdfInstance(SpdmModes.PSK, SpdmVersions.v12, HashFunctions.Sha2_d384); // test vector selected SHA384 during algorithm negotiation

            // reference input vectors generated from spdm-emu
            var getVersion = new BitString("10 84 00 00");
            var version = new BitString("10 04 00 00 00 01 00 12");
            var getCapabilities = new BitString("12 e1 00 00 00 00 00 00 c6 f7 02 00 00 12 00 00 00 12 00 00");
            var capabilities = new BitString("12 61 00 00 00 00 00 00 f7 fb 1a 00 00 12 00 00 00 12 00 00");


            var negotiateAlgorithms = new BitString("12 e3 04 00 30 00 01 02 90 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 20 1b 00 03 20 06 00 04 20 0f 00 05 20 01 00");


            var algorithms = new BitString("12 63 04 00 34 00 01 02 08 00 00 00 80 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 20 10 00 03 20 02 00 04 20 08 00 05 20 01 00");

            var vca = getVersion.ConcatenateBits(version).ConcatenateBits(getCapabilities).ConcatenateBits(capabilities).ConcatenateBits(negotiateAlgorithms).ConcatenateBits(algorithms);



            var pskKeyExchange = new BitString("12 e6 ff 01 ff ff 0c 00 40 00 14 00 54 65 73 74 50 73 6b 48 69 6e 74 00 30 cf 4c 55 a8 84 6d cf 26 80 ca 43 b9 fe 39 0d e5 dd 65 9e 6b 7e a3 a1 50 19 1d 7c ad 90 b4 db 8f bb a3 17 7f e1 9e 1e ac 40 29 6a bc eb f0 f5 80 f4 11 9b a4 88 fb 53 46 34 55 5d c7 12 64 a8 01 00 00 00 00 00 09 00 01 01 03 00 10 00 11 00 12 00 00 00");

            // TH1 includes all of pskKeyExchangeRsp except "ResponderVerifyData"


            var pskKeyExchangeRspPartial = new BitString("12 66 f0 00 ff ff 00 00 40 00 0c 00 fd ab e1 6b 17 de df 3e 76 2a 76 f1 c5 d9 ee 01 5e 9f 50 b7 5b d7 5e a1 8d b5 d3 98 b8 80 25 8b 46 fc c8 1a e5 3a 9a a3 5f 49 f4 c2 4f 4e d5 a2 de 4f 00 55 9f 53 64 b3 5e 6f 36 ac c7 60 a4 56 44 31 4d 1c ae cb dd e5 b2 b5 fb 27 66 5f 70 5d 0a b7 e7 bc cd 6f 51 00 ee 23 e5 38 2d 60 ec bd b1 66 70 e3 37 bc 54 a9 97 9c 61 bf 2e fe df 13 01 00 00 00 00 00 04 00 01 00 00 12");
            // TH2 includes all of pskKeyExchangeRsp including ResponderVerifyData
            var pskKeyExchangeRsp_responderVerifyData = new BitString("ad 3f f7 e7 04 24 26 d1 d1 9a c1 83 ab 7d 64 1e 9f e3 5e fc 17 d4 a4 62 41 fd 2f c0 04 fe 01 35 dd 74 ca aa bb ba 9f 2f 80 c8 4e 06 34 df 1d 38");

            


            var referenceTh1 = new BitString("77 09 d8 67 dc bf f9 52 88 95 91 87 ed ea d8 6f 1b 79 01 1d 4e f6 c8 bf 22 2a 91 b2 4d 1e 9e e4 4c 6f 2a 29 a0 a0 62 57 a2 41 63 c8 8c 29 45 4b");

            var calculatedTh1 = kdf.TranscriptHash(vca, pskKeyExchange, pskKeyExchangeRspPartial);

            var psk = new BitString("54 65 73 74 50 73 6b 44 61 74 61 00");

            Assert.That(calculatedTh1.ToHex(), Is.EqualTo(referenceTh1.ToHex()), "Check that TH1 is equal");


            // Calculate handshake secrets using reference inputs
            var handshakeSecrets = kdf.GetDerivedHandshakeSecret(psk, true, calculatedTh1);


            // reference expected handshake secrets
            var referenceHandshakeSecret = new BitString("91 fb da 7e 67 88 02 25 87 66 0d db 80 7f 5d d8 2f 02 33 77 f8 88 af e7 bd 28 08 34 8d c0 02 92 e0 09 23 23 34 f6 01 7a 59 a6 56 7b 0c 86 0e 07");

            var referenceRequestHandshakeSecret = new BitString("22 b7 65 2f 7e 48 18 ff a7 d2 85 15 c1 74 7b 57 53 27 23 24 fc bc a9 a9 51 dc 76 9b 06 55 66 98 5d e3 2e 2c c1 47 06 8e 47 67 7e 2d 38 57 a3 25");

            var referenceResponderHandshakeSecret = new BitString("f8 c6 8e a6 f5 42 65 24 59 a9 21 3b ee 5f 88 10 7b 44 25 b4 b2 17 d5 8c ba 59 96 10 14 3b 53 1a 22 10 5b 3d f8 6e b2 50 90 0f 53 36 9a 35 bd 95");

            var referenceSalt1 = new BitString("0b 01 43 e7 46 f2 a0 ab e5 84 8d c2 dc 15 a9 4d b8 44 1e 88 da 15 9c 1c 84 30 86 33 f9 fb fc da c3 1b d2 ab 74 b1 7a ed c2 44 d2 64 dc 50 e7 f6");


            // test that calculated handhskae secrets match reference handshake secrets
            Assert.That(handshakeSecrets.HandshakeSecret.ToHex(), Is.EqualTo(referenceHandshakeSecret.ToHex()), "Check that handshake secret is equal");
            Assert.That(handshakeSecrets.RequestDirectionHandshakeSecret.ToHex(), Is.EqualTo(referenceRequestHandshakeSecret.ToHex()), "Check that request direction handshake secret is equal");
            Assert.That(handshakeSecrets.ResponseDirectionHandshakeSecret.ToHex(), Is.EqualTo(referenceResponderHandshakeSecret.ToHex()), "Check that response direction handshake secret is equal");
            Assert.That(handshakeSecrets.Salt_1.ToHex(), Is.EqualTo(referenceSalt1.ToHex()), "Check that salt1 is equal");


            // reference finish messages


            var pskFinish = new BitString("12 e7 00 00 e0 54 2a df 30 79 a7 4a 9e 54 c5 79 f9 9f 38 b1 c7 e8 ad 3a 37 ea d7 97 bb a6 b7 de f1 1e 2f 02 4f 22 b3 b6 e5 b3 55 e0 e9 79 59 1d 79 ac ca 02");

            var pskFinishRsp = new BitString("12 67 00 00");


            var referenceTh2 = new BitString("ca 03 4c 39 3e 39 fd 96 c8 40 21 cc d4 71 23 28 97 9f 7c dd 14 a0 6a 3a 19 19 2d 41 40 98 fd 6c 54 ab 42 d9 a1 0a 13 83 b4 68 c2 94 87 52 4d 0c");

            var calculatedTh2 = kdf.TranscriptHash(vca, pskKeyExchange, pskKeyExchangeRspPartial.ConcatenateBits(pskKeyExchangeRsp_responderVerifyData), pskFinish, pskFinishRsp);

            Assert.That(calculatedTh2.ToHex(), Is.EqualTo(referenceTh2.ToHex()), "Check that TH2 is equal");

            // Calculate master and data secrets
            var masterSecrets = kdf.GetDerivedMasterSecret(handshakeSecrets.Salt_1, calculatedTh2);

            // reference expected master and data secrets
            var referenceMasterSecret = new BitString("ba d2 23 45 d4 8f c2 b7 42 21 2c 73 71 85 f3 6a d6 a1 c4 1f 33 09 06 04 7e 59 43 7b 18 4a 71 59 0a 58 11 fc f8 48 a0 b0 e1 24 e0 5b d2 fd 30 6f");

            var referenceRequestDataSecret = new BitString("72 5a 09 a7 05 58 8a ba 4c 83 ec 07 4a e9 92 45 2c a9 ff 5f c8 f4 6f ce 26 53 79 a7 00 94 6b e3 75 a8 c0 0a dd a3 86 c3 ab 15 cf 8f a9 04 19 2f");

            var referenceResponseDataSecret = new BitString("83 0e 10 c7 a4 62 75 b9 31 97 5a fa 22 d2 c0 43 2e ba 40 78 72 e7 db ab ca d8 14 cb 04 bd 7e 7f 31 32 43 4a 32 b8 59 dc e0 c8 d7 a0 f4 09 a4 ac");

            var referenceExportMasterSecret = new BitString("1a df b9 d6 ea b5 05 11 db 06 e5 d6 dd bb 6f 6b 4f ba 94 18 b2 63 8b 98 c0 6a 19 3a 79 03 d7 1d 13 d4 69 de b1 be 46 74 b5 ab 39 ae 80 22 f8 ea");

            // test that calculated master and data secrets match reference secrets
            Assert.That(masterSecrets.MasterSecret.ToHex(), Is.EqualTo(referenceMasterSecret.ToHex()), "Check that master secret is equal");
            Assert.That(masterSecrets.RequestDirectionDataSecret.ToHex(), Is.EqualTo(referenceRequestDataSecret.ToHex()), "Check that request direction data secret is equal");
            Assert.That(masterSecrets.ResponseDirectionDataSecret.ToHex(), Is.EqualTo(referenceResponseDataSecret.ToHex()), "Check that response direction data secret is equal");
            Assert.That(masterSecrets.ExportMasterSecret.ToHex(), Is.EqualTo(referenceExportMasterSecret.ToHex()), "Check that export master secret is equal");


        }



        [Test]
        public void TestVectorIetfDraft_TranscriptHashEmptyPayload()
        {
            var spdmVersion = SpdmVersions.v13;
            var shaFactory = new NativeShaFactory();
            var sha = shaFactory.GetShaInstance(new HashFunction(ModeValues.SHA2, DigestSizes.d256));
            var spdm = (SpdmKdf)_spdmFactory.GetSpdmKdfInstance(SpdmModes.ECDHEOrKEM, spdmVersion, HashFunctions.Sha2_d256);

            var emptyPayload = sha.HashMessage(BitString.Empty());

            var expectedHash =
                new BitString("e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55");

            Assert.That(emptyPayload.Digest.ToHex(), Is.EqualTo(expectedHash.ToHex()), nameof(emptyPayload));
            Assert.That(spdm.TranscriptHash(BitString.Empty()).ToHex(), Is.EqualTo(expectedHash.ToHex()), "Transcript hash");
        }

        [Test]
        public void TestVectorIetfDraft_TranscriptHashNonEmptyPayloadOneContribution()
        {
            var spdmVersion = SpdmVersions.v13;
            var shaFactory = new NativeShaFactory();
            var sha = shaFactory.GetShaInstance(new HashFunction(ModeValues.SHA2, DigestSizes.d256));
            var spdm = (SpdmKdf)_spdmFactory.GetSpdmKdfInstance(SpdmModes.ECDHEOrKEM, spdmVersion, HashFunctions.Sha2_d256);

            var clientHello = new BitString("01 00 01 fc 03 03 eb ef 0b 92 25 8b ec d1 07 3d cf f0 bb a7 da ad c7 b4 e8 14 df dd 1b 77 4b 0d 43 53 95 2b c4 2b 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00 26 00 24 00 1d 00 20 a2 e0 04 93 2f 3c d0 b3 c6 a2 9a de 11 8b 46 7c 69 55 a6 c3 6a 1d 44 27 38 60 59 b2 26 f5 0c 0f 00 2a 00 00 00 2b 00 03 02 7f 1c 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 15 00 5d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 0f 63 7d a7 09 04 33 70 d0 60 00 06 00 00 00 00 2d fe b5 7a a8 7b 9c f1 76 0a 8a b4 91 d4 fb 0f 00 70 3d 7a 42 b6 a9 87 ef d2 4a fb bd 2b c6 06 9d c9 03 d4 c2 d3 f0 4f dd 3d 8e 95 97 0a 7b 78 aa 2c e8 28 75 72 4f 8a 82 75 d1 65 e7 7b e4 7d 59 0e aa ab fa 5f 4c 2d f0 46 71 a0 44 d8 4c f5 cc da c5 88 7d 6b e7 fe 2e 52 80 d7 a5 0f 23 fc 9c d4 a5 43 01 9e 41 94 63 c4 ee 29 8f d3 2c 01 93 34 b7 ab bb 78 d4 f2 a1 cf 4e 0f e1 60 aa 72 86 19 3f da 28 8c 97 d5 ba 39 75 5f 25 b7 a4 a8 f0 63 01 24 88 3d 2c 66 78 78 75 d6 7a 0f 6e b0 ba 71 f4 34 71 a5 00 21 20 b1 da ce 1d 97 d7 ff bf 46 1d f9 4d ec 70 f1 30 08 f9 13 4b 9c c0 40 88 d9 6d 93 cf 73 18 5b d8");

            var expectedHash = new BitString("8a ec fe eb b4 23 6e fd 8b 78 bb 3f f1 c7 af e0 87 2b fb b2 60 0f 04 69 ed 58 6f 23 39 7a e0 2d");

            Assert.That(
                sha.HashMessage(clientHello).Digest.ToHex(), Is.EqualTo(expectedHash.ToHex()),
                "concatenate no lengths");
            Assert.That(spdm.TranscriptHash(clientHello).ToHex(), Is.EqualTo(expectedHash.ToHex()), "Transcript hash");
        }

        [Test]
        public void TestVectorIetfDraft_TranscriptHashNonEmptyPayloadTwoContribution()
        {
            var shaFactory = new NativeShaFactory();
            var sha = shaFactory.GetShaInstance(new HashFunction(ModeValues.SHA2, DigestSizes.d256));
            var tls = (SpdmKdf)_spdmFactory.GetSpdmKdfInstance(SpdmModes.ECDHEOrKEM, SpdmVersions.v13, HashFunctions.Sha2_d256);

            var clientHello = new BitString("01 00 00 b6 03 03 82 97 3b d3 3b b4 81 f5 37 de c6 5a cd 48 5b d4 bd aa 20 f7 d2 2f 68 0c 89 2f 68 45 06 51 a5 0e 00 00 06 13 01 13 03 13 02 01 00 00 87 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00 26 00 24 00 1d 00 20 79 fd 6e fb c1 92 04 40 aa 32 5c dc ea 3f 3c b7 07 8f ea 03 13 fa 76 6a c3 76 1e dc 62 ad 2c 31 00 2b 00 03 02 7f 1c 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01");
            var serverHello = new BitString("02 00 00 56 03 03 e1 6b 86 5e 76 5e 84 ba 47 b4 2d f2 62 e3 8e 2d e6 1e 95 e3 75 3b ad fd 98 76 5c 62 98 4f 28 d3 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c3 ec 4f 42 40 70 ce 83 c7 91 fa 32 8f e9 ae 00 96 ab fc cc 15 b9 aa ec eb f6 0b f4 8f 0b 0f 2e 00 2b 00 02 7f 1c");

            var expectedHash = new BitString("57 65 19 76 4b f9 ac e3 84 32 c8 6d 9e 0f 72 f2 ef 6b a3 7c 9f 76 30 6e fc bb e7 78 56 ad b3 41");

            Assert.That(
                sha.HashMessage(clientHello.ConcatenateBits(serverHello)).Digest.ToHex(), Is.EqualTo(expectedHash.ToHex()),
                "concatenate no lengths");
            Assert.That(tls.TranscriptHash(clientHello, serverHello).ToHex(), Is.EqualTo(expectedHash.ToHex()), "Transcript hash");
        }

        //[Test]
        //public void WhenGivenDeployedRefactoredVectorWithNewTranscriptHash_ShouldPassThroughCrypto()
        //{
        //    var tls = _tlsFactory.GetInstance(HashFunctions.Sha2_d256);

        //    var clientHello = new BitString("43E50D9385348E472D7437069F11F4BC9A9E91419F4D181B684D7FDCCB283C6F9B77FDEB");
        //    var serverHello = new BitString("28590A320ED4C84B4D83FAC83794D7EBF7C2575151416A3D0F5FD69E557FC6F4BB801945");
        //    var clientFinished = new BitString("7F89C4A133CCBC88862F2AB141B2ACEFC7A3EBB245C298946900A50B635F63D62F83CCB1");
        //    var serverFinished = new BitString("6F41191133DC5101D60A3243F9F348856E57ED4B3B33E24DDDEF64D83000BB74F6A5E210");

        //    var psk = new BitString("7EF1F0E2830A8B277B3EEBD55C911CF8EFB4BC40D18C8575161252B99CB2458BE7504EB6");
        //    var dhe = new BitString("0000000000000000000000000000000000000000000000000000000000000000");

        //    var expectedResumption = new BitString("42D6655172F7A28942566EF46574B51CB7DC9E8772E24A4C0695663F7A62E5C3");

        //    var result = tls.GetFullKdf(
        //        false, psk, dhe,
        //        clientHello, serverHello, serverFinished, clientFinished);

        //    Assert.That(result.MasterSecretResult.ResumptionMasterSecret.ToHex(), Is.EqualTo(expectedResumption.ToHex()));
        //}

        //[Test]
        //public void WhenIntegrationTest_ShouldPassThroughCrypto()
        //{
        //    var tls = _tlsFactory.GetInstance(HashFunctions.Sha2_d256);

        //    var clientHello = new BitString("80ABF9173154BB77CCB228E6F1C9EBA5190939B97BF376C3B1D25110FEE69BD430");
        //    var serverHello = new BitString("CBCA99A1FC54861AE8AC4A7E657480B5E719ADE631188436E2AB6CE9AAFCBF3ABD");
        //    var clientFinished = new BitString("12CF6F665ADEF8668E7E5694523758C146F47F4E089B6E46F5C346DA9F2E28BF4D");
        //    var serverFinished = new BitString("B99C40AE1862901313F03F1B367862493B0E919A99A3AF0F1E7FBC6E0C797EBD72");

        //    var psk = new BitString("702F6026CEF0526761258F48E8B4FC7CE79198936B2DB00B1FE621A723D9F14170");
        //    var dhe = new BitString("0000000000000000000000000000000000000000000000000000000000000000");

        //    var expectedResumption = new BitString("02CD04B88A20035376B33C2E7BD9F2E4DDE551A645B05DD90B6AA932BBB429DB");

        //    var result = tls.GetFullKdf(
        //        false, psk, dhe,
        //        clientHello, serverHello, serverFinished, clientFinished);

        //    Assert.That(result.MasterSecretResult.ResumptionMasterSecret.ToHex(), Is.EqualTo(expectedResumption.ToHex()));
        //}

        // [Test]
        // public void TestVectorIetfDraft_TranscriptHashHelloRetry()
        // {
        // 	var shaFactory = new ShaFactory();
        // 	var sha = shaFactory.GetShaInstance(new HashFunction(ModeValues.SHA2, DigestSizes.d256));
        // 	var tls = (TlsKdfv13)_tlsFactory.GetInstance(HashFunctions.Sha2_d256);
        // 	
        // 	var clientHello = new BitString("01 00 01 fc 03 03 fd a5 c0 5a 01 de 6f 64 0f 13 2a 1a a8 b7 a0 5a 9f 17 91 ca 88 fd f1 ac 8e 07 5e 50 cf 69 0c c9 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 08 00 06 00 1d 00 17 00 18 00 33 00 47 00 45 00 17 00 41 04 9c 86 50 ec 41 c5 a8 df da c7 8b 1f 35 65 42 16 cf cf 8c 2d b5 09 31 58 59 3b 33 22 1a 60 4b f7 df f9 a4 7d cf 13 ee cb 29 be 5c 24 73 21 48 2f 44 51 57 b7 33 1e e4 af 71 7b 59 7e 07 6d 56 e9 00 2b 00 03 02 7f 1c 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2c 00 74 00 72 be 27 61 a6 66 36 1c 81 90 47 cf 51 00 00 00 00 5a 99 8e 4c c3 d8 dd 02 5b bb e1 0d a6 f2 b2 d1 00 30 b0 3a 58 2f 9c c5 81 d1 0f 62 6c f0 e3 b9 3d 14 d4 65 f9 48 83 5a 2a b5 31 3a 23 a1 9a eb a3 67 1e 7a 0d 41 0e 17 4f d0 04 f6 53 f1 08 25 17 3d 1a 90 37 cd ea b4 86 df 4e 79 c6 87 f9 d9 b1 b9 e2 ae 81 1e 0b 97 4e 8f 82 7b b1 66 a8 2d f7 a1 00 2d 00 02 01 01 00 15 00 b5 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        // 	var serverHello = new BitString("02 00 00 ac 03 03 cf 21 ad 74 e5 9a 61 11 be 1d 8c 02 1e 65 b8 91 c2 a2 11 16 7a bb 8c 5e 07 9e 09 e2 c8 a8 33 9c 00 13 01 00 00 84 00 33 00 02 00 17 00 2c 00 74 00 72 be 27 61 a6 66 36 1c 81 90 47 cf 51 00 00 00 00 5a 99 8e 4c c3 d8 dd 02 5b bb e1 0d a6 f2 b2 d1 00 30 b0 3a 58 2f 9c c5 81 d1 0f 62 6c f0 e3 b9 3d 14 d4 65 f9 48 83 5a 2a b5 31 3a 23 a1 9a eb a3 67 1e 7a 0d 41 0e 17 4f d0 04 f6 53 f1 08 25 17 3d 1a 90 37 cd ea b4 86 df 4e 79 c6 87 f9 d9 b1 b9 e2 ae 81 1e 0b 97 4e 8f 82 7b b1 66 a8 2d f7 a1 00 2b 00 02 7f 1c");
        //
        // 	var early = tls.GetDerivedEarlySecret(false, new BitString(32 * BitString.BITSINBYTE), clientHello);
        // 	
        // 	Assert.AreEqual(new BitString("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba").ToHex(), early.DerivedEarlySecret.ToHex(), "Derived early sercret");
        //
        // 	var handshake = tls.GetDerivedHandshakeSecret(
        // 		new BitString("fe b0 20 4b f7 6c ce 95 68 ae ef fa 0b 10 ef c7 64 06 5c 03 48 cc f4 f2 f8 97 22 f2 f5 5c df a8"),
        // 		early.DerivedEarlySecret,
        // 		clientHello,
        // 		serverHello);
        // 	
        // 	Assert.AreEqual(
        // 		new BitString("91 35 3f 07 99 0d 6d 5a e0 43 f2 dd 4b 36 45 a8 2d d7 a4 8b 91 73 36 5c af 7e 09 80 ba f4 9d 15").ToHex(), 
        // 		handshake.HandshakeSecret.ToHex(), 
        // 		"Handshake secret");
        // 	Assert.AreEqual(
        // 		new BitString("66 65 be 10 30 f9 05 87 74 35 d5 6b 4a 9b d8 de 7f 4e 37 1c ef 29 5b ac 39 7b 98 d7 35 f5 16 54").ToHex(), 
        // 		handshake.ClientHandshakeTrafficSecret.ToHex(), 
        // 		"tls13 c hs traffic");
        // }
    }
}
