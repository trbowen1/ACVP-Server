﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Common.ExtensionMethods;
using NIST.CVP.ACVTS.Libraries.Common.Helpers;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.KAS.KDA.KdfHkdf;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.KDA.Shared;
using NIST.CVP.ACVTS.Libraries.Generation.KDA.Shared.Hkdf;
using NIST.CVP.ACVTS.Libraries.Math.Domain;

namespace NIST.CVP.ACVTS.Libraries.Generation.KDA.Sp800_56Cr2.Hkdf
{
    public class TestGroupGenerator : ITestGroupGeneratorAsync<Parameters, TestGroup, TestCase>
    {
        private readonly string[] _testTypes = { "AFT", "VAL" };

        public Task<List<TestGroup>> BuildTestGroupsAsync(Parameters parameters)
        {
            var groups = new List<TestGroup>();
            var algoMode =
                AlgoModeHelpers.GetAlgoModeFromAlgoAndMode(parameters.Algorithm, parameters.Mode, parameters.Revision);
            bool usesHybridSS = false;
            // if a saltLens property was provided, those values need to be used
            bool useIutProvidedSaltLens = (parameters.SaltLens != null) ? true : false;
            List<int> zLengths;
            List<int> tLengths = new List<int>(){};
            int zLength;
            int tLength;
            var random = new Random();
            
            usesHybridSS = parameters.UsesHybridSharedSecret.Value;
           
            foreach (var testType in _testTypes)
            {
                foreach (var fixedInfoEncoding in parameters.Encoding)
                {
                    foreach (var hmacAlg in parameters.HmacAlg)
                    {
                        var hashInputBlockSize = ParameterValidator.GetHashInputBlockSize(hmacAlg);
                        
                        foreach (var saltMethod in parameters.MacSaltMethods)
                        {
                            zLengths = GetSSLens(parameters.Z.GetDeepCopy());
                            int numSSLens = zLengths.Count;
                            
                            if (usesHybridSS)
                            {
                                tLengths = GetSSLens(parameters.AuxSharedSecretLen.GetDeepCopy());
                                if (tLengths.Count > numSSLens)
                                {
                                    numSSLens = tLengths.Count;
                                }
                            }

                            List<int> saltLens = new List<int>();;
                            // if the IUT provided them, pull back some valid saltLens to use
                            if (useIutProvidedSaltLens)
                            {
                                saltLens.AddRange(parameters.SaltLens.GetDeepCopy()
                                    .GetRandomValues(i => i <= hashInputBlockSize, numSSLens));
                            }

                            for (int i = 0; i < numSSLens; i++)
                            {
                                // tLength should default to 0
                                tLength = 0; 
                                // If we're not using HybridSS, we don't need to factor in/worry about t
                                if (!usesHybridSS)
                                {
                                    zLength = zLengths[i];
                                } 
                                else // if usesHybridSS is true, then we could be in a scenario where the  
                                { // number of zLengths is less than the number of tLengths and we'll need to reuse a
                                  // zLength 1 or more times or vice versus
                                    zLength = i < zLengths.Count ? zLengths[i] : zLengths[zLengths.Count-1]; 
                                    tLength = i < tLengths.Count ? tLengths[i] : tLengths[tLengths.Count-1];
                                }

                                // if the IUT supplied saltLens, choose one to use. Otherwise, default to the hash input block size
                                var saltLen = (useIutProvidedSaltLens)
                                    ? saltLens[random.Next(saltLens.Count)]
                                    : hashInputBlockSize;
                                
                                groups.Add(new TestGroup()
                                {
                                    KdfConfiguration = new HkdfConfiguration()
                                    {
                                        L = parameters.L,
                                        HmacAlg = hmacAlg,
                                        SaltMethod = saltMethod,
                                        SaltLen = saltLen,
                                        FixedInfoEncoding = fixedInfoEncoding,
                                        FixedInfoPattern = parameters.FixedInfoPattern
                                    },
                                    TestType = testType,
                                    ZLength = zLength,
                                    UsesHybridSharedSecret = parameters.UsesHybridSharedSecret,
                                    AuxSharedSecretLen = tLength,
                                    MultiExpansion = false,
                                    KdaExpectationProvider = testType.Equals("VAL") ? new KdaExpectationProvider(parameters.IsSample) : null
                                });

                                // Create groups for multi expansion using more or less the same options
                                if (parameters.PerformMultiExpansionTests)
                                {
                                    // grab a different random saltLen than what was used in the previous testGroup for better testing
                                    saltLen = (useIutProvidedSaltLens)
                                        ? saltLens[random.Next(saltLens.Count)]
                                        : hashInputBlockSize;
                                    groups.Add(new TestGroup()
                                    {
                                        KdfMultiExpansionConfiguration = new HkdfMultiExpansionConfiguration()
                                        {
                                            HmacAlg = hmacAlg,
                                            SaltMethod = saltMethod,
                                            SaltLen = saltLen,
                                            L = parameters.L
                                        },
                                        TestType = testType,
                                        ZLength = zLength,
                                        UsesHybridSharedSecret = parameters.UsesHybridSharedSecret,
                                        AuxSharedSecretLen = tLength,
                                        MultiExpansion = true,
                                        KdaExpectationProvider = testType.Equals("VAL") ? new KdaExpectationProvider(parameters.IsSample) : null
                                    });
                                }
                            }
                        }
                    }
                }
            }

            return Task.FromResult(groups);
        }
        
        private List<int> GetSSLens(MathDomain sS)
        {
            var values = new List<int>();

            // Only one shared secret length is supported. Only need one test group
            if (sS.GetDomainMinMax().Minimum == sS.GetDomainMinMax().Maximum)
            {
                values.Add(sS.GetDomainMinMax().Minimum);
            }
            else
            {
                values.AddRange(sS.GetRandomValues(i => i < 1024, 10));
                values.AddRange(sS.GetRandomValues(i => i < 4096, 5));
                values.AddRange(sS.GetRandomValues(i => i < 8192, 2));
                values.AddRange(sS.GetRandomValues(1));

                values = values.Shuffle().Take(3).ToList();
            
                values.Add(sS.GetDomainMinMax().Minimum);
                values.Add(sS.GetDomainMinMax().Maximum);                
            }
            
            return values.Shuffle();
        }
    }
}
