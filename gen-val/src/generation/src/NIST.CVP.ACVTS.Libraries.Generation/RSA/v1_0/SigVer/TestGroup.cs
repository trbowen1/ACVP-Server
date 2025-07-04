﻿using System;
using System.Collections.Generic;
using System.Numerics;
using Newtonsoft.Json;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.RSA.Enums;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Asymmetric.RSA.Keys;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper.Helpers;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.RSA.v1_0.SigVer.TestCaseExpectations;
using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Generation.RSA.v1_0.SigVer
{
    public class TestGroup : ITestGroup<TestGroup, TestCase>
    {
        public int TestGroupId { get; set; }

        [JsonProperty(PropertyName = "sigType")]
        public SignatureSchemes Mode { get; set; }
        public int Modulo { get; set; }

        [JsonIgnore]
        public HashFunction HashAlg { get; set; }

        [JsonProperty(PropertyName = "hashAlg")]
        public string HashAlgName
        {
            get => HashAlg?.Name;
            set => HashAlg = ShaAttributes.GetHashFunctionFromName(value);
        }

        [JsonIgnore]
        public bool IsMessageRandomized => "SP800-106".Equals(Conformance, StringComparison.OrdinalIgnoreCase);
        
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public string Conformance { get; set; } = string.Empty;

        public int SaltLen { get; set; }

        [JsonIgnore]
        public KeyPair Key { get; set; } = new KeyPair { PubKey = new PublicKey() };

        public BitString N
        {
            get => new BitString(Key.PubKey.N, Modulo);
            set => Key.PubKey.N = value.ToPositiveBigInteger();
        }

        public BigInteger E
        {
            get => Key.PubKey.E;
            set => Key.PubKey.E = value;
        }

        [JsonIgnore]
        public SignatureExpectationProvider TestCaseExpectationProvider { get; set; }

        public string TestType { get; set; }
        public List<TestCase> Tests { get; set; } = new List<TestCase>();

        public bool SetString(string name, string value)
        {
            if (string.IsNullOrEmpty(name))
            {
                return false;
            }

            switch (name.ToLower())
            {
                case "mod":
                    Modulo = int.Parse(value);
                    return true;

                case "n":
                    if (Key == null) { Key = new KeyPair { PubKey = new PublicKey() }; }
                    Key.PubKey.N = new BitString(value).ToPositiveBigInteger();
                    return true;

                case "e":
                    Key.PubKey.E = new BitString(value).ToPositiveBigInteger();
                    return true;

                case "hash":
                    HashAlg = ShaAttributes.GetHashFunctionFromName(value);
                    return true;

                case "saltlen":
                    SaltLen = int.Parse(value);
                    return true;
            }

            return false;
        }
    }
}
