﻿using System.Threading.Tasks;
using NIST.CVP.ACVTS.Libraries.Crypto.Common.Hash.ShaWrapper;
using NIST.CVP.ACVTS.Libraries.Generation.HMAC.v1_0;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Tests.Core.TestCategoryAttributes;
using NUnit.Framework;

namespace NIST.CVP.ACVTS.Libraries.Generation.Tests.HMAC.v1_0
{
    [TestFixture, UnitTest]
    public class TestCaseValidatorTests
    {
        private TestCaseValidator _subject;

        [Test]
        public async Task ShouldValidateIfExpectedAndSuppliedResultsMatch()
        {
            var testCase = GetTestCase();
            var testGroup = GetTestGroup();
            _subject = new TestCaseValidator(testCase, testGroup);
            var result = await _subject.ValidateAsync(testCase);
            Assert.That(result != null);
            Assert.That(result.Result, Is.EqualTo(Core.Enums.Disposition.Passed));
        }

        [Test]
        public async Task ShouldFailIfMacDoesNotMatch()
        {
            var testMac = new BitString("D00000");

            var testCase = GetTestCase();
            var testGroup = GetTestGroup();
            testGroup.MacLength = testMac.BitLength;

            _subject = new TestCaseValidator(testCase, testGroup);
            var suppliedResult = GetTestCase();
            suppliedResult.Mac = testMac;
            var result = await _subject.ValidateAsync(suppliedResult);
            Assert.That(result != null);
            Assert.That(result.Result, Is.EqualTo(Core.Enums.Disposition.Failed));
        }

        [Test]
        public async Task ShouldShowMacAsReasonIfItDoesNotMatch()
        {
            var testMac = new BitString("D00000");

            var testCase = GetTestCase();
            var testGroup = GetTestGroup();
            testGroup.MacLength = testMac.BitLength;

            _subject = new TestCaseValidator(testCase, testGroup);
            var suppliedResult = GetTestCase();
            suppliedResult.Mac = testMac;
            var result = await _subject.ValidateAsync(suppliedResult);
            Assert.That(result != null);
            Assert.That(Core.Enums.Disposition.Failed == result.Result);
            Assert.That(result.Reason.Contains("MAC"), Is.True);
        }

        [Test]
        public async Task ShouldFailIfCipherTextNotPresent()
        {
            var testCase = GetTestCase();
            var testGroup = GetTestGroup();
            _subject = new TestCaseValidator(testCase, testGroup);
            var suppliedResult = GetTestCase();

            suppliedResult.Mac = null;

            var result = await _subject.ValidateAsync(suppliedResult);
            Assert.That(result != null);
            Assert.That(Core.Enums.Disposition.Failed == result.Result);

            Assert.That(result.Reason.Contains($"{nameof(suppliedResult.Mac)} was not present in the {nameof(TestCase)}"), Is.True);
        }

        [Test]
        public async Task ShouldPassWithMacsDifferingAfterBitLength()
        {
            var testCaseExpected = GetTestCase();
            var testCaseSupplied = GetTestCase();
            var testGroup = GetTestGroup();
            testGroup.MacLength = 9;

            testCaseExpected.Mac = new BitString("F500CAFECAFE");
            testCaseSupplied.Mac = new BitString("F500FACEFACE");

            _subject = new TestCaseValidator(testCaseExpected, testGroup);
            var result = await _subject.ValidateAsync(testCaseSupplied);
            Assert.That(result != null);
            Assert.That(result.Result, Is.EqualTo(Core.Enums.Disposition.Passed));
        }

        private TestGroup GetTestGroup()
        {
            var testGroup = new TestGroup
            {
                ShaMode = ModeValues.SHA1,
                ShaDigestSize = DigestSizes.d160,
                MacLength = 80,
                KeyLength = 128,
                MessageLength = 128
            };

            return testGroup;
        }

        private TestCase GetTestCase()
        {
            var testCase = new TestCase
            {
                Message = new BitString("AADAADAADAAD"),
                Mac = new BitString("ABCDEF0123456789ABCDEF0123456789"),
                TestCaseId = 1
            };
            return testCase;
        }
    }
}
