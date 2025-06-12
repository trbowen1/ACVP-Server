﻿using System;
using System.Linq;
using System.Threading.Tasks;
using Moq;
using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Generation.Core.Async;
using NIST.CVP.ACVTS.Libraries.Generation.HMAC.v2_0;
using NIST.CVP.ACVTS.Libraries.Math;
using NIST.CVP.ACVTS.Tests.Core.TestCategoryAttributes;
using NUnit.Framework;

namespace NIST.CVP.ACVTS.Libraries.Generation.Tests.HMAC.v2_0
{
    [TestFixture, UnitTest]
    public class TestCaseValidatorFactoryTests
    {
        private Mock<ITestCaseGeneratorFactoryAsync<TestGroup, TestCase>> _mockTestCaseGeneratorFactory;
        private Mock<ITestCaseGeneratorAsync<TestGroup, TestCase>> _mockTestCaseGenerator;
        private TestCaseValidatorFactory _subject;

        [SetUp]
        public void Setup()
        {
            _mockTestCaseGeneratorFactory = new Mock<ITestCaseGeneratorFactoryAsync<TestGroup, TestCase>>();
            _mockTestCaseGenerator = new Mock<ITestCaseGeneratorAsync<TestGroup, TestCase>>();

            _mockTestCaseGenerator
                .Setup(s => s.GenerateAsync(It.IsAny<TestGroup>(), true, It.IsAny<int>()))
                .Returns(Task.FromResult(new TestCaseGenerateResponse<TestGroup, TestCase>(new TestCase())));
            _mockTestCaseGeneratorFactory
                .Setup(s => s.GetCaseGenerator(It.IsAny<TestGroup>()))
                .Returns(_mockTestCaseGenerator.Object);

            _subject = new TestCaseValidatorFactory();
        }

        [Test]
        [TestCase(typeof(TestCaseValidator))]
        public void ShouldReturnCorrectValidatorTypeDependantOnFunction(Type expectedType)
        {
            TestVectorSet testVectorSet = null;

            GetData(ref testVectorSet);

            var results = _subject.GetValidators(testVectorSet);

            Assert.That(results.Count() == 1, Is.True, "Expected 1 validator");
            Assert.That(results.First(), Is.InstanceOf(expectedType));
        }

        private void GetData(ref TestVectorSet testVectorSet)
        {
            testVectorSet = new TestVectorSet
            {
                Algorithm = string.Empty,
                TestGroups =
                [
                    new TestGroup
                    {
                        TestType = string.Empty,
                        Tests =
                        [
                            new TestCase
                            {
                                Key = new BitString(128),
                                Message = new BitString(128),
                                Mac = new BitString(128),
                                TestCaseId = 1
                            }
                        ]
                    }
                ]
            };
        }
    }
}
