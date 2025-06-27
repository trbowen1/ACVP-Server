using NIST.CVP.ACVTS.Libraries.Generation.Core;
using NIST.CVP.ACVTS.Libraries.Math;

namespace NIST.CVP.ACVTS.Libraries.Generation.SPDM
{
    public class TestCase : ITestCase<TestGroup, TestCase>
    {
        public int TestCaseId { get; set; }
        public TestGroup ParentGroup { get; set; }
        public bool? TestPassed => true;
        public bool Deferred => false;

        public BitString SharedSecret { get; set; }
        public BitString TranscriptHash1Random { get; set; }
        public BitString TranscriptHash2Random { get; set; }

        public BitString RequestDirectionHandshakeSecret { get; set; }
        public BitString ResponseDirectionHandshakeSecret { get; set; }

        public BitString RequestDirectionDataSecret { get; set; }
        public BitString ResponseDirectionDataSecret { get; set; }
        public BitString ExportMasterSecret { get; set; }
        
    }
}
