import DiskplanPolicy
import Foundation
import Testing

@Test
func publicPolicyAPIExposesOnlySourceBoundEvaluationAndConservativeDisplayInput() throws {
  let fixture = publicPolicyFixture()
  let evaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: fixture.evidence, globalFacts: fixture.facts)
  )

  #expect(evaluation.sourceBinding.captureID == fixture.evidence.captureID)
  #expect(evaluation.sourceBinding.evidenceID == fixture.evidence.evidenceID)
  #expect(evaluation.sourceBinding.globalFactsHash == fixture.facts.globalFactsHash)
  #expect(evaluation.sourceBinding.policyVersion == fixture.evidence.policyVersion)
  #expect(evaluation.sourceBinding.schemaVersion == fixture.evidence.schemaVersion)
  #expect(
    evaluation.sourceBinding.semanticReferenceTimeSeconds
      == fixture.evidence.semanticReferenceTimeSeconds
  )

  let displayInput = ActionDisplayMetrics(
    immediateReclaimBytes: .known(1),
    inactiveDurationSeconds: .known(2),
    rebuildCost: .known(3),
    cleanupCost: .known(4),
    canonicalRawPath: Data("public-api".utf8)
  )
  #expect(displayInput.tier == .blocked)
}
