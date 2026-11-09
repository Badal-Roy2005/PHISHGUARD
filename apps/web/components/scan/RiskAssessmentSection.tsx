"use client";

import type { RiskAssessment } from "@phishguard/contracts";

import { RiskScoreCard } from "./RiskScoreCard";
import { MLProbabilityCard } from "./MLProbabilityCard";
import { RiskFactorsSection } from "./RiskFactorsSection";
import { PolicyDetailsSection } from "./PolicyDetailsSection";
import { ConfidenceCard } from "./ConfidenceCard";

interface RiskAssessmentSectionProps {
  risk: RiskAssessment;
  isPartial: boolean;
}

export function RiskAssessmentSection({ risk, isPartial }: RiskAssessmentSectionProps) {
  return (
    <section className="space-y-5">
      <RiskScoreCard risk={risk} isPartial={isPartial} />
      <ConfidenceCard risk={risk} />
      <MLProbabilityCard risk={risk} />
      <RiskFactorsSection risk={risk} />
      <PolicyDetailsSection risk={risk} />
    </section>
  );
}
