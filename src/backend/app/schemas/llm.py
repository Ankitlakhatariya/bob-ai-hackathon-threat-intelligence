from typing import List, Optional
from pydantic import BaseModel, Field


class MITREAssessment(BaseModel):
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID, e.g., T1059.001")
    technique_name: str = Field(..., description="MITRE ATT&CK technique name")
    tactic: str = Field(..., description="The tactic this technique falls under")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this mapping (0.0 to 1.0)")
    evidence: str = Field(..., description="Specific evidence supporting this MITRE mapping")


class ThreatAnalysisResponse(BaseModel):
    assessment: str = Field(..., description="A detailed analysis of the threat based purely on evidence")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this assessment (0.0 to 1.0)")
    key_findings: List[str] = Field(..., description="High-level key findings from the evidence")
    evidence: List[str] = Field(..., description="A list of specific evidence points used in the analysis")
    potential_attack_chain: List[str] = Field(..., description="Hypothesized sequence of attack events")
    mitre_assessment: List[MITREAssessment] = Field(..., description="Mapping of evidence to MITRE ATT&CK techniques")
    uncertainties: List[str] = Field(..., description="What is NOT known or cannot be confirmed from evidence")
    recommended_investigation_focus: List[str] = Field(..., description="Specific next steps for analysts")
    bluf: str = Field(..., description="Bottom Line Up Front - Commander-friendly summary")
    priority_explanation: str = Field(..., description="Explanation of why this threat has its current priority/risk score")


class BlufLLMResponse(BaseModel):
    bottom_line: str = Field(..., description="What commanders need to know immediately")
    situation: str = Field(..., description="What happened")
    assessment: str = Field(..., description="What the evidence currently indicates")
    impact: str = Field(..., description="Potentially affected assets/systems")
    evidence: List[str] = Field(..., description="Most important supporting evidence")
    mitre_context: str = Field(..., description="Relevant observed MITRE ATT&CK techniques")
    uncertainties: str = Field(..., description="What is not yet known")
    recommended_focus: str = Field(..., description="What analysts should examine next")
    priority: str = Field(..., description="Explanation of existing deterministic priority/risk")
