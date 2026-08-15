from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class RootCauseInfo(BaseModel):
    description: str = Field(..., description="Technical description of the primary root cause")
    confidence: str = Field(default="HIGH", description="Confidence level: HIGH, MEDIUM, LOW")


class ImpactInfo(BaseModel):
    description: str = Field(..., description="Description of network operational impact")
    scope: str = Field(default="INTERFACE", description="Impact scope: DEVICE, INTERFACE, BGP, OSPF, ROUTING, NAT, UNKNOWN")


class EvidenceFact(BaseModel):
    fact: str = Field(..., description="Factual statement grounded strictly in evidence payload")
    source: str = Field(default="event", description="Data source: event, metric, interface, bgp, ospf, route, nat")


class Hypothesis(BaseModel):
    description: str = Field(..., description="Hypothesis description based on correlated evidence")
    confidence: str = Field(default="MEDIUM", description="Confidence level: HIGH, MEDIUM, LOW")


class RecommendedAction(BaseModel):
    step: int = Field(..., description="Step priority sequence number (1 = highest)")
    action: str = Field(..., description="Actionable troubleshooting recommendation")
    reason: str = Field(..., description="Technical rationale for the recommended action")


class AIIncidentAnalysisResponse(BaseModel):
    summary: str = Field(..., description="High-level incident analysis summary")
    root_cause: RootCauseInfo
    impact: ImpactInfo
    evidence: List[EvidenceFact] = Field(default_factory=list)
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    verification_steps: List[str] = Field(default_factory=list)
    customer_impact: str = Field(default="UNKNOWN", description="Customer impact assessment statement")
