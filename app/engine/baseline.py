import math
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class BaselineResult(BaseModel):
    sample_count: int = Field(default=0)
    baseline_status: str = Field(default="INSUFFICIENT_HISTORY", description="NORMAL or INSUFFICIENT_HISTORY")
    current_value: float = Field(default=0.0)
    previous_value: Optional[float] = Field(default=None)
    moving_average: float = Field(default=0.0)
    min_value: float = Field(default=0.0)
    max_value: float = Field(default=0.0)
    stddev: float = Field(default=0.0)
    pct_change: float = Field(default=0.0)


def calculate_baseline(values: List[float], min_samples: int = 10) -> BaselineResult:
    """
    Calculates moving average, min, max, stddev, previous value, and percentage change.
    Enforces minimum sample rule: if len(values) < 10, baseline_status = 'INSUFFICIENT_HISTORY'.
    """
    if not values:
        return BaselineResult(sample_count=0, baseline_status="INSUFFICIENT_HISTORY")

    n = len(values)
    current_val = values[0]
    prev_val = values[1] if n > 1 else None

    avg_val = sum(values) / float(n)
    min_val = min(values)
    max_val = max(values)

    # Standard deviation calculation
    if n > 1:
        variance = sum((x - avg_val) ** 2 for x in values) / float(n - 1)
        stddev_val = math.sqrt(variance)
    else:
        stddev_val = 0.0

    # Percentage change
    pct_chg = 0.0
    if prev_val is not None and prev_val != 0:
        pct_chg = ((current_val - prev_val) / float(prev_val)) * 100.0

    status = "NORMAL" if n >= min_samples else "INSUFFICIENT_HISTORY"

    return BaselineResult(
        sample_count=n,
        baseline_status=status,
        current_value=current_val,
        previous_value=prev_val,
        moving_average=avg_val,
        min_value=min_val,
        max_value=max_val,
        stddev=stddev_val,
        pct_change=pct_chg,
    )
