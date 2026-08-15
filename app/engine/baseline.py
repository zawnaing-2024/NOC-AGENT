import math
import statistics
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class BaselineResult(BaseModel):
    sample_count: int = Field(default=0)
    valid_sample_count: int = Field(default=0)
    invalid_sample_count: int = Field(default=0)
    baseline_status: str = Field(default="INSUFFICIENT_HISTORY", description="NORMAL or INSUFFICIENT_HISTORY")
    current_value: float = Field(default=0.0)
    previous_value: Optional[float] = Field(default=None)
    moving_average: float = Field(default=0.0)
    median_value: float = Field(default=0.0)
    min_value: float = Field(default=0.0)
    max_value: float = Field(default=0.0)
    stddev: float = Field(default=0.0)
    pct_change: float = Field(default=0.0)
    method: str = Field(default="median")


def calculate_baseline(values: List[float], min_samples: int = 10, max_valid_limit: float = 800_000_000_000.0) -> BaselineResult:
    """
    Calculates robust baseline using median over validated historical rate samples.
    Excludes corrupted/impossible samples (> max_valid_limit or negative).
    Enforces minimum valid sample rule.
    """
    if not values:
        return BaselineResult(sample_count=0, valid_sample_count=0, invalid_sample_count=0, baseline_status="INSUFFICIENT_HISTORY")

    total_samples = len(values)
    current_val = values[0]
    prev_val = values[1] if total_samples > 1 else None

    # Exclude invalid/corrupted samples
    valid_vals = [v for v in values if v is not None and 0.0 <= v <= max_valid_limit]
    invalid_cnt = total_samples - len(valid_vals)
    valid_cnt = len(valid_vals)

    if not valid_vals:
        return BaselineResult(
            sample_count=total_samples,
            valid_sample_count=0,
            invalid_sample_count=invalid_cnt,
            baseline_status="INSUFFICIENT_HISTORY",
            current_value=current_val,
            previous_value=prev_val
        )

    median_val = float(statistics.median(valid_vals))
    avg_val = sum(valid_vals) / float(valid_cnt)
    min_val = min(valid_vals)
    max_val = max(valid_vals)

    if valid_cnt > 1:
        variance = sum((x - avg_val) ** 2 for x in valid_vals) / float(valid_cnt - 1)
        stddev_val = math.sqrt(variance)
    else:
        stddev_val = 0.0

    pct_chg = 0.0
    if prev_val is not None and prev_val > 0:
        pct_chg = ((current_val - prev_val) / float(prev_val)) * 100.0

    status = "NORMAL" if valid_cnt >= min_samples else "INSUFFICIENT_HISTORY"

    return BaselineResult(
        sample_count=total_samples,
        valid_sample_count=valid_cnt,
        invalid_sample_count=invalid_cnt,
        baseline_status=status,
        current_value=current_val,
        previous_value=prev_val,
        moving_average=median_val,
        median_value=median_val,
        min_value=min_val,
        max_value=max_val,
        stddev=stddev_val,
        pct_change=pct_chg,
        method="median"
    )
