from __future__ import annotations

from .config import AnalysisConfig
from .models import AggregateScore, DimensionResult


def similarity_level(score: float, levels: dict[str, int]) -> str:
    return max(levels.items(), key=lambda item: (item[1] <= score, item[1]))[0]


def aggregate_dimensions(
    dimensions: dict[str, DimensionResult], config: AnalysisConfig
) -> AggregateScore:
    minimum = 0.0
    missing_weight = 0
    analyzed_weight = 0
    for key, weight in config.weights.items():
        result = dimensions[key]
        if result.score is None:
            missing_weight += weight
            continue
        analyzed_weight += weight
        minimum += weight * result.score / 100
    minimum = round(minimum, 2)
    maximum = round(minimum + missing_weight, 2)
    if missing_weight:
        return AggregateScore(None, minimum, maximum, analyzed_weight, None)
    return AggregateScore(
        minimum, minimum, maximum, analyzed_weight, similarity_level(minimum, config.levels)
    )
