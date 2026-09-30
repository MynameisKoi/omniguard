"""SpectraC2 Feature Extraction Module

Provides temporal and spectral feature extraction for non-decrypting C2 beacon detection.
"""

from .temporal import TemporalFeatureExtractor, FlowMetrics
from .spectral import SpectralFeatureExtractor, SpectralMetrics

__all__ = [
    "TemporalFeatureExtractor",
    "FlowMetrics",
    "SpectralFeatureExtractor",
    "SpectralMetrics",
]
