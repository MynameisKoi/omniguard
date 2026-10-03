/* ============================================================
 * SAMPLE DATA — NOT REAL. NEEDS A BACKEND.
 * ============================================================
 *
 * Everything in this file is invented so the charts have a shape to draw
 * while the endpoint behind them doesn't exist yet.
 *
 * TODO: replace with GET /stats/timeseries?hours=24, which should return
 * per-hour counts bucketed by severity:
 *
 *   { "buckets": [
 *       { "hour": "2026-10-02T09:00:00Z",
 *         "critical": 2, "high": 5, "medium": 9, "low": 4 }, ... ] }
 *
 * Until then: anything importing from here renders with a "sample" badge so
 * nobody mistakes it for live data in a demo.
 */

// deterministic pseudo-random, so the charts don't jump on every re-render
function seeded(seed) {
    let value = seed;
    return () => {
        value = (value * 1664525 + 1013904223) % 4294967296;
        return value / 4294967296;
    };
}

/* 24 hourly buckets, one series per severity. Shaped to look like a working
   day — quiet overnight, a climb through the morning, a spike mid-afternoon. */
export function sampleThreatActivity() {
    const rand = seeded(20261002);
    const shape = hour => {
        const workday = Math.exp(-Math.pow((hour - 14) / 5.5, 2));  // peak ~2pm
        const night = 0.18;
        return night + workday;
    };

    return Array.from({ length: 24 }, (_, hour) => {
        const base = shape(hour);
        const jitter = () => 0.75 + rand() * 0.5;
        return {
            hour,
            label: `${String(hour).padStart(2, "0")}:00`,
            critical: Math.round(base * 4 * jitter()),
            high: Math.round(base * 13 * jitter()),
            medium: Math.round(base * 26 * jitter()),
            low: Math.round(base * 18 * jitter()),
        };
    });
}

/* Short series for the sparkline on each stat card. */
export function sampleSparkline(key) {
    const seeds = { total: 11, critical: 23, high: 37, medium: 51, low: 67, incidents: 83 };
    const rand = seeded(seeds[key] ?? 7);
    let value = 40 + rand() * 20;
    return Array.from({ length: 20 }, () => {
        value += (rand() - 0.45) * 14;
        value = Math.max(6, Math.min(94, value));
        return value;
    });
}

/* The "↑ 12%" deltas. Invented. Sign is what the arrow and colour key off. */
export const SAMPLE_DELTAS = {
    total: 12,
    critical: 50,
    high: 22,
    medium: -8,
    low: -15,
    incidents: 40,
};
