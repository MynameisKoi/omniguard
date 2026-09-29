"""Synthetic telemetry flow generator for C2 beacon training and evaluation.

Generates realistic network flow traces for:
1. Automated C2 Beacons (with 0% to 50% randomized jitter, e.g. Sliver, Cobalt Strike)
2. Normal Enterprise Background Traffic (bursty human browsing, Pareto think times)
"""

from __future__ import annotations

import random
from typing import Tuple, List, Dict, Any
import numpy as np


class SyntheticFlowGenerator:
    """Generates synthetic network flows simulating adversary beaconing vs benign traffic."""

    def __init__(self, random_seed: int = 42):
        np.random.seed(random_seed)
        random.seed(random_seed)

    def generate_c2_beacon(
        self,
        base_interval: float = 10.0,
        jitter_pct: float = 0.2,
        num_packets: int = 40,
        start_time: float = 1700000000.0,
    ) -> Dict[str, Any]:
        """Generates a C2 beacon session with timing jitter.

        Args:
            base_interval: Expected interval between beacons in seconds.
            jitter_pct: Jitter percentage (e.g. 0.2 = +/- 20% randomization).
            num_packets: Number of packets in the flow window.
            start_time: Base epoch timestamp.
        """
        timestamps = [start_time]
        sizes = [random.randint(90, 240)] # Initial beacon checkin
        directions = ["fwd"]

        current_time = start_time
        for i in range(1, num_packets):
            if i % 2 == 1:
                # Immediate C2 server response/ACK (10-40ms later)
                current_time += random.uniform(0.01, 0.04)
                timestamps.append(current_time)
                sizes.append(random.randint(60, 150))
                directions.append("bwd")
            else:
                # Adversary beacon sleep with jitter
                # interval = base * (1 + uniform(-jitter, +jitter))
                jitter_val = random.uniform(-jitter_pct, jitter_pct)
                sleep_interval = max(0.5, base_interval * (1.0 + jitter_val))
                current_time += sleep_interval
                timestamps.append(current_time)
                sizes.append(random.randint(80, 260))
                directions.append("fwd")

        return {
            "label": 1, # Malicious C2 beacon
            "flow_type": "c2_beacon",
            "base_interval": base_interval,
            "jitter_pct": jitter_pct,
            "timestamps": timestamps,
            "packet_sizes": sizes,
            "directions": directions,
        }

    def generate_benign_traffic(
        self,
        num_packets: int = 40,
        start_time: float = 1700000000.0,
    ) -> Dict[str, Any]:
        """Generates benign human browsing/application traffic (Pareto/bursty)."""
        timestamps = [start_time]
        sizes = [random.randint(64, 1460)]
        directions = [random.choice(["fwd", "bwd"])]

        current_time = start_time
        # Bursty behavior: packets arrive in rapid clusters followed by idle human think-time
        in_burst = True
        burst_counter = random.randint(3, 8)

        for _ in range(1, num_packets):
            if in_burst:
                # Fast consecutive packets (HTTP/TLS data transfer)
                current_time += np.random.exponential(scale=0.03)
                sizes.append(int(np.random.choice([64, 512, 1420, 1500])))
                directions.append(random.choice(["fwd", "bwd"]))
                burst_counter -= 1
                if burst_counter <= 0:
                    in_burst = False
            else:
                # Think time: heavy-tailed idle interval
                think_time = float(np.random.pareto(a=1.8) * 3.0 + 1.5)
                think_time = min(think_time, 90.0) # Cap idle time
                current_time += think_time
                sizes.append(random.randint(80, 500))
                directions.append("fwd")
                in_burst = True
                burst_counter = random.randint(3, 8)

            timestamps.append(current_time)

        return {
            "label": 0, # Benign traffic
            "flow_type": "benign",
            "timestamps": timestamps,
            "packet_sizes": sizes,
            "directions": directions,
        }

    def generate_dataset(
        self,
        n_samples: int = 1000,
        packets_per_flow: int = 40,
        c2_ratio: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """Generates a balanced dataset of C2 beacons and benign flows."""
        dataset = []
        n_c2 = int(n_samples * c2_ratio)
        n_benign = n_samples - n_c2

        for _ in range(n_c2):
            interval = float(random.choice([3.0, 5.0, 10.0, 15.0, 30.0, 60.0]))
            jitter = float(random.uniform(0.05, 0.45)) # 5% to 45% jitter
            flow = self.generate_c2_beacon(
                base_interval=interval,
                jitter_pct=jitter,
                num_packets=packets_per_flow,
            )
            dataset.append(flow)

        for _ in range(n_benign):
            flow = self.generate_benign_traffic(num_packets=packets_per_flow)
            dataset.append(flow)

        random.shuffle(dataset)
        return dataset
