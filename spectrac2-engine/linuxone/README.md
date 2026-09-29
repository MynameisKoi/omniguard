# SpectraC2 on IBM LinuxONE (`s390x`)

This directory contains deployment manifests, Docker configurations, and performance optimization guides for running the **SpectraC2** flow behavioral inference engine on **IBM LinuxONE** (`s390x`) enterprise servers.

---

## Why IBM LinuxONE for SpectraC2?

1. **High-Throughput Vector Math**: IBM z15 and z16 enterprise mainframes feature specialized **Vector Facility (SIMD)** instructions accelerating complex Fast Fourier Transform (FFT) and Power Spectral Density (PSD) matrix operations across millions of simultaneous network flows.
2. **Zero-Downtime Telemetry Ingestion**: Delivers 99.999% reliability with dedicated hardware crypto accelerators (CPACF) and massive L2/L3/L4 cache hierarchies capable of processing enterprise-scale Zeek and Suricata streams with sub-millisecond jitter.
3. **Data Sovereignty**: Meets air-gapped zero-cloud-egress enterprise security requirements.

---

## Building and Cross-Compiling for `s390x`

Using Docker Buildx from any x86_64 or ARM development workstation:

```bash
# 1. Enable QEMU multi-architecture emulation
docker run --privileged --rm tonistiigi/binfmt --install all

# 2. Create a multi-arch builder instance
docker buildx create --name omniguard-builder --use
docker buildx inspect --bootstrap

# 3. Build and tag the s390x image
docker buildx build \
  --platform linux/s390x \
  -t omniguard/spectrac2-engine:s390x \
  -f spectrac2-engine/linuxone/Dockerfile.s390x \
  --load .
```

---

## Deploying to IBM Cloud Hyper Protect Virtual Server (HPVS)

On the IBM LinuxONE instance:

```bash
# Run container with resource limits and OpenBLAS thread scaling
docker run -d \
  --name spectrac2-engine \
  --restart unless-stopped \
  -p 8000:8000 \
  -e OPENBLAS_NUM_THREADS=8 \
  -e OMP_NUM_THREADS=8 \
  omniguard/spectrac2-engine:s390x

# Verify health endpoint
curl -s http://localhost:8000/health | jq .
```

---

## Big-Endian vs Little-Endian Architecture Considerations

* `s390x` is a **Big-Endian** architecture, unlike x86_64 and aarch64 which are Little-Endian.
* All FFT and signal processing implementations in `spectrac2-engine/feature-extraction/` rely on native IEEE 754 floating point arrays with endianness handled automatically by NumPy and SciPy.
* Custom binary network protocol decoders should explicitly specify `>` (Big-Endian) or `<` (Little-Endian) when unpacking raw network packet headers using Python's `struct` module.
