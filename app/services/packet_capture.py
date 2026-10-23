"""CICIDS2017-compatible flow feature extraction for live metadata."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from time import monotonic
from typing import Any, Iterable

FEATURE_NAMES = (
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max",
    "Bwd IAT Min", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s",
    "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "PSH Flag Count", "ACK Flag Count", "Average Packet Size",
    "Subflow Fwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Max",
    "Active Min", "Idle Mean", "Idle Max", "Idle Min",
)


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    return (
        min(values),
        max(values),
        statistics.fmean(values),
        statistics.stdev(values) if len(values) > 1 else 0.0,
    )


@dataclass
class FlowFeatureAccumulator:
    """Accumulate packet metadata and emit all 52 model features.

    Packet dictionaries must contain ``timestamp``, ``length`` and
    ``direction`` (``fwd`` or ``bwd``). Optional TCP flags and header/window
    values are used when present. No payload is accepted or retained.
    """

    destination_port: int = 0
    _packets: list[dict[str, float | str]] = field(default_factory=list)

    def add_packet(self, packet: dict[str, Any]) -> None:
        try:
            timestamp = float(packet["timestamp"])
            length = float(packet["length"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("packet requires numeric timestamp and length") from exc
        if length < 0:
            raise ValueError("packet length cannot be negative")
        direction = str(packet.get("direction", "fwd")).lower()
        if direction not in {"fwd", "bwd"}:
            raise ValueError("packet direction must be fwd or bwd")
        self.destination_port = int(packet.get("dst_port", self.destination_port) or 0)
        self._packets.append({
            "timestamp": timestamp,
            "length": length,
            "direction": direction,
            "header": float(packet.get("header_length", 0) or 0),
            "window": float(packet.get("window", 0) or 0),
            "flags": str(packet.get("tcp_flags", "")).upper(),
        })

    def features(self) -> dict[str, float]:
        if not self._packets:
            return {name: 0.0 for name in FEATURE_NAMES}
        packets = sorted(self._packets, key=lambda item: float(item["timestamp"]))
        fwd = [p for p in packets if p["direction"] == "fwd"]
        bwd = [p for p in packets if p["direction"] == "bwd"]
        lengths = [float(p["length"]) for p in packets]
        fwd_lengths = [float(p["length"]) for p in fwd]
        bwd_lengths = [float(p["length"]) for p in bwd]
        duration = max(float(packets[-1]["timestamp"]) - float(packets[0]["timestamp"]), 0.0)
        all_iat = [float(b["timestamp"]) - float(a["timestamp"]) for a, b in zip(packets, packets[1:])]
        fwd_iat = [float(b["timestamp"]) - float(a["timestamp"]) for a, b in zip(fwd, fwd[1:])]
        bwd_iat = [float(b["timestamp"]) - float(a["timestamp"]) for a, b in zip(bwd, bwd[1:])]
        fmin, fmax, fmean, fstd = _stats(fwd_lengths)
        bmin, bmax, bmean, bstd = _stats(bwd_lengths)
        pmin, pmax, pmean, pstd = _stats(lengths)
        imin, imax, imean, istd = _stats(all_iat)

        def iat(values: list[float]) -> tuple[float, float, float, float]:
            if not values:
                return 0.0, 0.0, 0.0, 0.0
            return sum(values), statistics.fmean(values), (
                statistics.stdev(values) if len(values) > 1 else 0.0
            ), max(values)

        fit, fim, fis, fimax = iat(fwd_iat)
        bit, bim, bis, bimax = iat(bwd_iat)
        duration_seconds = duration or 1e-9
        headers_fwd = sum(float(p["header"]) for p in fwd)
        headers_bwd = sum(float(p["header"]) for p in bwd)
        result = {
            "Destination Port": float(self.destination_port),
            "Flow Duration": duration * 1_000_000,
            "Total Fwd Packets": float(len(fwd)),
            "Total Length of Fwd Packets": sum(fwd_lengths),
            "Fwd Packet Length Max": fmax, "Fwd Packet Length Min": fmin,
            "Fwd Packet Length Mean": fmean, "Fwd Packet Length Std": fstd,
            "Bwd Packet Length Max": bmax, "Bwd Packet Length Min": bmin,
            "Bwd Packet Length Mean": bmean, "Bwd Packet Length Std": bstd,
            "Flow Bytes/s": sum(lengths) / duration_seconds,
            "Flow Packets/s": len(packets) / duration_seconds,
            "Flow IAT Mean": imean * 1_000_000, "Flow IAT Std": istd * 1_000_000,
            "Flow IAT Max": imax * 1_000_000, "Flow IAT Min": imin * 1_000_000,
            "Fwd IAT Total": fit * 1_000_000, "Fwd IAT Mean": fim * 1_000_000,
            "Fwd IAT Std": fis * 1_000_000, "Fwd IAT Max": fimax * 1_000_000,
            "Fwd IAT Min": min(fwd_iat, default=0.0) * 1_000_000,
            "Bwd IAT Total": bit * 1_000_000, "Bwd IAT Mean": bim * 1_000_000,
            "Bwd IAT Std": bis * 1_000_000, "Bwd IAT Max": bimax * 1_000_000,
            "Bwd IAT Min": min(bwd_iat, default=0.0) * 1_000_000,
            "Fwd Header Length": headers_fwd, "Bwd Header Length": headers_bwd,
            "Fwd Packets/s": len(fwd) / duration_seconds,
            "Bwd Packets/s": len(bwd) / duration_seconds,
            "Min Packet Length": pmin, "Max Packet Length": pmax,
            "Packet Length Mean": pmean, "Packet Length Std": pstd,
            "Packet Length Variance": pstd * pstd,
            "FIN Flag Count": sum("FIN" in str(p["flags"]) for p in packets),
            "PSH Flag Count": sum("PSH" in str(p["flags"]) for p in packets),
            "ACK Flag Count": sum("ACK" in str(p["flags"]) for p in packets),
            "Average Packet Size": pmean, "Subflow Fwd Bytes": sum(fwd_lengths),
            "Init_Win_bytes_forward": float(fwd[0]["window"]) if fwd else 0.0,
            "Init_Win_bytes_backward": float(bwd[0]["window"]) if bwd else 0.0,
            "act_data_pkt_fwd": float(sum(float(p["length"]) > 0 for p in fwd)),
            "min_seg_size_forward": fmin,
            "Active Mean": duration * 1_000_000, "Active Max": duration * 1_000_000,
            "Active Min": duration * 1_000_000, "Idle Mean": 0.0, "Idle Max": 0.0,
            "Idle Min": 0.0,
        }
        return {name: float(result.get(name, 0.0)) for name in FEATURE_NAMES}


def capture_packets(interface: str = "", packet_filter: str = "") -> Iterable[dict[str, Any]]:
    """Yield metadata from Scapy when packet capture is explicitly enabled."""
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("packet capture requires the optional scapy dependency") from exc

    def convert(packet: Any) -> dict[str, Any]:
        timestamp = float(getattr(packet, "time", monotonic()))
        length = float(len(packet))
        return {"timestamp": timestamp, "length": length, "direction": "fwd"}

    packets = sniff(iface=interface or None, filter=packet_filter or None, store=False)
    return (convert(packet) for packet in packets)
