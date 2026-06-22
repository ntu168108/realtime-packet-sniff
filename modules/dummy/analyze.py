"""
Dummy Analysis Module - Module demo đầy đủ
- Batch mode: phân tích PCAP rotated file
- Live mode: stream từng packet qua detector
- Detection thật:
  * Port scan: sliding window 5s, threshold configurable
  * DNS tunneling: entropy subdomain + length
  * Beaconing: regular interval (Jitter thấp)
- Auto flush detections theo batch size + timeout
"""

import math
import time
import logging
from collections import Counter, deque, defaultdict
from typing import List, Dict, Optional, Deque, Tuple

from ..base import (
    BaseModule, LiveModule, Summary, Detection,
    Priority, Category,
)
from core.pcap_writer import PcapReader
from core.decoder import decode_packet

logger = logging.getLogger(__name__)


# ============================================================
                    # BATCH MODULE
# ============================================================

class DummyModule(BaseModule):
    """
    Batch module demo:
    - Protocol distribution
    - Top talkers
    - Port scan (sliding window 5s, configurable threshold)
    - DNS tunneling (entropy + long subdomain)
    - Beaconing detection
    """

    def __init__(
        self,
        port_scan_threshold: int = 20,
        port_scan_window_sec: float = 5.0,
        dns_entropy_threshold: float = 4.0,
        dns_subdomain_max: int = 30,
        beacon_jitter_ratio: float = 0.15,
        beacon_min_packets: int = 6,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_sec = port_scan_window_sec
        self.dns_entropy_threshold = dns_entropy_threshold
        self.dns_subdomain_max = dns_subdomain_max
        self.beacon_jitter_ratio = beacon_jitter_ratio
        self.beacon_min_packets = beacon_min_packets

    @property
    def name(self) -> str:
        return "dummy"

    @property
    def description(self) -> str:
        return "Demo module: stats + port-scan + dns-tunnel + beaconing"

    @property
    def version(self) -> str:
        return "2.0.0"

    def analyze(
        self,
        pcap_path: str,
        output_dir: str,
        interface: str,
        time_window: str,
    ) -> Summary:
        start_time = time.time()

        # Sliding window port hits: src_ip -> deque[(ts, dport)]
        port_hits: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        # DNS qname tracking: src -> deque[(ts, qname)]
        dns_queries: Dict[str, Deque[Tuple[float, str]]] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        # Beacon: dst_ip -> deque[ts]
        beacon_intervals: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=64)
        )

        proto_counts: Counter = Counter()
        src_counts: Counter = Counter()
        dst_counts: Counter = Counter()

        detections: List[Detection] = []
        total_packets = 0
        analyzed_packets = 0
        errors: List[str] = []
        alerted_keys: set = set()  # dedup: (src, label) -> chỉ fire 1 lần

        try:
            with PcapReader(pcap_path) as reader:
                for pkt_info in reader:
                    total_packets += 1
                    try:
                        decoded = decode_packet(pkt_info.data)
                        analyzed_packets += 1
                        ts = pkt_info.ts_sec + (pkt_info.ts_usec or 0) / 1e6

                        proto = decoded.protocol_name or "UNKNOWN"
                        proto_counts[proto] += 1
                        if decoded.src_addr:
                            src_counts[decoded.src_addr] += 1
                        if decoded.dst_addr:
                            dst_counts[decoded.dst_addr] += 1

                        # ----- Port scan (sliding window) -----
                        if decoded.src_addr and decoded.dst_port and decoded.protocol_name == "TCP":
                            dq = port_hits[decoded.src_addr]
                            dq.append((ts, decoded.dst_port))
                            # prune cũ hơn window
                            while dq and ts - dq[0][0] > self.port_scan_window_sec:
                                dq.popleft()
                            # unique ports trong window
                            unique_ports = {p for _, p in dq}
                            if len(unique_ports) >= self.port_scan_threshold:
                                key = (decoded.src_addr, "port-scan")
                                if key not in alerted_keys:
                                    alerted_keys.add(key)
                                    detections.append(Detection(
                                        stt=pkt_info.stt,
                                        ts_sec=pkt_info.ts_sec,
                                        label="port-scan",
                                        src=decoded.src_addr,
                                        dst="multiple",
                                        dport=len(unique_ports),
                                        proto="TCP",
                                        priority=Priority.HIGH.value,
                                        category=Category.RECON.value,
                                        details={
                                            "unique_ports": len(unique_ports),
                                            "window_sec": self.port_scan_window_sec,
                                            "threshold": self.port_scan_threshold,
                                        }
                                    ))

                        # ----- DNS tunneling (qname từ DNS payload) -----
                        if decoded.protocol_name == "DNS" and decoded.dst_port == 53:
                            qname = self._extract_dns_qname(decoded)
                            if qname and decoded.src_addr:
                                dns_queries[decoded.src_addr].append((ts, qname))
                                entropy = self._shannon_entropy(qname.split('.')[0])
                                # Long subdomain + entropy cao = tunnel suspect
                                first_label = qname.split('.')[0]
                                if (entropy >= self.dns_entropy_threshold
                                        or len(first_label) >= self.dns_subdomain_max):
                                    key = (decoded.src_addr, "dns-tunnel")
                                    if key not in alerted_keys:
                                        alerted_keys.add(key)
                                        detections.append(Detection(
                                            stt=pkt_info.stt,
                                            ts_sec=pkt_info.ts_sec,
                                            label="dns-tunnel",
                                            src=decoded.src_addr,
                                            dport=53,
                                            proto="DNS",
                                            priority=Priority.HIGH.value,
                                            category=Category.EXFIL.value,
                                            details={
                                                "qname": qname,
                                                "entropy": round(entropy, 2),
                                                "label_len": len(first_label),
                                            }
                                        ))

                        # ----- Beaconing (regular interval) -----
                        if decoded.dst_addr and decoded.protocol_name in ("TCP", "UDP", "HTTPS", "HTTP"):
                            dq = beacon_intervals[decoded.dst_addr]
                            dq.append(ts)
                            if len(dq) >= self.beacon_min_packets:
                                intervals = [dq[i] - dq[i-1] for i in range(1, len(dq))]
                                intervals = [x for x in intervals if x > 0]
                                if len(intervals) >= self.beacon_min_packets - 1:
                                    mean = sum(intervals) / len(intervals)
                                    if mean > 0:
                                        variance = sum(
                                            (x - mean) ** 2 for x in intervals
                                        ) / len(intervals)
                                        std = math.sqrt(variance)
                                        jitter_ratio = std / mean
                                        # Jitter thấp + interval cố định = beacon
                                        if jitter_ratio <= self.beacon_jitter_ratio and mean < 300:
                                            key = (decoded.dst_addr, "beaconing")
                                            if key not in alerted_keys:
                                                alerted_keys.add(key)
                                                detections.append(Detection(
                                                    stt=pkt_info.stt,
                                                    ts_sec=pkt_info.ts_sec,
                                                    label="beaconing",
                                                    dst=decoded.dst_addr,
                                                    proto=decoded.protocol_name,
                                                    priority=Priority.CRITICAL.value,
                                                    category=Category.C2.value,
                                                    details={
                                                        "interval_mean_sec": round(mean, 2),
                                                        "jitter_ratio": round(jitter_ratio, 4),
                                                        "samples": len(intervals),
                                                    }
                                                ))

                    except Exception as e:
                        if len(errors) < 10:
                            errors.append(f"Packet {pkt_info.stt}: {str(e)}")
        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
            errors.append(f"PCAP read error: {str(e)}")

        # ----- High-rate (legacy) -----
        HIGH_RATE_THRESHOLD = 1000
        for src_ip, count in src_counts.items():
            if count >= HIGH_RATE_THRESHOLD:
                detections.append(Detection(
                    stt=0,
                    ts_sec=int(start_time),
                    label="high-rate-source",
                    src=src_ip,
                    priority=Priority.MEDIUM.value,
                    category=Category.ANOMALY.value,
                    details={"packet_count": count}
                ))

        end_time = time.time()
        alerts_count = sum(1 for d in detections if d.is_alert)

        summary = Summary(
            module_name=self.name,
            interface=interface,
            time_window=time_window,
            pcap_file=pcap_path,
            total_packets=total_packets,
            analyzed_packets=analyzed_packets,
            total_hits=len(detections),
            alerts_generated=alerts_count,
            labels={
                "port-scan": sum(1 for d in detections if d.label == "port-scan"),
                "dns-tunnel": sum(1 for d in detections if d.label == "dns-tunnel"),
                "beaconing": sum(1 for d in detections if d.label == "beaconing"),
                "high-rate-source": sum(
                    1 for d in detections if d.label == "high-rate-source"
                ),
            },
            top_protocols=dict(proto_counts.most_common(10)),
            top_sources=src_counts.most_common(10),
            top_destinations=dst_counts.most_common(10),
            start_time=start_time,
            end_time=end_time,
            duration_sec=end_time - start_time,
            errors=errors,
        )
        # Lưu cả labels protocol vào summary để backward-compat
        summary.labels.update({
            f"proto_{k}": v for k, v in proto_counts.most_common(10)
        })

        self.write_output(
            output_dir=output_dir,
            interface=interface,
            time_window=time_window,
            summary=summary,
            detections=detections,
        )
        return summary

    # ----- helpers -----

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Entropy Shannon của 1 string"""
        if not s:
            return 0.0
        freq: Counter = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _extract_dns_qname(decoded) -> Optional[str]:
        """
        Trích qname từ DNS payload nếu có.
        decoded.info_str có thể chứa hint, fallback parse payload.
        """
        try:
            # Thử dùng info_str trước (format: "... DNS ...")
            # Rồi parse raw payload: bỏ DNS header 12 bytes, rồi đọc labels
            payload = decoded.payload
            if not payload or len(payload) < 12:
                return None
            # Skip 12-byte header
            labels = []
            i = 12
            while i < len(payload) and payload[i] != 0:
                length = payload[i]
                i += 1
                if length & 0xC0:  # pointer
                    break
                if i + length > len(payload):
                    break
                try:
                    label = payload[i:i+length].decode('ascii', errors='ignore')
                    labels.append(label)
                    i += length
                except Exception:
                    break
            return '.'.join(labels) if labels else None
        except Exception:
            return None


# ============================================================
                    # LIVE MODULE
# ============================================================

class DummyLiveModule(LiveModule):
    """
    Live module demo - dùng cùng detectors nhưng stream-based.
    State nằm trong instance, không persist giữa các lần restart.
    Flush detection định kỳ (mỗi N packet hoặc M giây).
    """

    def __init__(
        self,
        port_scan_threshold: int = 15,
        dns_entropy_threshold: float = 4.0,
        beacon_min_packets: int = 5,
        flush_interval_sec: float = 5.0,
        on_flush: Optional[callable] = None,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.dns_entropy_threshold = dns_entropy_threshold
        self.beacon_min_packets = beacon_min_packets
        self.flush_interval_sec = flush_interval_sec
        self._on_flush = on_flush  # callback để runner emit alert

        # Sliding window state
        self._port_hits: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=5000)
        )
        self._beacon_intervals: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=32)
        )
        self._alerted_keys: set = set()
        self._last_flush = time.time()
        # Thống kê counters để flush summary
        self._packet_count = 0
        self._detection_count = 0
        self._alert_count = 0

    @property
    def name(self) -> str:
        return "dummy-live"

    @property
    def description(self) -> str:
        return "Live detector: port-scan + dns-tunnel + beaconing"

    @property
    def version(self) -> str:
        return "2.0.0"

    @property
    def max_latency_ms(self) -> float:
        # Live cần nhanh - nếu vượt thì skip packet
        return 10.0

    def on_start(self):
        logger.info(f"{self.name} started")
        self._last_flush = time.time()
        self._packet_count = 0
        self._detection_count = 0
        self._alert_count = 0

    def on_stop(self):
        logger.info(
            f"{self.name} stopped: "
            f"{self._packet_count} packets, "
            f"{self._detection_count} detections, "
            f"{self._alert_count} alerts"
        )

    def on_packet(self, pkt_info, decoded) -> Optional[Detection]:
        if decoded is None:
            return None
        self._packet_count += 1
        ts = pkt_info.ts_sec + (pkt_info.ts_usec or 0) / 1e6

        det: Optional[Detection] = None

        # Port scan (TCP)
        if decoded.src_addr and decoded.dst_port and decoded.protocol_name == "TCP":
            dq = self._port_hits[decoded.src_addr]
            dq.append((ts, decoded.dst_port))
            # prune cũ hơn 5s
            while dq and ts - dq[0][0] > 5.0:
                dq.popleft()
            unique_ports = {p for _, p in dq}
            if len(unique_ports) >= self.port_scan_threshold:
                key = (decoded.src_addr, "port-scan-live")
                if key not in self._alerted_keys:
                    self._alerted_keys.add(key)
                    det = Detection(
                        stt=pkt_info.stt,
                        ts_sec=pkt_info.ts_sec,
                        label="port-scan-live",
                        src=decoded.src_addr,
                        dst="multiple",
                        dport=len(unique_ports),
                        proto="TCP",
                        priority=Priority.HIGH.value,
                        category=Category.RECON.value,
                        details={
                            "unique_ports": len(unique_ports),
                            "window_sec": 5.0,
                        }
                    )

        # DNS tunneling
        elif decoded.protocol_name == "DNS" and decoded.dst_port == 53:
            qname = DummyModule._extract_dns_qname(decoded)
            if qname and decoded.src_addr:
                first_label = qname.split('.')[0]
                entropy = DummyModule._shannon_entropy(first_label)
                if (entropy >= self.dns_entropy_threshold
                        or len(first_label) >= 30):
                    key = (decoded.src_addr, "dns-tunnel-live")
                    if key not in self._alerted_keys:
                        self._alerted_keys.add(key)
                        det = Detection(
                            stt=pkt_info.stt,
                            ts_sec=pkt_info.ts_sec,
                            label="dns-tunnel-live",
                            src=decoded.src_addr,
                            dport=53,
                            proto="DNS",
                            priority=Priority.HIGH.value,
                            category=Category.EXFIL.value,
                            details={
                                "qname": qname,
                                "entropy": round(entropy, 2),
                                "label_len": len(first_label),
                            }
                        )

        # Beaconing
        if decoded.dst_addr and decoded.protocol_name in ("TCP", "UDP", "HTTPS", "HTTP"):
            dq = self._beacon_intervals[decoded.dst_addr]
            dq.append(ts)
            if len(dq) >= self.beacon_min_packets:
                intervals = [dq[i] - dq[i-1] for i in range(1, len(dq))]
                intervals = [x for x in intervals if x > 0]
                if len(intervals) >= self.beacon_min_packets - 1:
                    mean = sum(intervals) / len(intervals)
                    if mean > 0:
                        variance = sum(
                            (x - mean) ** 2 for x in intervals
                        ) / len(intervals)
                        std = math.sqrt(variance)
                        jitter = std / mean
                        if jitter <= 0.15 and mean < 300:
                            key = (decoded.dst_addr, "beaconing-live")
                            if key not in self._alerted_keys:
                                self._alerted_keys.add(key)
                                # Beaconing critical - override detection
                                if det is None:
                                    det = Detection(
                                        stt=pkt_info.stt,
                                        ts_sec=pkt_info.ts_sec,
                                        label="beaconing-live",
                                        dst=decoded.dst_addr,
                                        proto=decoded.protocol_name,
                                        priority=Priority.CRITICAL.value,
                                        category=Category.C2.value,
                                        details={
                                            "interval_mean_sec": round(mean, 2),
                                            "jitter_ratio": round(jitter, 4),
                                        }
                                    )

        if det:
            self._detection_count += 1
            if det.is_alert:
                self._alert_count += 1
                if self._on_flush:
                    try:
                        self._on_flush(det)
                    except Exception:
                        pass

        # Periodic flush state để tránh alerted_keys phình to
        if ts - self._last_flush > self.flush_interval_sec:
            self._alerted_keys.clear()
            self._last_flush = ts

        return det

    def health_check(self) -> bool:
        # State quá to -> suspect memory leak
        return len(self._alerted_keys) < 100_000


# For auto-discovery: phải export cả 2
__all__ = ['DummyModule', 'DummyLiveModule']
