"""Entrypoint: capture trên NIC → KafkaPcapSegmenter → Kafka.

Dùng core.capture.CaptureEngine (đã có sẵn từ SNIFF). Callback API thực tế:
- CaptureEngine(interface=..., bpf_filter=..., on_packet_filtered=...)
- on_packet_filtered nhận PacketInfo(ts_sec, ts_usec, data, ...)
"""
import logging
import os
import signal
import sys
import time

from kafka import KafkaProducer

from .config import load_config
from .kafka_segmenter import KafkaPcapSegmenter


def _make_producer(bootstrap, max_segment_bytes):
    return KafkaProducer(
        bootstrap_servers=bootstrap,
        max_request_size=max_segment_bytes + (1 << 20),
        linger_ms=200,
        acks=1,
    )


def build_engine_and_segmenter(cfg, producer):
    """Trả về (engine, segmenter) đã cấu hình theo config.

    CaptureEngine thật cần chạy trong thread; hàm này chỉ wire-up.
    """
    seg = KafkaPcapSegmenter(
        producer,
        cfg["kafka"]["topic"],
        cfg["capture"]["interface"],
        segment_seconds=cfg["kafka"]["segment_seconds"],
        segment_max_bytes=cfg["kafka"]["segment_max_bytes"],
    )

    def on_pkt(pi):
        seg.add_packet(pi.ts_sec, pi.ts_usec, pi.data)

    # Late import: tránh scapy nạp khi chỉ cần config.
    from core.capture import CaptureEngine

    engine = CaptureEngine(
        interface=cfg["capture"]["interface"],
        bpf_filter=cfg["capture"]["bpf"],
        on_packet_filtered=on_pkt,
    )
    return engine, seg


def _install_structured_logging() -> None:
    """Configure logging with a structured format.

    The format string deliberately does NOT include custom fields so that
    third-party loggers (kafka, scapy) don't crash trying to populate them.
    Our own log lines that carry segment_id include it INLINE in the message
    via the _SegmentAdapter helper.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )


class _SegmentAdapter(logging.LoggerAdapter):
    """LoggerAdapter that prefixes the message with [segment=<sid>] so
    structured queries (grep / journalctl) can extract it.
    """

    def process(self, msg, kwargs):
        sid = self.extra.get("segment_id", "-")
        return f"[segment={sid}] {msg}", kwargs


def main():
    _install_structured_logging()
    cfg = load_config()
    producer = _make_producer(
        cfg["kafka"]["bootstrap"], cfg["kafka"]["segment_max_bytes"]
    )
    engine, seg = build_engine_and_segmenter(cfg, producer)

    last_segment_id = "-"
    n_segments = 0
    n_pkts = 0
    t_last_hb = time.monotonic()
    hb_every_sec = float(os.environ.get("PRODUCER_HEARTBEAT_EVERY_SEC", "60"))

    def _emit_heartbeat(force: bool = False) -> None:
        nonlocal t_last_hb, n_segments, n_pkts
        now_mono = time.monotonic()
        if not force and (now_mono - t_last_hb) < hb_every_sec:
            return
        _SegmentAdapter(logging.getLogger("producer"), {"segment_id": "-"}).info(
            "heartbeat segments_published=%d pkts_buffered=%d last_segment=%s uptime_sec=%.1f",
            n_segments, n_pkts, last_segment_id, now_mono,
        )
        t_last_hb = now_mono

    # Patch segmenter to log structured flush events.
    original_flush = seg.flush
    def logged_flush():
        nonlocal last_segment_id, n_segments
        sid = original_flush()
        if sid is not None:
            n_segments += 1
            last_segment_id = sid
            _SegmentAdapter(logging.getLogger("producer"), {"segment_id": sid}).info(
                "published segment to Kafka topic=%s n_pkts=%d",
                seg.topic, len(seg._pkts) if False else 0,  # placeholder; seg resets state
            )
            _emit_heartbeat(force=True)
        return sid
    seg.flush = logged_flush  # type: ignore[assignment]

    def shutdown(*_):
        _SegmentAdapter(logging.getLogger("producer"), {"segment_id": "-"}).info(
            "producer: shutdown signal")
        try:
            engine.stop()
        except Exception as exc:
            logging.error("engine.stop: %s", exc)
        try:
            sid = seg.flush()
            if sid:
                _SegmentAdapter(logging.getLogger("producer"), {"segment_id": sid}).info(
                    "flushed final segment %s", sid)
        except Exception as exc:
            logging.error("seg.flush: %s", exc)
        try:
            producer.flush(timeout=5)
            producer.close(timeout=5)
        except Exception as exc:
            logging.error("producer.close: %s", exc)
        _emit_heartbeat(force=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    _SegmentAdapter(logging.getLogger("producer"), {"segment_id": "-"}).info(
        "producer starting | interface=%s topic=%s segment_seconds=%d max_bytes=%d",
        cfg["capture"]["interface"], cfg["kafka"]["topic"],
        cfg["kafka"]["segment_seconds"], cfg["kafka"]["segment_max_bytes"],
    )

    engine.start()
    # Sniffer chạy trong background; main thread chờ signal.
    signal.pause()


if __name__ == "__main__":
    main()
