import logging
from datetime import datetime
from pathlib import Path

LOG_PATH = Path("firewall.log")


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("personal_firewall")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def log_event(logger: logging.Logger, action: str, direction: str, protocol: str, src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None) -> None:
    timestamp = datetime.utcnow().isoformat()
    src_port_str = str(src_port) if src_port is not None else "-"
    dst_port_str = str(dst_port) if dst_port is not None else "-"
    entry = f"{timestamp} action={action} direction={direction} proto={protocol} src={src_ip}:{src_port_str} dst={dst_ip}:{dst_port_str}"
    logger.info(entry)
