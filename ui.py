from __future__ import annotations

import os
import queue
import socket
import sys
import threading
from datetime import datetime
from pathlib import Path

import customtkinter as ctk

from engine import PacketProcessor
from logger import setup_logger
from rules import RuleEngine
from sniffer import PacketInfo, SnifferController

BLACKLIST_PATH = Path("blacklist.txt")


def ensure_root() -> None:
    if os.geteuid() != 0:
        print("This program must be run as root. Try: sudo ./run.sh")
        sys.exit(1)


class FirewallUI(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        self.title("Personal Firewall")
        self.geometry("1100x700")
        self.minsize(980, 620)

        self._colors = {
            "bg": "#120813",
            "panel": "#1a0f23",
            "panel_alt": "#21112f",
            "accent": "#8b5cf6",
            "accent_soft": "#a78bfa",
            "text": "#f1e9ff",
            "muted": "#b9a6d9",
            "danger": "#ff6b81",
            "success": "#5eead4",
        }

        self.configure(fg_color=self._colors["bg"])

        self._packet_queue: queue.Queue[PacketInfo] = queue.Queue()
        self._dns_queue: queue.Queue[str] = queue.Queue()
        self._dns_results: queue.Queue[tuple[str, str | None]] = queue.Queue()
        self._dns_pending: set[str] = set()
        self._ip_name_cache: dict[str, str | None] = {}

        self._rules = RuleEngine()
        self._rules.load_blacklist(BLACKLIST_PATH)
        self._logger = setup_logger()
        self._processor = PacketProcessor(self._rules, self._logger)
        self._sniffer = SnifferController(self._enqueue_packet)

        self._stats = {
            "total": 0,
            "allowed": 0,
            "blocked": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
        }

        self._build_ui()
        self._start_dns_thread()
        self._poll_queues()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        ctk.set_appearance_mode("dark")

        header = ctk.CTkFrame(self, fg_color=self._colors["panel"], corner_radius=16)
        header.pack(fill="x", padx=20, pady=(20, 10))

        title = ctk.CTkLabel(
            header,
            text="Personal Firewall",
            font=("Space Grotesk", 22, "bold"),
            text_color=self._colors["text"],
        )
        title.pack(side="left", padx=16, pady=12)

        self._status_label = ctk.CTkLabel(
            header,
            text="Stopped",
            font=("Space Grotesk", 14, "bold"),
            text_color=self._colors["danger"],
        )
        self._status_label.pack(side="right", padx=16)

        tabview = ctk.CTkTabview(
            self,
            fg_color=self._colors["panel"],
            segmented_button_fg_color=self._colors["panel_alt"],
            segmented_button_selected_color=self._colors["accent"],
            segmented_button_selected_hover_color=self._colors["accent_soft"],
            segmented_button_unselected_color=self._colors["panel_alt"],
            text_color=self._colors["text"],
        )
        tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        monitor_tab = tabview.add("Monitor")
        blacklist_tab = tabview.add("Blacklist")

        control_bar = ctk.CTkFrame(monitor_tab, fg_color=self._colors["panel_alt"], corner_radius=12)
        control_bar.pack(fill="x", padx=16, pady=16)

        self._start_button = ctk.CTkButton(
            control_bar,
            text="Start Capture",
            fg_color=self._colors["accent"],
            hover_color=self._colors["accent_soft"],
            text_color=self._colors["text"],
            command=self._toggle_capture,
        )
        self._start_button.pack(side="left", padx=12, pady=12)

        clear_button = ctk.CTkButton(
            control_bar,
            text="Clear Log",
            fg_color=self._colors["panel"],
            hover_color=self._colors["panel_alt"],
            text_color=self._colors["text"],
            command=self._clear_log,
        )
        clear_button.pack(side="left", padx=12)

        reload_button = ctk.CTkButton(
            control_bar,
            text="Reload Blacklist",
            fg_color=self._colors["panel"],
            hover_color=self._colors["panel_alt"],
            text_color=self._colors["text"],
            command=self._reload_blacklist,
        )
        reload_button.pack(side="left", padx=12)

        stats_frame = ctk.CTkFrame(monitor_tab, fg_color=self._colors["panel"], corner_radius=16)
        stats_frame.pack(fill="x", padx=16, pady=(0, 16))

        self._stat_labels: dict[str, ctk.CTkLabel] = {}
        for label, key in [
            ("Total", "total"),
            ("Allowed", "allowed"),
            ("Blocked", "blocked"),
            ("TCP", "tcp"),
            ("UDP", "udp"),
            ("ICMP", "icmp"),
            ("Other", "other"),
        ]:
            container = ctk.CTkFrame(stats_frame, fg_color=self._colors["panel_alt"], corner_radius=12)
            container.pack(side="left", padx=10, pady=12, expand=True, fill="x")

            label_widget = ctk.CTkLabel(
                container,
                text=label,
                font=("Space Grotesk", 12, "bold"),
                text_color=self._colors["muted"],
            )
            label_widget.pack(pady=(10, 4))

            value_widget = ctk.CTkLabel(
                container,
                text="0",
                font=("Space Grotesk", 18, "bold"),
                text_color=self._colors["text"],
            )
            value_widget.pack(pady=(0, 10))
            self._stat_labels[key] = value_widget

        log_frame = ctk.CTkFrame(monitor_tab, fg_color=self._colors["panel"], corner_radius=16)
        log_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self._log_box = ctk.CTkTextbox(
            log_frame,
            fg_color=self._colors["panel_alt"],
            text_color=self._colors["text"],
            font=("JetBrains Mono", 12),
            corner_radius=12,
        )
        self._log_box.pack(fill="both", expand=True, padx=12, pady=12)
        self._log_box.configure(state="disabled")

        blacklist_frame = ctk.CTkFrame(blacklist_tab, fg_color=self._colors["panel"], corner_radius=16)
        blacklist_frame.pack(fill="both", expand=True, padx=16, pady=16)

        blacklist_label = ctk.CTkLabel(
            blacklist_frame,
            text="Blacklist",
            font=("Space Grotesk", 14, "bold"),
            text_color=self._colors["text"],
        )
        blacklist_label.pack(anchor="w", padx=12, pady=(12, 4))

        self._blacklist_box = ctk.CTkTextbox(
            blacklist_frame,
            fg_color=self._colors["panel_alt"],
            text_color=self._colors["text"],
            font=("JetBrains Mono", 12),
            corner_radius=12,
        )
        self._blacklist_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._blacklist_box.insert("1.0", BLACKLIST_PATH.read_text(encoding="utf-8") if BLACKLIST_PATH.exists() else "")

        save_button = ctk.CTkButton(
            blacklist_frame,
            text="Save Blacklist",
            fg_color=self._colors["accent"],
            hover_color=self._colors["accent_soft"],
            text_color=self._colors["text"],
            command=self._save_blacklist,
        )
        save_button.pack(anchor="e", padx=12, pady=(0, 12))

    def _enqueue_packet(self, info: PacketInfo) -> None:
        self._packet_queue.put(info)

    def _poll_queues(self) -> None:
        processed = False
        while True:
            try:
                info = self._packet_queue.get_nowait()
            except queue.Empty:
                break
            processed = True
            result = self._processor.handle(info)
            self._update_stats(result)
            self._append_log(result)

        while True:
            try:
                ip, name = self._dns_results.get_nowait()
            except queue.Empty:
                break
            self._ip_name_cache[ip] = name

        if processed:
            self._refresh_status()

        self.after(150, self._poll_queues)

    def _append_log(self, result) -> None:
        src_name = self._get_hostname(result.src_ip)
        dst_name = self._get_hostname(result.dst_ip)
        src_display = f"{result.src_ip} ({src_name})" if src_name else result.src_ip
        dst_display = f"{result.dst_ip} ({dst_name})" if dst_name else result.dst_ip

        timestamp = datetime.now().strftime("%H:%M:%S")
        line = (
            f"[{timestamp}] {result.action:<5} {result.direction:<7} {result.protocol:<4} "
            f"{src_display}:{result.src_port or '-'} -> {dst_display}:{result.dst_port or '-'}\n"
        )

        self._log_box.configure(state="normal")
        self._log_box.insert("end", line)
        self._log_box.see("end")
        self._log_box.configure(state="disabled")

    def _get_hostname(self, ip: str) -> str | None:
        if ip in self._ip_name_cache:
            return self._ip_name_cache[ip]
        if ip not in self._dns_pending:
            self._dns_pending.add(ip)
            self._dns_queue.put(ip)
        return None

    def _start_dns_thread(self) -> None:
        def _worker() -> None:
            while True:
                ip = self._dns_queue.get()
                if ip is None:
                    return
                name = None
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except OSError:
                    name = None
                self._dns_results.put((ip, name))
                self._dns_pending.discard(ip)

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()

    def _update_stats(self, result) -> None:
        self._stats["total"] += 1
        if result.action == "BLOCK":
            self._stats["blocked"] += 1
        else:
            self._stats["allowed"] += 1

        protocol = result.protocol.lower()
        if protocol == "tcp":
            self._stats["tcp"] += 1
        elif protocol == "udp":
            self._stats["udp"] += 1
        elif protocol == "icmp":
            self._stats["icmp"] += 1
        else:
            self._stats["other"] += 1

        for key, label in self._stat_labels.items():
            label.configure(text=str(self._stats[key]))

    def _toggle_capture(self) -> None:
        if self._sniffer.is_running:
            self._sniffer.stop()
            self._processor.cleanup()
        else:
            self._sniffer.start()
        self._refresh_status()

    def _refresh_status(self) -> None:
        if self._sniffer.is_running:
            self._status_label.configure(text="Running", text_color=self._colors["success"])
            self._start_button.configure(text="Stop Capture")
        else:
            self._status_label.configure(text="Stopped", text_color=self._colors["danger"])
            self._start_button.configure(text="Start Capture")

    def _clear_log(self) -> None:
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")
        for key in self._stats:
            self._stats[key] = 0
        for key, label in self._stat_labels.items():
            label.configure(text="0")

    def _reload_blacklist(self) -> None:
        self._rules.blocked_ips.clear()
        self._rules.load_blacklist(BLACKLIST_PATH)

    def _save_blacklist(self) -> None:
        content = self._blacklist_box.get("1.0", "end").strip() + "\n"
        BLACKLIST_PATH.write_text(content, encoding="utf-8")
        self._reload_blacklist()

    def _on_close(self) -> None:
        if self._sniffer.is_running:
            self._sniffer.stop()
        self._processor.cleanup()
        self._dns_queue.put(None)
        self.destroy()


def main() -> None:
    ensure_root()
    app = FirewallUI()
    app.mainloop()


if __name__ == "__main__":
    main()
