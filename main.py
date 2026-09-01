# -*- coding: utf-8 -*-
"""
اسکنر کلودفلر - Ultimate Proxy & Cloudflare IP Scanner
KivyMD (Material Design 3) Android application.

Three-stage concurrent scanning engine (TCP -> Real HTTP -> Speed),
multi-protocol parsing (VLESS / VMess / Trojan / SS), local SQLite
history, and export/share hub. Fully Persian (Farsi) UI.
"""

import base64
import binascii
import ipaddress
import json
import os
import re
import socket
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from kivy.clock import Clock, mainthread
from kivy.core.clipboard import Clipboard
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import (
    BooleanProperty,
    ListProperty,
    NumericProperty,
    ObjectProperty,
    StringProperty,
)
from kivy.uix.boxlayout import BoxLayout

from kivymd.app import MDApp
from kivymd.uix.behaviors import RoundedRectangularElevationBehavior
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import (
    MDFillRoundFlatButton,
    MDFlatButton,
    MDFloatingActionButtonSpeedDial,
    MDIconButton,
    MDRaisedButton,
)
from kivymd.uix.card import MDCard
from kivymd.uix.dialog import MDDialog
from kivymd.uix.label import MDLabel
from kivymd.uix.list import OneLineListItem
from kivymd.uix.snackbar import Snackbar

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

APP_DB_NAME = "cfscanner_history.db"
CF_TRACE_PATH = "/cdn-cgi/trace"
CF_GENERATE_204_PATH = "/generate_204"
SPEED_TEST_PATH = "/__down?bytes=1048576"  # 1MB payload style endpoint
DEFAULT_TCP_TIMEOUT = 1.5
DEFAULT_HTTP_TIMEOUT = 3.0
DEFAULT_SPEED_TIMEOUT = 6.0
REAL_PING_THRESHOLD_FOR_SPEEDTEST_MS = 800
MAX_WORKERS_DEFAULT = 50

PROTOCOL_COLORS = {
    "vless": (0.20, 0.60, 0.86, 1),
    "vmess": (0.55, 0.36, 0.96, 1),
    "trojan": (0.90, 0.30, 0.30, 1),
    "ss": (0.20, 0.70, 0.45, 1),
}

PROTOCOL_LABELS_FA = {
    "vless": "وی‌لس",
    "vmess": "وی‌مس",
    "trojan": "تروجان",
    "ss": "شادوساکس",
}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

class ProxyConfig:
    """Represents a single parsed proxy configuration."""

    __slots__ = (
        "protocol", "address", "port", "uuid_or_password", "sni",
        "remark", "raw", "network", "extra",
        "tcp_ok", "real_ping_ms", "speed_mbps", "tested",
    )

    def __init__(self, protocol, address, port, uuid_or_password="",
                 sni="", remark="", raw="", network="tcp", extra=None):
        self.protocol = protocol
        self.address = address
        self.port = int(port) if port else 0
        self.uuid_or_password = uuid_or_password
        self.sni = sni or address
        self.remark = remark or f"{protocol}-{address}:{port}"
        self.raw = raw
        self.network = network
        self.extra = extra or {}
        self.tcp_ok = False
        self.real_ping_ms = None
        self.speed_mbps = None
        self.tested = False

    def as_row(self):
        return (
            self.protocol, self.address, self.port, self.uuid_or_password,
            self.sni, self.remark, self.raw,
            self.real_ping_ms or -1, self.speed_mbps or 0.0,
            int(time.time()),
        )


# --------------------------------------------------------------------------
# Ultimate protocol parser
# --------------------------------------------------------------------------

class ConfigParser:
    """Parses vless://, vmess://, trojan://, ss:// URIs plus CIDR ranges
    and raw / base64 subscription blobs."""

    VLESS_TROJAN_RE = re.compile(
        r"^(?P<scheme>vless|trojan)://"
        r"(?P<userinfo>[^@]+)@"
        r"(?P<host>[^:/?#]+):"
        r"(?P<port>\d+)"
        r"(?:\?(?P<query>[^#]*))?"
        r"(?:#(?P<remark>.*))?$"
    )

    SS_RE = re.compile(
        r"^ss://(?P<blob>[^#?]+)(?:\?[^#]*)?(?:#(?P<remark>.*))?$"
    )

    CIDR_RE = re.compile(r"^\s*\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\s*$")

    @staticmethod
    def _b64_decode(data):
        data = data.strip()
        data += "=" * (-len(data) % 4)
        try:
            return base64.urlsafe_b64decode(data.encode()).decode(
                "utf-8", errors="ignore"
            )
        except (binascii.Error, ValueError):
            try:
                return base64.b64decode(data.encode()).decode(
                    "utf-8", errors="ignore"
                )
            except Exception:
                return ""

    @classmethod
    def parse_vless_or_trojan(cls, line):
        m = cls.VLESS_TROJAN_RE.match(line.strip())
        if not m:
            return None
        scheme = m.group("scheme")
        userinfo = urllib.parse.unquote(m.group("userinfo"))
        host = m.group("host")
        port = m.group("port")
        query = urllib.parse.parse_qs(m.group("query") or "")
        remark = urllib.parse.unquote(m.group("remark") or "")
        sni = (query.get("sni", [""])[0] or query.get("host", [""])[0] or host)
        network = query.get("type", ["tcp"])[0]
        return ProxyConfig(
            protocol=scheme,
            address=host,
            port=port,
            uuid_or_password=userinfo,
            sni=sni,
            remark=remark,
            raw=line.strip(),
            network=network,
            extra={k: v[0] for k, v in query.items()},
        )

    @classmethod
    def parse_vmess(cls, line):
        try:
            payload = line.strip()[len("vmess://"):]
            decoded = cls._b64_decode(payload)
            data = json.loads(decoded)
        except Exception:
            return None
        return ProxyConfig(
            protocol="vmess",
            address=data.get("add", ""),
            port=data.get("port", 0),
            uuid_or_password=data.get("id", ""),
            sni=data.get("sni") or data.get("host") or data.get("add", ""),
            remark=data.get("ps", ""),
            raw=line.strip(),
            network=data.get("net", "tcp"),
            extra=data,
        )

    @classmethod
    def parse_ss(cls, line):
        m = cls.SS_RE.match(line.strip())
        if not m:
            return None
        blob = m.group("blob")
        remark = urllib.parse.unquote(m.group("remark") or "")
        if "@" in blob:
            userinfo_part, hostport = blob.rsplit("@", 1)
            userinfo = cls._b64_decode(userinfo_part) or userinfo_part
        else:
            decoded = cls._b64_decode(blob)
            if "@" not in decoded:
                return None
            userinfo, hostport = decoded.rsplit("@", 1)
        if ":" not in hostport:
            return None
        host, port = hostport.rsplit(":", 1)
        method_pass = userinfo.split(":", 1)
        password = method_pass[1] if len(method_pass) > 1 else ""
        return ProxyConfig(
            protocol="ss",
            address=host,
            port=port,
            uuid_or_password=password,
            sni=host,
            remark=remark,
            raw=line.strip(),
        )

    @classmethod
    def parse_cidr(cls, line):
        """Expand a CIDR block into individual bare-IP pseudo configs
        (protocol='ip', tested against port 443 by default)."""
        line = line.strip()
        if not cls.CIDR_RE.match(line):
            return []
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            return []
        results = []
        # Guard against absurdly large ranges (Android device safety).
        max_hosts = 1024
        for i, ip in enumerate(network.hosts() if network.num_addresses > 1
                                else [network.network_address]):
            if i >= max_hosts:
                break
            results.append(ProxyConfig(
                protocol="ip", address=str(ip), port=443,
                remark=f"IP-{ip}",
            ))
        return results

    @classmethod
    def parse_line(cls, line):
        line = line.strip()
        if not line:
            return None
        if line.startswith("vless://") or line.startswith("trojan://"):
            return cls.parse_vless_or_trojan(line)
        if line.startswith("vmess://"):
            return cls.parse_vmess(line)
        if line.startswith("ss://"):
            return cls.parse_ss(line)
        return None

    @classmethod
    def parse_bulk(cls, text):
        """Accepts raw multi-line text, a base64 blob, or a subscription
        URL's fetched body, and returns a list of ProxyConfig objects."""
        text = text.strip()
        if not text:
            return []

        configs = []

        # 1) Try each line as CIDR first.
        for raw_line in text.splitlines():
            configs.extend(cls.parse_cidr(raw_line))

        # 2) If the whole blob looks like base64 (no scheme, no newlines
        #    heavy with '://'), try decoding it wholesale (subscription style).
        if "://" not in text:
            decoded = cls._b64_decode(text)
            if decoded and "://" in decoded:
                text = decoded

        # 3) Parse line by line for URI schemes.
        for raw_line in text.splitlines():
            cfg = cls.parse_line(raw_line)
            if cfg:
                configs.append(cfg)

        return configs

    @staticmethod
    def fetch_subscription(url, timeout=8):
        req = urllib.request.Request(url, headers={"User-Agent": "cfpersianscan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="ignore")


# --------------------------------------------------------------------------
# SQLite storage
# --------------------------------------------------------------------------

class Database:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.path, check_same_thread=False)

    def _init_db(self):
        with self._lock, self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol TEXT,
                    address TEXT,
                    port INTEGER,
                    secret TEXT,
                    sni TEXT,
                    remark TEXT,
                    raw TEXT UNIQUE,
                    ping_ms INTEGER,
                    speed_mbps REAL,
                    created_at INTEGER
                )
            """)
            conn.commit()

    def save_config(self, cfg: ProxyConfig):
        with self._lock, self._connect() as conn:
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO history
                       (protocol, address, port, secret, sni, remark, raw,
                        ping_ms, speed_mbps, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    cfg.as_row(),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                pass

    def get_history(self, query=""):
        with self._lock, self._connect() as conn:
            if query:
                like = f"%{query}%"
                cur = conn.execute(
                    """SELECT protocol, address, port, remark, ping_ms,
                              speed_mbps, raw FROM history
                       WHERE remark LIKE ? OR address LIKE ?
                       ORDER BY created_at DESC""",
                    (like, like),
                )
            else:
                cur = conn.execute(
                    """SELECT protocol, address, port, remark, ping_ms,
                              speed_mbps, raw FROM history
                       ORDER BY created_at DESC"""
                )
            return cur.fetchall()

    def clear_history(self):
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM history")
            conn.commit()


# --------------------------------------------------------------------------
# Three-stage concurrent scanning engine
# --------------------------------------------------------------------------

class ScannerEngine:
    """
    Stage 1 - TCP ping: raw socket connect.
    Stage 2 - Real HTTP ping: HTTP GET through the target IP with the
              config's SNI/Host, hitting Cloudflare's generate_204 endpoint.
    Stage 3 - Speed test: download ~1MB and measure throughput, only for
              configs whose real ping beat the threshold.
    """

    def __init__(self, max_workers=MAX_WORKERS_DEFAULT,
                 tcp_timeout=DEFAULT_TCP_TIMEOUT,
                 http_timeout=DEFAULT_HTTP_TIMEOUT,
                 speed_timeout=DEFAULT_SPEED_TIMEOUT):
        self.max_workers = max_workers
        self.tcp_timeout = tcp_timeout
        self.http_timeout = http_timeout
        self.speed_timeout = speed_timeout
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    def reset(self):
        self._stop_flag.clear()

    # ---- Stage 1 ----
    def tcp_ping(self, cfg: ProxyConfig):
        try:
            start = time.time()
            with socket.create_connection(
                (cfg.address, cfg.port), timeout=self.tcp_timeout
            ):
                pass
            cfg.tcp_ok = True
            return (time.time() - start) * 1000
        except OSError:
            cfg.tcp_ok = False
            return None

    # ---- Stage 2 ----
    def real_http_ping(self, cfg: ProxyConfig):
        """Connects directly to cfg.address:port (as Cloudflare typically
        listens on 80/443) and issues a GET for /generate_204, sending the
        config's SNI/Host header — verifying real HTTP-layer reachability,
        not just an open TCP port."""
        try:
            scheme = "https" if cfg.port in (443, 2053, 2083, 2087, 2096) else "http"
            url = f"{scheme}://{cfg.address}:{cfg.port}{CF_GENERATE_204_PATH}"
            req = urllib.request.Request(
                url,
                headers={
                    "Host": cfg.sni or cfg.address,
                    "User-Agent": "Mozilla/5.0 (cfpersianscan)",
                },
            )
            start = time.time()
            with urllib.request.urlopen(req, timeout=self.http_timeout) as resp:
                resp.read(64)
                elapsed_ms = (time.time() - start) * 1000
                if resp.status in (204, 200, 301, 302):
                    return elapsed_ms
            return None
        except Exception:
            return None

    # ---- Stage 3 ----
    def speed_test(self, cfg: ProxyConfig):
        try:
            scheme = "https" if cfg.port in (443, 2053, 2083, 2087, 2096) else "http"
            url = f"{scheme}://{cfg.address}:{cfg.port}/__down?bytes=1048576"
            req = urllib.request.Request(
                url,
                headers={
                    "Host": cfg.sni or cfg.address,
                    "User-Agent": "Mozilla/5.0 (cfpersianscan)",
                },
            )
            start = time.time()
            total = 0
            with urllib.request.urlopen(req, timeout=self.speed_timeout) as resp:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total >= 1_048_576:
                        break
            elapsed = max(time.time() - start, 0.001)
            return (total / 1024 / 1024) / elapsed  # MB/s
        except Exception:
            return None

    def test_one(self, cfg: ProxyConfig):
        if self._stop_flag.is_set():
            return cfg
        tcp_ms = self.tcp_ping(cfg)
        cfg.tested = True
        if tcp_ms is None:
            return cfg
        if self._stop_flag.is_set():
            return cfg
        real_ms = self.real_http_ping(cfg)
        cfg.real_ping_ms = round(real_ms) if real_ms is not None else None
        if real_ms is not None and real_ms < REAL_PING_THRESHOLD_FOR_SPEEDTEST_MS:
            if not self._stop_flag.is_set():
                speed = self.speed_test(cfg)
                cfg.speed_mbps = round(speed, 2) if speed else None
        return cfg

    def scan(self, configs, on_result, on_progress, on_done):
        """Runs the full pipeline concurrently. Callbacks are invoked on
        the calling (background) thread; the caller is responsible for
        marshalling to the UI thread (handled by the App via @mainthread)."""
        self.reset()
        total = len(configs)
        completed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.test_one, c): c for c in configs}
            for future in as_completed(futures):
                if self._stop_flag.is_set():
                    break
                cfg = future.result()
                completed += 1
                on_result(cfg)
                on_progress(completed, total)
        on_done()


# --------------------------------------------------------------------------
# KV layout (Material Design 3 look & feel, Persian strings)
# --------------------------------------------------------------------------

KV = """
#:import dp kivy.metrics.dp

<PingLabel@MDLabel>:
    halign: "right"
    font_style: "Caption"
    size_hint_y: None
    height: self.texture_size[1]

<ResultCard>:
    orientation: "vertical"
    size_hint_y: None
    height: dp(112)
    padding: dp(12), dp(8)
    spacing: dp(4)
    radius: [16, 16, 16, 16]
    elevation: 1
    md_bg_color: app.theme_cls.bg_light

    MDBoxLayout:
        size_hint_y: None
        height: dp(28)
        MDLabel:
            text: root.protocol_label
            bold: True
            halign: "right"
            theme_text_color: "Custom"
            text_color: root.protocol_color
        MDLabel:
            text: root.ping_text
            halign: "left"
            theme_text_color: "Custom"
            text_color: root.ping_color
            size_hint_x: 0.4

    MDLabel:
        text: root.remark_text
        halign: "right"
        font_style: "Subtitle2"
        shorten: True
        shorten_from: "right"

    MDLabel:
        text: root.address_text
        halign: "right"
        font_style: "Caption"
        theme_text_color: "Secondary"

    MDBoxLayout:
        size_hint_y: None
        height: dp(30)
        MDLabel:
            text: root.speed_text
            halign: "right"
            font_style: "Caption"
        MDIconButton:
            icon: "content-copy"
            size_hint_x: None
            width: dp(36)
            on_release: root.on_copy()

<HistoryRow@MDCard>:
    orientation: "vertical"
    size_hint_y: None
    height: dp(84)
    padding: dp(10), dp(6)
    radius: [14, 14, 14, 14]
    elevation: 0.5
    md_bg_color: app.theme_cls.bg_light

MDBoxLayout:
    orientation: "vertical"

    MDTopAppBar:
        title: "اسکنر پروکسی و آی‌پی کلودفلر"
        right_action_items: [["theme-light-dark", lambda x: app.toggle_theme()]]
        elevation: 4
        specific_text_color: 1, 1, 1, 1
        md_bg_color: app.theme_cls.primary_color

    MDBottomNavigation:
        id: bottom_nav
        panel_color: app.theme_cls.bg_darkest
        text_color_active: app.theme_cls.primary_color

        MDBottomNavigationItem:
            name: "tab_scanner"
            text: "اسکنر"
            icon: "radar"

            RelativeLayout:
                id: scanner_relative

                MDBoxLayout:
                    orientation: "vertical"
                    padding: dp(12)
                    spacing: dp(10)
                    pos_hint: {"top": 1}
                    size_hint_y: 1

                    MDTextField:
                        id: input_field
                        hint_text: "آی‌پی، CIDR، ساب‌لینک یا کانفیگ را وارد کنید"
                        multiline: True
                        max_height: dp(110)
                        mode: "rectangle"
                        halign: "right"
                        size_hint_y: None
                        height: dp(110)

                    MDBoxLayout:
                        size_hint_y: None
                        height: dp(48)
                        spacing: dp(8)

                        MDRaisedButton:
                            text: "شروع اسکن"
                            icon: "play"
                            md_bg_color: 0.20, 0.60, 0.35, 1
                            on_release: app.start_scan()

                        MDRaisedButton:
                            text: "توقف"
                            icon: "stop"
                            md_bg_color: 0.75, 0.20, 0.20, 1
                            on_release: app.stop_scan()

                        MDIconButton:
                            icon: "content-paste"
                            on_release: app.paste_from_clipboard()

                    MDBoxLayout:
                        size_hint_y: None
                        height: dp(24)
                        MDLabel:
                            id: progress_label
                            text: "آماده برای اسکن"
                            halign: "right"
                            font_style: "Caption"

                    MDProgressBar:
                        id: progress_bar
                        value: 0
                        max: 100

                    ScrollView:
                        MDBoxLayout:
                            id: results_box
                            orientation: "vertical"
                            spacing: dp(8)
                            size_hint_y: None
                            height: self.minimum_height
                            padding: 0, dp(4)

        MDBottomNavigationItem:
            name: "tab_history"
            text: "تاریخچه"
            icon: "history"

            MDBoxLayout:
                orientation: "vertical"
                padding: dp(12)
                spacing: dp(10)

                MDBoxLayout:
                    size_hint_y: None
                    height: dp(48)
                    spacing: dp(8)

                    MDTextField:
                        id: search_field
                        hint_text: "جستجو بر اساس نام یا آی‌پی"
                        halign: "right"
                        on_text: app.search_history(self.text)

                    MDIconButton:
                        icon: "delete-sweep"
                        on_release: app.clear_history_confirm()

                ScrollView:
                    MDBoxLayout:
                        id: history_box
                        orientation: "vertical"
                        spacing: dp(8)
                        size_hint_y: None
                        height: self.minimum_height
                        padding: 0, dp(4)

        MDBottomNavigationItem:
            name: "tab_settings"
            text: "تنظیمات"
            icon: "cog"

            MDBoxLayout:
                orientation: "vertical"
                padding: dp(20)
                spacing: dp(18)

                MDBoxLayout:
                    size_hint_y: None
                    height: dp(48)
                    MDLabel:
                        text: "حالت تیره / روشن"
                        halign: "right"
                    MDSwitch:
                        id: theme_switch
                        active: app.theme_cls.theme_style == "Dark"
                        on_active: app.set_dark_mode(self.active)

                MDLabel:
                    text: "تعداد نخ‌های همزمان (Threads)"
                    halign: "right"
                    size_hint_y: None
                    height: self.texture_size[1]

                MDSlider:
                    id: threads_slider
                    min: 5
                    max: 100
                    value: 50
                    hint: True
                    on_value: app.on_threads_change(self.value)

                MDLabel:
                    text: "زمان انتظار اتصال (ثانیه)"
                    halign: "right"
                    size_hint_y: None
                    height: self.texture_size[1]

                MDSlider:
                    id: timeout_slider
                    min: 1
                    max: 10
                    value: 1.5
                    hint: True
                    on_value: app.on_timeout_change(self.value)

                MDLabel:
                    id: settings_info_label
                    text: "نخ‌ها: 50   |   تایم‌اوت: 1.5 ثانیه"
                    halign: "right"
                    size_hint_y: None
                    height: self.texture_size[1]

                Widget:
"""


# --------------------------------------------------------------------------
# Widget classes bound in KV
# --------------------------------------------------------------------------

class ResultCard(MDCard, RoundedRectangularElevationBehavior):
    protocol_label = StringProperty("")
    protocol_color = ListProperty([1, 1, 1, 1])
    remark_text = StringProperty("")
    address_text = StringProperty("")
    ping_text = StringProperty("")
    ping_color = ListProperty([1, 1, 1, 1])
    speed_text = StringProperty("")
    config_raw = StringProperty("")

    def on_copy(self):
        Clipboard.copy(self.config_raw)
        Snackbar(text="کانفیگ کپی شد").open()


# --------------------------------------------------------------------------
# Main Application
# --------------------------------------------------------------------------

class CFPersianScanApp(MDApp):

    is_scanning = BooleanProperty(False)

    def build(self):
        self.title = "اسکنر کلودفلر"
        self.theme_cls.material_style = "M3"
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.theme_style = "Dark"

        self.db = Database(self._db_path())
        self.engine = ScannerEngine()
        self._pending_configs = []
        self._scan_thread = None

        root = Builder.load_string(KV)
        return root

    def on_start(self):
        self.refresh_history()
        self._build_export_fab()

    def _build_export_fab(self):
        """FAB speed-dial for the export/share hub, floated over the
        scanner tab's results area."""
        self.export_fab = MDFloatingActionButtonSpeedDial()
        # KivyMD's speed-dial `data` dict maps icon name -> hint text.
        self.export_fab.data = {
            "content-copy": "کپی همه کانفیگ‌ها",
            "content-save": "ذخیره در فایل",
            "link-variant": "تولید لینک سابسکریپشن",
        }
        self.export_fab.root_button_anim = True
        self.export_fab.bg_hint_color = self.theme_cls.primary_color
        self.export_fab.icon = "export-variant"
        self.export_fab.callback = self._on_export_fab_select
        self.root.ids.scanner_relative.add_widget(self.export_fab)

    def _on_export_fab_select(self, instance_button):
        """Called by the speed dial with the pressed stack button; its
        `icon` tells us which export action was chosen."""
        icon = getattr(instance_button, "icon", "")
        if icon == "content-copy":
            self.copy_all_configs()
        elif icon == "content-save":
            self.export_to_file("txt")
        elif icon == "link-variant":
            self.generate_sub_link()
        self.export_fab.close_stack()


    # ---------------- paths ----------------

    def _db_path(self):
        try:
            from android.storage import app_storage_path  # noqa
            base = app_storage_path()
        except Exception:
            base = os.path.expanduser("~")
        return os.path.join(base, APP_DB_NAME)

    def _export_dir(self):
        try:
            from android.storage import primary_external_storage_path  # noqa
            base = primary_external_storage_path()
            path = os.path.join(base, "Download")
            if not os.path.isdir(path):
                path = base
        except Exception:
            path = os.path.expanduser("~")
        return path

    # ---------------- theme ----------------

    def toggle_theme(self):
        self.theme_cls.theme_style = (
            "Light" if self.theme_cls.theme_style == "Dark" else "Dark"
        )

    def set_dark_mode(self, active):
        self.theme_cls.theme_style = "Dark" if active else "Light"

    def on_threads_change(self, value):
        self.engine.max_workers = int(value)
        self._update_settings_label()

    def on_timeout_change(self, value):
        self.engine.tcp_timeout = float(value)
        self._update_settings_label()

    def _update_settings_label(self):
        label = self.root.ids.settings_info_label
        label.text = (
            f"نخ‌ها: {int(self.engine.max_workers)}   |   "
            f"تایم‌اوت: {self.engine.tcp_timeout:.1f} ثانیه"
        )

    # ---------------- clipboard ----------------

    def paste_from_clipboard(self):
        text = Clipboard.paste()
        if not text:
            Snackbar(text="کلیپ‌بورد خالی است").open()
            return
        field = self.root.ids.input_field
        field.text = (field.text + "\n" + text).strip()

    # ---------------- scanning ----------------

    def start_scan(self):
        if self.is_scanning:
            Snackbar(text="اسکن در حال اجراست").open()
            return

        raw_text = self.root.ids.input_field.text.strip()
        if not raw_text:
            Snackbar(text="لطفاً آی‌پی یا کانفیگ وارد کنید").open()
            return

        self.root.ids.results_box.clear_widgets()
        self.root.ids.progress_bar.value = 0
        self.root.ids.progress_label.text = "در حال آماده‌سازی..."

        threading.Thread(target=self._prepare_and_scan, args=(raw_text,),
                          daemon=True).start()

    def _prepare_and_scan(self, raw_text):
        configs = []
        for chunk in raw_text.splitlines():
            chunk = chunk.strip()
            if not chunk:
                continue
            if chunk.startswith("http://") or chunk.startswith("https://"):
                try:
                    body = ConfigParser.fetch_subscription(chunk)
                    configs.extend(ConfigParser.parse_bulk(body))
                except Exception:
                    self._toast_threadsafe(f"خطا در دریافت ساب‌لینک: {chunk}")
                continue
            configs.extend(ConfigParser.parse_bulk(chunk))

        if not configs:
            self._toast_threadsafe("هیچ کانفیگ معتبری پیدا نشد")
            self._set_scanning_state(False)
            return

        self._set_scanning_state(True)
        self._set_progress_label(f"در حال اسکن {len(configs)} مورد...")

        self.engine.scan(
            configs,
            on_result=self._on_result_threadsafe,
            on_progress=self._on_progress_threadsafe,
            on_done=self._on_done_threadsafe,
        )

    def stop_scan(self):
        if not self.is_scanning:
            return
        self.engine.stop()
        self._set_progress_label("در حال توقف...")

    @mainthread
    def _set_scanning_state(self, val):
        self.is_scanning = val

    @mainthread
    def _set_progress_label(self, text):
        self.root.ids.progress_label.text = text

    def _toast_threadsafe(self, text):
        Clock.schedule_once(lambda dt: Snackbar(text=text).open(), 0)

    @mainthread
    def _on_result_threadsafe(self, cfg: ProxyConfig):
        if cfg.tcp_ok and cfg.real_ping_ms is not None:
            self._add_result_card(cfg)
            self.db.save_config(cfg)

    @mainthread
    def _on_progress_threadsafe(self, done, total):
        pct = (done / total) * 100 if total else 0
        self.root.ids.progress_bar.value = pct
        self.root.ids.progress_label.text = f"بررسی شد {done} از {total}"

    @mainthread
    def _on_done_threadsafe(self):
        self._set_scanning_state(False)
        self.root.ids.progress_label.text = "اسکن به پایان رسید"
        self.refresh_history()

    def _add_result_card(self, cfg: ProxyConfig):
        color = PROTOCOL_COLORS.get(cfg.protocol, (0.6, 0.6, 0.6, 1))
        ping = cfg.real_ping_ms or 0
        if ping < 200:
            ping_color = (0.30, 0.80, 0.40, 1)
        elif ping < 500:
            ping_color = (0.95, 0.75, 0.20, 1)
        else:
            ping_color = (0.90, 0.30, 0.30, 1)

        speed_text = (
            f"سرعت: {cfg.speed_mbps} MB/s" if cfg.speed_mbps else "سرعت: نامشخص"
        )

        card = ResultCard(
            protocol_label=PROTOCOL_LABELS_FA.get(cfg.protocol, cfg.protocol.upper()),
            protocol_color=color,
            remark_text=cfg.remark or cfg.address,
            address_text=f"{cfg.address}:{cfg.port}",
            ping_text=f"{ping} ms" if ping else "—",
            ping_color=ping_color,
            speed_text=speed_text,
            config_raw=cfg.raw or "",
        )
        self.root.ids.results_box.add_widget(card)

    # ---------------- history ----------------

    def refresh_history(self):
        rows = self.db.get_history()
        self._render_history(rows)

    def search_history(self, query):
        rows = self.db.get_history(query.strip())
        self._render_history(rows)

    def _render_history(self, rows):
        box = self.root.ids.history_box
        box.clear_widgets()
        for protocol, address, port, remark, ping_ms, speed_mbps, raw in rows:
            item = self._build_history_row(
                protocol, address, port, remark, ping_ms, speed_mbps, raw
            )
            box.add_widget(item)

    def _build_history_row(self, protocol, address, port, remark,
                            ping_ms, speed_mbps, raw):
        row = BoxLayout(
            orientation="vertical", size_hint_y=None, height=dp(74),
            padding=(dp(10), dp(4)),
        )
        top = BoxLayout(size_hint_y=None, height=dp(26))
        title = MDLabel(
            text=f"{PROTOCOL_LABELS_FA.get(protocol, protocol.upper())} | {remark}",
            halign="right",
        )
        copy_btn = MDIconButton(
            icon="content-copy",
            on_release=lambda *_: (Clipboard.copy(raw),
                                    Snackbar(text="کپی شد").open()),
        )
        top.add_widget(title)
        top.add_widget(copy_btn)

        sub = MDLabel(
            text=f"{address}:{port}   |   پینگ: {ping_ms if ping_ms and ping_ms > 0 else '—'} ms"
                 f"   |   سرعت: {speed_mbps or 0} MB/s",
            halign="right",
            font_style="Caption",
        )
        row.add_widget(top)
        row.add_widget(sub)
        return row

    def clear_history_confirm(self):
        self.dialog = MDDialog(
            title="حذف تاریخچه",
            text="آیا از حذف تمام کانفیگ‌های ذخیره‌شده مطمئن هستید؟",
            buttons=[
                MDFlatButton(text="انصراف", on_release=lambda *_: self.dialog.dismiss()),
                MDFlatButton(
                    text="حذف همه",
                    theme_text_color="Custom",
                    text_color=(0.9, 0.2, 0.2, 1),
                    on_release=lambda *_: self._do_clear_history(),
                ),
            ],
        )
        self.dialog.open()

    def _do_clear_history(self):
        self.db.clear_history()
        self.dialog.dismiss()
        self.refresh_history()
        Snackbar(text="تاریخچه پاک شد").open()

    # ---------------- export / share hub ----------------

    def _collect_working_configs_raw(self):
        rows = self.db.get_history()
        return [r[6] for r in rows if r[6]]

    def copy_all_configs(self):
        configs = self._collect_working_configs_raw()
        if not configs:
            Snackbar(text="کانفیگی برای کپی وجود ندارد").open()
            return
        Clipboard.copy("\n".join(configs))
        Snackbar(text=f"{len(configs)} کانفیگ کپی شد").open()

    def export_to_file(self, fmt="txt"):
        configs = self._collect_working_configs_raw()
        if not configs:
            Snackbar(text="کانفیگی برای ذخیره وجود ندارد").open()
            return
        out_dir = self._export_dir()
        filename = f"cfscanner_export_{int(time.time())}.{fmt}"
        path = os.path.join(out_dir, filename)
        try:
            if fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(configs, f, ensure_ascii=False, indent=2)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(configs))
            Snackbar(text=f"در فایل ذخیره شد: {filename}").open()
        except OSError as e:
            Snackbar(text=f"خطا در ذخیره‌سازی: {e}").open()

    def generate_sub_link(self):
        configs = self._collect_working_configs_raw()
        if not configs:
            Snackbar(text="کانفیگی برای تولید لینک وجود ندارد").open()
            return
        blob = "\n".join(configs).encode("utf-8")
        b64 = base64.b64encode(blob).decode("ascii")
        Clipboard.copy(b64)
        Snackbar(text="لینک ساب (Base64) در کلیپ‌بورد کپی شد").open()


if __name__ == "__main__":
    CFPersianScanApp().run()
