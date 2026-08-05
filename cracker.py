"""
ArchiveCracker v2.1 — ARCHPR风格 压缩包密码破解工具
GPU加速(hashcat) + 多攻击模式 + PyQt5 GUI
支持 ZIP / RAR / 7Z / TAR.GZ / TAR.BZ2 / TAR.XZ / CAB / ARJ / ISO
"""
import sys, os, time, struct, zlib, itertools, string, hashlib
import subprocess, threading, shutil, tempfile, tarfile, gzip, bz2, lzma
from pathlib import Path
from collections import OrderedDict

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox,
    QFileDialog, QTextEdit, QProgressBar, QGroupBox, QTabWidget,
    QListWidget, QStackedWidget,
    QMessageBox, QComboBox, QDoubleSpinBox, QFrame, QSplitter,
    QRadioButton, QButtonGroup, QScrollArea, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QMutex, QMutexLocker
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QPixmap

# ── Archive libs ──
import zipfile
HAS_RAR = False; HAS_7Z = False
try:
    import rarfile; HAS_RAR = True
except ImportError: pass
try:
    import py7zlib; HAS_7Z = True
except ImportError:
    try:
        import py7zr; HAS_7Z = True
    except ImportError: pass

# ── Format → hashcat mode mapping ──
HASHCAT_MODES = {
    'zip':  '13600',   # WinZip
    'rar':  '13000',   # RAR3-hp
    '7z':   '11600',   # 7-Zip
}
GPU_FORMATS = {'zip', 'rar', '7z'}
ALL_FORMATS = {
    '.zip': 'zip', '.rar': 'rar', '.7z': '7z',
    '.tar.gz': 'tar.gz', '.tgz': 'tar.gz',
    '.tar.bz2': 'tar.bz2', '.tbz2': 'tar.bz2',
    '.tar.xz': 'tar.xz', '.txz': 'tar.xz',
    '.cab': 'cab', '.arj': 'arj',
    '.iso': 'iso',
}

# ── Tool detection ──
def find_tool(names):
    # PyInstaller onefile: look next to the running exe first (tools/ dir)
    try:
        exe_dir = os.path.dirname(sys.executable)
        for n in names:
            # tools/<sub>/<tool> 和 tools/<tool> 两级路径
            for sub in ('', 'hashcat', 'bkcrack', 'john', 'tools', 'tools/hashcat', 'tools/bkcrack', 'tools/john'):
                fp = os.path.join(exe_dir, sub, n)
                if os.path.isfile(fp):
                    return fp
            # john 的 2john 工具在嵌套 run/ 目录下；bkcrack 在版本子目录下
            for dn in ('john/run', 'tools/john/run',
                       'john-1.9.0-jumbo-1-win64/run', 'tools/john/python2john',
                       'bkcrack-1.7.1-win64', 'tools/bkcrack/bkcrack-1.7.1-win64'):
                fp = os.path.join(exe_dir, dn, n)
                if os.path.isfile(fp):
                    return fp
    except Exception:
        pass
    for n in names:
        p = shutil.which(n)
        if p: return p
        if os.path.isfile(n): return n
        for d in [r"C:\Program Files\hashcat", r"C:\Tools\hashcat",
                  r"C:\Program Files (x86)\John", r"C:\Tools\john",
                  r"C:\Tools\bkcrack"]:
            fp = os.path.join(d, n)
            if os.path.isfile(fp): return fp
        if n.endswith('.exe'):
            for d in [r"C:\Program Files\hashcat", r"C:\Tools\hashcat"]:
                fp = os.path.join(d, n)
                if os.path.isfile(fp): return fp
    return None

def check_7z():
    """检测7z命令行是否可用"""
    return find_tool(["7z", "7z.exe", "7za", "7za.exe"]) is not None

def check_arj():
    return find_tool(["arj", "arj.exe"]) is not None

HASHCAT_BIN = find_tool(["hashcat", "hashcat.exe"])
JOHN_BIN = find_tool(["john", "john.exe"])
BKCRACK_BIN = find_tool(["bkcrack", "bkcrack.exe"])
HAS_7Z_CLI = check_7z()
HAS_ARJ_CLI = check_arj()

# *2john tools for hash extraction
TOOLS_2JOHN = {
    'zip':  ['zip2john', 'zip2john.exe'],
    'rar':  ['rar2john', 'rar2john.exe'],
    '7z':   ['7z2john', '7z2john.pl'],
}
TOOLS_2JOHN_PATHS = {}
for fmt, names in TOOLS_2JOHN.items():
    TOOLS_2JOHN_PATHS[fmt] = find_tool(names)

# ── Temp file tracking for cleanup ──
_temp_files = []

def _make_temp_path(suffix=''):
    """Create a real temporary file path and track it for cleanup.

    tempfile.mktemp() is race-prone. This helper reserves the path with
    mkstemp(), closes the fd immediately, and lets later code write to it.
    """
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    _temp_files.append(path)
    return path

def _track_temp(path):
    _temp_files.append(path)
    return path

def _cleanup_temps():
    for p in _temp_files:
        try:
            if os.path.isfile(p): os.unlink(p)
        except: pass
    _temp_files.clear()

def _extract_hash_to_file(archive_path, archive_type, log=None):
    """Extract a hashcat-compatible hash into a tracked temp file.

    Returns (hash_file, error_message). hash_file is None on failure.
    """
    john_tool = TOOLS_2JOHN_PATHS.get(archive_type)
    if not john_tool:
        return None, f"未找到 {archive_type}2john 工具"
    hash_file = _make_temp_path(suffix='.hash')
    try:
        result = subprocess.run(
            [john_tool, archive_path],
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='replace',
        )
    except subprocess.TimeoutExpired:
        return None, "哈希提取超时(30s)"
    except OSError as e:
        return None, f"无法执行 {john_tool}: {e}"
    except Exception as e:
        return None, f"哈希提取异常: {e}"

    output = (result.stdout or '').strip()
    err = (result.stderr or '').strip()
    if result.returncode != 0 and not output:
        return None, err[:500] or f"{john_tool} 返回码 {result.returncode}"
    if not output:
        return None, "未提取到哈希，可能是不支持的加密格式"
    with open(hash_file, 'w', encoding='utf-8') as f:
        f.write(output + '\n')
    if log and err:
        log(f"2john提示: {err[:300]}")
    return hash_file, None

import atexit
atexit.register(_cleanup_temps)


def _escape_hashcat_charset(cs):
    """Escape hashcat-reserved chars in a custom charset (-1..-4) value.

    hashcat treats `?` (mask placeholders), `,` (charset separator) and
    `\\` (escape) specially inside custom charset definitions. Backslash-escape
    them so a user's charset like `!?@#,` doesn't corrupt the mask.
    """
    out = []
    for ch in cs:
        if ch in ('?', ',', '\\'):
            out.append('\\' + ch)
        else:
            out.append(ch)
    return ''.join(out)


# ============================================================
#  Theme Stylesheets
# ============================================================

LIGHT_QSS = """
QMainWindow {
    background: #FFFFFF;
}
QWidget {
    color: #212121;
    font-family: 'Microsoft YaHei UI', 'Segoe UI', sans-serif;
    font-size: 12px;
}

/* ── ARCHPR 风格左侧模式列表 ── */
QListWidget#modeList {
    background: #FAFBFC;
    border: none;
    border-right: 1px solid #E2E6ED;
    padding: 6px;
    outline: none;
}
QListWidget#modeList::item {
    padding: 10px 12px;
    border-radius: 8px;
    margin: 2px 0;
    color: #424242;
    font-size: 12px;
}
QListWidget#modeList::item:hover {
    background: #EEF2F8;
}
QListWidget#modeList::item:selected {
    background: #0066FF;
    color: #FFFFFF;
    font-weight: 600;
}

/* ── Tab bar as segmented control ── */
QTabWidget::pane {
    border: none;
    background: transparent;
}
QTabBar {
    background: transparent;
}
QTabBar::tab {
    background: transparent;
    color: #757575;
    border: none;
    border-bottom: 3px solid transparent;
    padding: 10px 20px;
    font-size: 12px;
    font-weight: 500;
}
QTabBar::tab:selected {
    color: #0066FF;
    border-bottom: 3px solid #0066FF;
    font-weight: 600;
}
QTabBar::tab:hover {
    color: #424242;
}

/* ── Cards (GroupBox) ── */
QGroupBox {
    font-size: 13px;
    font-weight: 600;
    color: #212121;
    border: 1px solid #E8E8E8;
    border-radius: 8px;
    margin-top: 14px;
    padding: 18px 16px 14px 16px;
    background: #FAFAFA;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 16px;
    padding: 0 6px;
    background: #FAFAFA;
}

/* ── Labels ── */
QLabel {
    color: #424242;
    font-size: 12px;
}
QLabel#hint {
    color: #9E9E9E;
    font-size: 11px;
}
QLabel#accent {
    color: #0066FF;
    font-weight: 600;
}
QLabel#success {
    color: #00C853;
    font-weight: 600;
}
QLabel#error {
    color: #EF4444;
    font-weight: 600;
}

/* ── Inputs ── */
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background: #FFFFFF;
    color: #212121;
    border: 1px solid #E0E0E0;
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 12px;
    min-height: 20px;
    selection-background-color: #0066FF30;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border-color: #0066FF;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #757575;
    margin-right: 8px;
}

/* ── Checkbox ── */
QCheckBox, QRadioButton {
    color: #424242;
    font-size: 12px;
    spacing: 8px;
}
QCheckBox::indicator, QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border-radius: 3px;
    border: 2px solid #BDBDBD;
    background: #FFFFFF;
}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {
    background: #0066FF;
    border-color: #0066FF;
}
QRadioButton::indicator {
    border-radius: 8px;
}

/* ── Buttons ── */
QPushButton {
    background: #F5F5F5;
    color: #424242;
    border: 1px solid #E0E0E0;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 12px;
    font-weight: 500;
}
QPushButton:hover {
    background: #EEEEEE;
    border-color: #BDBDBD;
}
QPushButton:pressed {
    background: #E0E0E0;
}
QPushButton:disabled {
    color: #BDBDBD;
    border-color: #F0F0F0;
    background: #FAFAFA;
}

/* ── Primary action button ── */
#startBtn {
    background: #0066FF;
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 12px 24px;
    font-size: 14px;
    font-weight: 600;
}
#startBtn:hover {
    background: #0055DD;
}
#startBtn:pressed {
    background: #0044BB;
}
#startBtn:disabled {
    background: #B0C4FF;
    color: #FFFFFF;
}

/* ── Stop button ── */
#stopBtn {
    background: #FFEBEE;
    color: #D32F2F;
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 13px;
    font-weight: 600;
}
#stopBtn:hover {
    background: #FFCDD2;
}

/* ── Theme toggle ── */
#themeBtn {
    background: transparent;
    border: 1px solid #E0E0E0;
    border-radius: 16px;
    padding: 4px 12px;
    font-size: 12px;
    color: #757575;
}
#themeBtn:hover {
    border-color: #BDBDBD;
    color: #424242;
}

/* ── Advanced toggle ── */
#advToggle {
    background: transparent;
    border: none;
    color: #757575;
    font-size: 11px;
    text-align: left;
    padding: 4px 0;
}
#advToggle:hover {
    color: #0066FF;
}

/* ── Progress bar ── */
QProgressBar {
    background: #E8E8E8;
    border: none;
    border-radius: 4px;
    height: 6px;
}
QProgressBar::chunk {
    background: #0066FF;
    border-radius: 4px;
}

/* ── Log / Text area ── */
QTextEdit {
    background: #FFFFFF;
    color: #616161;
    border: 1px solid #E8E8E8;
    border-radius: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    padding: 12px;
    selection-background-color: #0066FF20;
}
QTextEdit:focus {
    border-color: #0066FF;
}

/* ── Result card frame ── */
QFrame#resultCard {
    background: #F0FFF4;
    border: 1px solid #C8E6C9;
    border-radius: 8px;
    padding: 16px;
}

/* ── Scrollbar ── */
QScrollArea { border: none; }
QScrollBar:vertical {
    background: transparent;
    width: 6px;
    border: none;
}
QScrollBar::handle:vertical {
    background: #D0D0D0;
    border-radius: 3px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #B0B0B0; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

/* ── Status bar ── */
QStatusBar {
    background: #FAFAFA;
    border-top: 1px solid #E8E8E8;
    color: #9E9E9E;
    font-size: 11px;
}
QStatusBar QLabel {
    color: #9E9E9E;
    font-size: 11px;
    padding: 0 4px;
}
QStatusBar QLabel#statusRunning {
    color: #00C853;
}
QStatusBar QLabel#statusError {
    color: #EF4444;
}
QStatusBar QLabel#statusRight {
    color: #9E9E9E;
    font-size: 10px;
}
"""

DARK_QSS = """
QMainWindow {
    background: #0F1115;
}
QWidget {
    color: #F3F4F6;
    font-family: 'Microsoft YaHei UI', 'Segoe UI', sans-serif;
    font-size: 12px;
}

QTabWidget::pane { border: none; background: transparent; }
QListWidget#modeList {
    background: #1B1E26;
    border: none;
    border-right: 1px solid #2A2F3A;
    padding: 6px;
    outline: none;
}
QListWidget#modeList::item {
    padding: 10px 12px;
    border-radius: 8px;
    margin: 2px 0;
    color: #9CA3AF;
    font-size: 12px;
}
QListWidget#modeList::item:hover {
    background: #232834;
}
QListWidget#modeList::item:selected {
    background: #3B82F6;
    color: #FFFFFF;
    font-weight: 600;
}
QTabBar { background: transparent; }
QTabBar::tab {
    background: transparent;
    color: #6B7280;
    border: none;
    border-bottom: 3px solid transparent;
    padding: 10px 20px;
    font-size: 12px;
    font-weight: 500;
}
QTabBar::tab:selected {
    color: #3B82F6;
    border-bottom: 3px solid #3B82F6;
    font-weight: 600;
}
QTabBar::tab:hover { color: #D1D5DB; }

QGroupBox {
    font-size: 13px; font-weight: 600; color: #F3F4F6;
    border: 1px solid #262B34; border-radius: 8px;
    margin-top: 14px; padding: 18px 16px 14px 16px;
    background: #181C23;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 16px; padding: 0 6px;
    background: #181C23;
}

QLabel { color: #D1D5DB; font-size: 12px; }
QLabel#hint { color: #6B7280; font-size: 11px; }
QLabel#accent { color: #3B82F6; font-weight: 600; }
QLabel#success { color: #10B981; font-weight: 600; }
QLabel#error { color: #EF4444; font-weight: 600; }

QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background: #1A1F2B; color: #F3F4F6;
    border: 1px solid #262B34; border-radius: 6px;
    padding: 7px 10px; font-size: 12px; min-height: 20px;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border-color: #3B82F6;
}
QComboBox::drop-down { border: none; width: 24px; }
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #6B7280;
    margin-right: 8px;
}

QCheckBox, QRadioButton { color: #D1D5DB; font-size: 12px; spacing: 8px; }
QCheckBox::indicator, QRadioButton::indicator {
    width: 16px; height: 16px; border-radius: 3px;
    border: 2px solid #374151; background: #1A1F2B;
}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {
    background: #3B82F6; border-color: #3B82F6;
}
QRadioButton::indicator { border-radius: 8px; }

QPushButton {
    background: #1F2937; color: #D1D5DB;
    border: 1px solid #374151; border-radius: 6px;
    padding: 8px 16px; font-size: 12px; font-weight: 500;
}
QPushButton:hover { background: #283548; border-color: #4B5563; }
QPushButton:pressed { background: #374151; }
QPushButton:disabled { color: #4B5563; border-color: #1F2937; background: #181C23; }

#startBtn {
    background: #3B82F6; color: #FFFFFF; border: none;
    border-radius: 8px; padding: 12px 24px;
    font-size: 14px; font-weight: 600;
}
#startBtn:hover { background: #2563EB; }
#startBtn:pressed { background: #1D4ED8; }
#startBtn:disabled { background: #1E3A5F; color: #6B7280; }

#stopBtn {
    background: #2D1B1B; color: #EF4444; border: none;
    border-radius: 8px; padding: 10px 20px;
    font-size: 13px; font-weight: 600;
}
#stopBtn:hover { background: #3B2020; }

#themeBtn {
    background: transparent; border: 1px solid #374151;
    border-radius: 16px; padding: 4px 12px;
    font-size: 12px; color: #9CA3AF;
}
#themeBtn:hover { border-color: #4B5563; color: #D1D5DB; }

#advToggle {
    background: transparent; border: none;
    color: #6B7280; font-size: 11px; text-align: left; padding: 4px 0;
}
#advToggle:hover { color: #3B82F6; }

QProgressBar {
    background: #262B34; border: none; border-radius: 4px; height: 6px;
}
QProgressBar::chunk { background: #3B82F6; border-radius: 4px; }

QTextEdit {
    background: #181C23; color: #9CA3AF;
    border: 1px solid #262B34; border-radius: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px; padding: 12px;
}
QTextEdit:focus { border-color: #3B82F6; }

QFrame#resultCard {
    background: #0D2818; border: 1px solid #166534;
    border-radius: 8px; padding: 16px;
}

QScrollArea { border: none; }
QScrollBar:vertical { background: transparent; width: 6px; border: none; }
QScrollBar::handle:vertical { background: #374151; border-radius: 3px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #4B5563; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QStatusBar {
    background: #181C23; border-top: 1px solid #262B34;
    color: #6B7280; font-size: 11px;
}
QStatusBar QLabel { color: #6B7280; font-size: 11px; padding: 0 4px; }
QStatusBar QLabel#statusRunning { color: #10B981; }
QStatusBar QLabel#statusError { color: #EF4444; }
QStatusBar QLabel#statusRight { color: #6B7280; font-size: 10px; }
"""

THEMES = {"light": LIGHT_QSS, "dark": DARK_QSS}
STATUS_COLORS = {
    "light": {"accent": "#0066FF", "success": "#00C853", "error": "#EF4444", "muted": "#9E9E9E"},
    "dark":  {"accent": "#3B82F6", "success": "#10B981", "error": "#EF4444", "muted": "#6B7280"},
}


# ============================================================
#  Known Plaintext Attack (bkcrack wrapper) — FIXED
# ============================================================
class KPACrackEngine:
    @staticmethod
    def find_bkcrack():
        if BKCRACK_BIN:
            return BKCRACK_BIN
        for p in ["bkcrack", "bkcrack.exe",
                  r"C:\Tools\bkcrack\bkcrack.exe",
                  "/usr/bin/bkcrack"]:
            if os.path.isfile(p) or shutil.which(p):
                return p
        return None

    @staticmethod
    def run(zip_path, plain_file, entry_name="", offset=0, callback_log=None):
        bk = KPACrackEngine.find_bkcrack()
        if not bk:
            return None, "bkcrack未找到，请安装: https://github.com/kimci86/bkcrack"
        cmd = [bk, "-C", zip_path]
        if entry_name:
            cmd += ["-c", entry_name]
        cmd += ["-p", plain_file]
        if offset:
            cmd += ["--load-from-pos", str(offset)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = result.stdout + result.stderr
            for line in output.splitlines():
                if "Key" in line and ":" in line:
                    return line.split(":", 1)[1].strip(), None
            return None, output[:500]
        except subprocess.TimeoutExpired:
            return None, "bkcrack超时(10min)"
        except Exception as e:
            return None, str(e)


# ============================================================
#  hashcat Backend
# ============================================================
class HashcatWorker(QThread):
    progress = pyqtSignal(str)
    found = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, args, hash_type=None):
        super().__init__()
        self.args = args
        self.hash_type = hash_type
        self.process = None
        self._stop = False
        self._plain_only = True  # --outfile-format=2 => raw plaintext lines

    def stop(self):
        self._stop = True
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try: self.process.kill()
                except Exception: pass
            except Exception:
                pass

    def _decode_password(self, raw):
        """Decode a hashcat result line into the plaintext password."""
        raw = raw.strip()
        if raw.startswith("$HEX[") and raw.endswith("]"):
            try:
                return bytes.fromhex(raw[5:-1]).decode('utf-8', errors='replace')
            except (ValueError, UnicodeDecodeError):
                return raw
        return raw

    def _read_result(self, result_file):
        """Read passwords from hashcat outfile. Returns list of decoded passwords."""
        if not result_file or not os.path.isfile(result_file):
            return []
        out = []
        try:
            with open(result_file, encoding='utf-8', errors='replace') as f:
                for rl in f:
                    rl = rl.rstrip('\n\r')
                    if not rl:
                        continue
                    # outfile-format=2 => plaintext only; fallback to hash:pass
                    pw = rl.rsplit(":", 1)[-1].strip() if not self._plain_only else rl.strip()
                    out.append(self._decode_password(pw))
        except (OSError, ValueError):
            pass
        return [p for p in out if p]

    def run(self):
        if not HASHCAT_BIN:
            self.finished_signal.emit(False, "hashcat未安装")
            return
        cmd = [HASHCAT_BIN] + self.args
        self.progress.emit(f"执行: {' '.join(cmd[:8])}...")
        result_file = None
        for i, a in enumerate(self.args):
            if a == "-o" and i + 1 < len(self.args):
                result_file = self.args[i + 1]
                break
        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, universal_newlines=True, encoding='utf-8', errors='replace'
            )
            for line in self.process.stdout:
                if self._stop:
                    self.process.terminate()
                    break
                line = line.strip()
                if not line:
                    continue
                self.progress.emit(line)
                # Precise status matches: only treat `Status.........: Cracked`
                # (or a plain "Cracked" token on its own) as a hit.
                if "Status.........: Cracked" in line or line.strip().lower() == "cracked":
                    pws = self._read_result(result_file)
                    if pws:
                        pw = pws[0]
                        self.found.emit(pw)
                        self.process.terminate()
                        self.finished_signal.emit(True, pw)
                        return
            self.process.wait()
            if self._stop:
                self.finished_signal.emit(False, "已停止")
                return
            pws = self._read_result(result_file)
            if pws:
                pw = pws[0]
                self.found.emit(pw)
                self.finished_signal.emit(True, pw)
                return
            self.finished_signal.emit(self.process.returncode == 0, "破解未找到密码")
        except Exception as e:
            self.finished_signal.emit(False, str(e))


# ============================================================
#  Index-based password chunk (memory-efficient brute force)
# ============================================================
class _IndexChunk:
    """Generates passwords on-the-fly by index range, avoiding full list in memory."""
    def __init__(self, charset, length, start, end):
        self.charset = charset
        self.length = length
        self.start = start
        self.end = end

    def __iter__(self):
        cs = self.charset
        n = len(cs)
        L = self.length
        for idx in range(self.start, self.end):
            pwd = []
            tmp = idx
            for _ in range(L):
                pwd.append(cs[tmp % n])
                tmp //= n
            yield ''.join(reversed(pwd))

    def __len__(self):
        return self.end - self.start


# ============================================================
#  Multi-thread CPU Worker (thread-safe progress)
# ============================================================
class CPUWorker(QThread):
    progress = pyqtSignal(int)
    found = pyqtSignal(str)
    speed = pyqtSignal(float)
    finished_signal = pyqtSignal()

    def __init__(self, archive_path, archive_type, passwords, name=""):
        super().__init__()
        self.archive_path = archive_path
        self.archive_type = archive_type
        self.passwords = passwords
        self.name = name
        self._stop = threading.Event()
        self._local_count = 0

    def stop(self):
        self._stop.set()

    def run(self):
        for pwd in self.passwords:
            if self._stop.is_set():
                break
            self._local_count += 1
            if self._local_count % 100 == 0:
                self.progress.emit(100)
            try:
                if self._check(pwd):
                    self.found.emit(pwd)
                    self._stop.set()
                    return
            except:
                continue
        # Emit remaining count
        remaining = self._local_count % 100
        if remaining > 0:
            self.progress.emit(remaining)
        self.finished_signal.emit()

    def _check(self, pwd):
        at = self.archive_type
        tmpdir = tempfile.mkdtemp(prefix='_crack_')
        try:
            if at == 'zip':
                with zipfile.ZipFile(self.archive_path) as zf:
                    # 必须挑"真正加密"的成员验证（flag_bits 第0位=加密）。
                    # 用未加密成员验证会导致假阳性：open(pwd=...) 会忽略
                    # 密码直接读成功，第一个候选就误报"找到"。
                    target = next((i for i in zf.infolist()
                                   if not i.is_dir() and (i.flag_bits & 0x1)), None)
                    if target is None:
                        # 整个 zip 没有任何加密成员 → 无密码可破
                        return False
                    with zf.open(target, pwd=pwd.encode('utf-8')) as fp:
                        fp.read(64 * 1024)
                    return True
            elif at == 'rar' and HAS_RAR:
                with rarfile.RarFile(self.archive_path) as rf:
                    # rarfile 用 needs_password() 判断成员是否加密，
                    # 未加密 rar 的 extractall(pwd=...) 同样会假阳性
                    if not any(getattr(i, 'needs_password', lambda: False)()
                               for i in rf.infolist()):
                        return False
                    rf.extractall(path=tmpdir, pwd=pwd)
                    return True
            elif at == '7z':
                if HAS_7Z:
                    try:
                        import py7zlib
                        with open(self.archive_path, 'rb') as f:
                            a = py7zlib.SevenZipFile(f, mode='r', password=pwd)
                            a.extractall(tmpdir)
                            return True
                    except ImportError: pass
                    try:
                        import py7zr
                        with py7zr.SevenZipFile(self.archive_path, mode='r', password=pwd) as a:
                            a.extractall(tmpdir)
                            return True
                    except ImportError: pass
            elif at in ('tar.gz', 'tar.bz2', 'tar.xz', 'cab', 'arj', 'iso'):
                if at == 'arj' and HAS_ARJ_CLI:
                    cmd = ['arj', 'x', f'-g{pwd}', self.archive_path, tmpdir, '-y']
                elif HAS_7Z_CLI:
                    cmd = ['7z', 'x', f'-p{pwd}', f'-o{tmpdir}', self.archive_path, '-y']
                else:
                    return False
                r = subprocess.run(cmd, capture_output=True, timeout=30)
                return r.returncode == 0
            return False
        except (RuntimeError, zipfile.BadZipFile, rarfile.BadRarFile, OSError, ValueError):
            # Wrong password or corrupt archive — expected during brute force
            return False
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ============================================================
#  Background CRC32 collision worker (keeps UI responsive)
# ============================================================
class CRC32Worker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal(object)   # bytes content or None

    def __init__(self, path, entry_name, max_len, charset):
        super().__init__()
        self.path = path
        self.entry_name = entry_name
        self.max_len = max_len
        self.charset = charset
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        import zlib as _zlib
        target_crc = None
        try:
            with zipfile.ZipFile(self.path) as zf:
                info = None
                for i in zf.infolist():
                    if i.filename == self.entry_name:
                        info = i; break
                if not info:
                    for i in zf.infolist():
                        if self.entry_name in i.filename:
                            info = i
                            self.progress.emit(f"匹配: {i.filename}")
                            break
                if not info:
                    self.progress.emit(f"ZIP内未找到: {self.entry_name}")
                    self.done.emit(None)
                    return
                target_crc = info.CRC
                self.progress.emit(f"目标CRC32: {target_crc:08x}")
        except Exception as e:
            self.progress.emit(f"读取ZIP失败: {e}")
            self.done.emit(None)
            return

        self.progress.emit(f"开始碰撞搜索 (字符集 {len(self.charset)} 个)")
        for length in range(1, self.max_len + 1):
            if self._stop.is_set():
                self.done.emit(None)
                return
            count = len(self.charset) ** length
            if count > 10_000_000:
                self.progress.emit(f"{length}位组合数 {count:,} 过大，跳过")
                continue
            self.progress.emit(f"搜索 {length}位 ({count:,} 组合)")
            for combo in itertools.product(self.charset, repeat=length):
                if self._stop.is_set():
                    self.done.emit(None)
                    return
                content = ''.join(combo).encode('utf-8')
                if _zlib.crc32(content) & 0xFFFFFFFF == target_crc:
                    self.done.emit(content)
                    return
        self.done.emit(None)


# ============================================================
#  Background KPA worker (bkcrack subprocess off the UI thread)
# ============================================================
class KPAWorker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal(object, object)   # (result, error)

    def __init__(self, zip_path, plain_path, entry_name, offset):
        super().__init__()
        self.zip_path = zip_path
        self.plain_path = plain_path
        self.entry_name = entry_name
        self.offset = offset
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        bk = KPACrackEngine.find_bkcrack()
        if not bk:
            self.done.emit(None, "bkcrack未找到，请安装: https://github.com/kimci86/bkcrack")
            return
        cmd = [bk, "-C", self.zip_path]
        if self.entry_name:
            cmd += ["-c", self.entry_name]
        cmd += ["-p", self.plain_path]
        if self.offset:
            cmd += ["--load-from-pos", str(self.offset)]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace'
            )
            for line in proc.stdout:
                if self._stop.is_set():
                    proc.terminate()
                    self.done.emit(None, "已停止")
                    return
                line = line.strip()
                if not line:
                    continue
                self.progress.emit(line)
                if "Key" in line and ":" in line:
                    proc.terminate()
                    self.done.emit(line.split(":", 1)[1].strip(), None)
                    return
            proc.wait()
            self.done.emit(None, "未找到密钥，或明文不匹配")
        except Exception as e:
            self.done.emit(None, str(e))


# ============================================================
#  Tab 1 — Brute Force (Modern Layout)
# ============================================================
class BruteForceTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Charset row ──
        cs_group = QGroupBox("字符集")
        cs_layout = QVBoxLayout(cs_group)
        cs_layout.setSpacing(10)

        row1 = QHBoxLayout()
        self.cb_lower = QCheckBox("小写字母"); self.cb_lower.setChecked(True)
        self.cb_upper = QCheckBox("大写字母")
        self.cb_digits = QCheckBox("数字"); self.cb_digits.setChecked(True)
        self.cb_special = QCheckBox("特殊字符")
        row1.addWidget(self.cb_lower)
        row1.addWidget(self.cb_upper)
        row1.addWidget(self.cb_digits)
        row1.addWidget(self.cb_special)
        row1.addStretch()
        cs_layout.addLayout(row1)

        # ── Advanced toggle ──
        self.adv_btn = QPushButton("高级选项（自定义字符集）")
        self.adv_btn.setObjectName("advToggle")
        self.adv_btn.setCursor(Qt.PointingHandCursor)
        self.adv_btn.clicked.connect(self._toggle_advanced)
        cs_layout.addWidget(self.adv_btn)

        # ── Advanced panel ──
        self.adv_panel = QWidget()
        adv_row = QHBoxLayout(self.adv_panel)
        adv_row.setContentsMargins(0, 0, 0, 0)
        adv_row.addWidget(QLabel("自定义:"))
        self.custom_chars = QLineEdit()
        self.custom_chars.setPlaceholderText("输入额外字符")
        adv_row.addWidget(self.custom_chars)
        self.adv_panel.setVisible(False)
        cs_layout.addWidget(self.adv_panel)

        layout.addWidget(cs_group)

        # ── 参数卡片 ──
        pg = QGroupBox("参数设置")
        pg_layout = QGridLayout(pg)
        pg_layout.setSpacing(10)

        pg_layout.addWidget(QLabel("长度范围"), 0, 0)
        len_row = QHBoxLayout()
        self.spin_min = QSpinBox(); self.spin_min.setRange(1, 20); self.spin_min.setValue(1)
        self.spin_min.setFixedWidth(60)
        len_row.addWidget(self.spin_min)
        lbl_tilde = QLabel("~"); lbl_tilde.setAlignment(Qt.AlignCenter)
        len_row.addWidget(lbl_tilde)
        self.spin_max = QSpinBox(); self.spin_max.setRange(1, 20); self.spin_max.setValue(6)
        self.spin_max.setFixedWidth(60)
        len_row.addWidget(self.spin_max)
        len_row.addStretch()
        pg_layout.addLayout(len_row, 0, 1)

        pg_layout.addWidget(QLabel("线程数"), 1, 0)
        self.spin_threads = QSpinBox(); self.spin_threads.setRange(1, 64); self.spin_threads.setValue(8)
        self.spin_threads.setFixedWidth(80)
        pg_layout.addWidget(self.spin_threads, 1, 1)

        layout.addWidget(pg)

        # ── 引擎卡片 ──
        eg = QGroupBox("破解引擎")
        eg_layout = QVBoxLayout(eg)
        eg_layout.setSpacing(10)
        eng_row = QHBoxLayout()
        self.chk_cpu = QCheckBox("CPU")
        self.chk_cpu.setChecked(True)
        eng_row.addWidget(self.chk_cpu)
        self.chk_hashcat = QCheckBox("GPU 加速 (hashcat)")
        self.chk_hashcat.setChecked(True)
        eng_row.addWidget(self.chk_hashcat)
        eng_row.addStretch()
        eg_layout.addLayout(eng_row)
        ghint = QLabel("选择 CPU 或 GPU，或两者并行。GPU 需单独安装 hashcat。")
        ghint.setObjectName("hint")
        eg_layout.addWidget(ghint)
        layout.addWidget(eg)

        layout.addStretch()

    def _toggle_advanced(self):
        visible = not self.adv_panel.isVisible()
        self.adv_panel.setVisible(visible)

    def get_charset(self):
        c = ""
        if self.cb_lower.isChecked(): c += string.ascii_lowercase
        if self.cb_upper.isChecked(): c += string.ascii_uppercase
        if self.cb_digits.isChecked(): c += string.digits
        if self.cb_special.isChecked(): c += "!@#$%^&*()_-+=[]{}|;:',.<>?/`~"
        c += self.custom_chars.text()
        return c

    def get_mask(self):
        return self.get_charset(), self.spin_min.value(), self.spin_max.value()


# ============================================================
#  Tab 2 — Mask Attack
# ============================================================
class MaskTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)

        g = QGroupBox("掩码设置")
        gl = QGridLayout(g)
        gl.setSpacing(10)
        gl.addWidget(QLabel("掩码模板"), 0, 0)
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("例: ?u?l?l?l?d?d?d")
        gl.addWidget(self.mask_input, 0, 1)
        ref = QLabel(
            "?l=a-z  ?u=A-Z  ?d=0-9  ?s=特殊  ?a=全部  ?1~?4=自定义\n"
            "例: pass?d?d?d → pass000~pass999"
        )
        ref.setObjectName("hint")
        ref.setWordWrap(True)
        gl.addWidget(ref, 1, 0, 1, 2)
        layout.addWidget(g)

        # 引擎
        eg = QGroupBox("破解引擎")
        eg_layout = QVBoxLayout(eg)
        self.chk_hashcat = QCheckBox("GPU 加速 (hashcat)")
        self.chk_hashcat.setChecked(True)
        eg_layout.addWidget(self.chk_hashcat)
        layout.addWidget(eg)
        layout.addStretch()


# ============================================================
#  Tab 3 — Dictionary
# ============================================================
class DictionaryTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)

        g = QGroupBox("字典文件")
        gl = QGridLayout(g)
        gl.setSpacing(10)
        self.dict_path = QLineEdit()
        self.dict_path.setPlaceholderText("选择字典文件...")
        gl.addWidget(self.dict_path, 0, 0)
        btn = QPushButton("浏览"); btn.clicked.connect(self._browse)
        gl.addWidget(btn, 0, 1)
        self.chk_auto_rule = QCheckBox("启用 hashcat 规则增强")
        self.chk_auto_rule.setChecked(True)
        gl.addWidget(self.chk_auto_rule, 1, 0, 1, 2)
        layout.addWidget(g)

        eg = QGroupBox("破解引擎")
        eg_layout = QVBoxLayout(eg)
        self.chk_hashcat = QCheckBox("GPU 加速 (hashcat)")
        self.chk_hashcat.setChecked(True)
        eg_layout.addWidget(self.chk_hashcat)
        layout.addWidget(eg)

        hint = QLabel("推荐: rockyou.txt · github.com/danielmiessler/SecLists")
        hint.setObjectName("hint")
        layout.addWidget(hint)
        layout.addStretch()

    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择字典文件", "",
            "文本文件 (*.txt *.dic *.lst);;所有文件 (*)")
        if p: self.dict_path.setText(p)


# ============================================================
#  Tab 4 — CRC32
# ============================================================
class CRC32Tab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)

        g = QGroupBox("CRC32 内容碰撞 (ZIP only)")
        gl = QGridLayout(g)
        gl.setSpacing(10)
        gl.addWidget(QLabel("目标文件名"), 0, 0)
        self.entry_name = QLineEdit()
        self.entry_name.setPlaceholderText("ZIP内文件名，如: secret.txt")
        gl.addWidget(self.entry_name, 0, 1)
        gl.addWidget(QLabel("最大长度"), 1, 0)
        self.spin_max = QSpinBox(); self.spin_max.setRange(1, 8); self.spin_max.setValue(6)
        self.spin_max.setFixedWidth(80)
        gl.addWidget(self.spin_max, 1, 1)
        gl.addWidget(QLabel("字符集"), 2, 0)
        self.charset_combo = QComboBox()
        self.charset_combo.addItems(["纯数字 0-9", "小写+数字", "字母+数字", "全部字符"])
        gl.addWidget(self.charset_combo, 2, 1)
        layout.addWidget(g)

        hint = QLabel("注意: CRC32碰撞只能恢复很小文件(<6字节)的原文内容，不能直接恢复密码")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        layout.addStretch()


# ============================================================
#  Tab 5 — Known Plaintext Attack
# ============================================================
class KPATab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)

        g = QGroupBox("已知明文攻击 (KPA)")
        gl = QGridLayout(g)
        gl.setSpacing(10)
        gl.addWidget(QLabel("ZIP内文件名"), 0, 0)
        self.entry_name = QLineEdit()
        self.entry_name.setPlaceholderText("如: image.png")
        gl.addWidget(self.entry_name, 0, 1)
        gl.addWidget(QLabel("明文文件"), 1, 0)
        self.plain_path = QLineEdit()
        self.plain_path.setPlaceholderText("已知明文内容文件")
        gl.addWidget(self.plain_path, 1, 1)
        btn = QPushButton("浏览"); btn.clicked.connect(self._browse)
        gl.addWidget(btn, 1, 2)
        gl.addWidget(QLabel("偏移量(字节)"), 2, 0)
        self.spin_offset = QSpinBox(); self.spin_offset.setRange(0, 99999)
        self.spin_offset.setFixedWidth(100)
        gl.addWidget(self.spin_offset, 2, 1)
        self.chk_auto = QCheckBox("自动识别模板 (PNG/ZIP/EXE)")
        self.chk_auto.setChecked(True)
        gl.addWidget(self.chk_auto, 3, 0, 1, 2)
        layout.addWidget(g)

        hint = QLabel("需安装 bkcrack: github.com/kimci86/bkcrack")
        hint.setObjectName("hint")
        layout.addWidget(hint)
        layout.addStretch()

    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择明文文件", "")
        if p: self.plain_path.setText(p)


# ============================================================
#  Main Window (Modern Layout)
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ArchiveCracker v2.2")
        self.setMinimumSize(580, 440)
        self.resize(960, 720)

        self.workers = []
        self._running = False
        self._start_time = 0
        self._total_tried = 0
        self._found_pw = None
        self._theme = "light"
        self.setAcceptDrops(True)

        central = QWidget()
        self.setCentralWidget(central)
        main_v = QVBoxLayout(central)
        main_v.setSpacing(12)
        main_v.setContentsMargins(16, 12, 16, 8)

        # ── Top bar: file card + theme toggle ──
        top = QHBoxLayout()
        top.setSpacing(12)

        file_group = QGroupBox("压缩包文件")
        fl = QHBoxLayout(file_group)
        fl.setSpacing(10)
        self.file_icon = QLabel("📦")
        self.file_icon.setFixedWidth(28)
        fl.addWidget(self.file_icon)
        info_col = QVBoxLayout()
        info_col.setSpacing(2)
        self.file_name_label = QLabel("未选择文件")
        self.file_name_label.setStyleSheet("font-weight: 600; font-size: 13px;")
        info_col.addWidget(self.file_name_label)
        self.file_size_label = QLabel("")
        self.file_size_label.setObjectName("hint")
        info_col.addWidget(self.file_size_label)
        fl.addLayout(info_col, 1)
        self.format_label = QLabel("")
        self.format_label.setObjectName("accent")
        fl.addWidget(self.format_label)
        browse_btn = QPushButton("更换文件")
        browse_btn.clicked.connect(self._browse_file)
        fl.addWidget(browse_btn)
        top.addWidget(file_group, 1)

        self.theme_btn = QPushButton("🌙")
        self.theme_btn.setObjectName("themeBtn")
        self.theme_btn.setFixedSize(36, 36)
        self.theme_btn.setCursor(Qt.PointingHandCursor)
        self.theme_btn.clicked.connect(self._toggle_theme)
        top.addWidget(self.theme_btn)

        main_v.addLayout(top)

        # ── ARCHPR 风格：左侧模式列表 + 右侧参数面板 ──
        mode_split = QHBoxLayout()
        mode_split.setSpacing(0)

        self.mode_list = QListWidget()
        self.mode_list.setObjectName("modeList")
        self.mode_list.setFixedWidth(150)
        self.mode_list.addItems([
            "🔓 暴力破解",
            "🎭 掩码攻击",
            "📖 字典攻击",
            "🔑 已知明文",
            "🧮 CRC32碰撞",
        ])
        self.mode_list.setCurrentRow(0)

        self.stack = QStackedWidget()
        self.bf_tab = BruteForceTab()
        self.mask_tab = MaskTab()
        self.dict_tab = DictionaryTab()
        self.kpa_tab = KPATab()
        self.crc_tab = CRC32Tab()
        for t in (self.bf_tab, self.mask_tab, self.dict_tab, self.kpa_tab, self.crc_tab):
            self.stack.addWidget(t)

        self.mode_list.currentRowChanged.connect(self.stack.setCurrentIndex)
        mode_split.addWidget(self.mode_list)
        mode_split.addWidget(self.stack, 1)
        main_v.addLayout(mode_split, 1)

        # ── Single action button ──
        self.start_btn = QPushButton("▶  开始破解")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.clicked.connect(self._start)
        main_v.addWidget(self.start_btn)

        # ── Running status (hidden by default) ──
        self.status_group = QGroupBox("运行状态")
        sg = QVBoxLayout(self.status_group)
        sg.setSpacing(10)

        prog_header = QHBoxLayout()
        prog_lbl = QLabel("破解进度")
        prog_lbl.setStyleSheet("font-weight: 600;")
        prog_header.addWidget(prog_lbl)
        prog_header.addStretch()
        self.lbl_pct = QLabel("0%")
        self.lbl_pct.setObjectName("accent")
        self.lbl_pct.setStyleSheet("font-size: 16px; font-weight: 700;")
        prog_header.addWidget(self.lbl_pct)
        sg.addLayout(prog_header)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        sg.addWidget(self.progress_bar)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(24)
        for label_text, var_name in [("当前速度", "lbl_speed"), ("已尝试", "lbl_tried"), ("已耗时", "lbl_time")]:
            col = QVBoxLayout()
            col.setSpacing(2)
            val = QLabel("--")
            val.setStyleSheet("font-size: 14px; font-weight: 600;")
            setattr(self, var_name, val)
            col.addWidget(val)
            desc = QLabel(label_text)
            desc.setObjectName("hint")
            col.addWidget(desc)
            stats_row.addLayout(col)
        stats_row.addStretch()
        sg.addLayout(stats_row)

        self.status_group.setVisible(False)
        main_v.addWidget(self.status_group)

        # ── 活动记录 + 结果卡片（QSplitter 分栏，可拖拽） ──
        log_group = QGroupBox("活动记录")
        log_h = QHBoxLayout(log_group)
        log_h.setSpacing(0)
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMinimumHeight(120)
        log_h.addWidget(self.log_box)

        # 结果卡片 (right side of splitter)
        self.result_card = QFrame()
        self.result_card.setObjectName("resultCard")
        self.result_card.setMinimumWidth(180)
        rc = QVBoxLayout(self.result_card)
        rc.setSpacing(10)
        rc.setContentsMargins(16, 16, 16, 16)
        rc_lbl = QLabel("✓ 密码已找到")
        rc_lbl.setObjectName("success")
        rc_lbl.setStyleSheet("font-size: 14px;")
        rc.addWidget(rc_lbl)
        self.result_pw = QLabel("")
        self.result_pw.setStyleSheet("font-size: 20px; font-weight: 700; color: #00C853; padding: 4px 0;")
        self.result_pw.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.result_pw.setWordWrap(True)
        rc.addWidget(self.result_pw)
        copy_btn = QPushButton("📋  复制密码")
        copy_btn.setCursor(Qt.PointingHandCursor)
        copy_btn.clicked.connect(self._copy_password)
        rc.addWidget(copy_btn)
        rc.addStretch()
        self.result_card.setVisible(False)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(log_group)
        splitter.addWidget(self.result_card)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([600, 220])
        main_v.addWidget(splitter, 1)

        # ── Timer for stats ──
        self._timer = QTimer()
        self._timer.timeout.connect(self._update_stats)

        # ── Status bar ──
        self.statusBar = self.statusBar()
        self.lbl_status_dot = QLabel("● 就绪")
        self.lbl_status_dot.setObjectName("statusRunning")
        self.statusBar.addWidget(self.lbl_status_dot)
        self.lbl_algo = QLabel("")
        self.lbl_algo.setObjectName("statusRight")
        self.statusBar.addPermanentWidget(self.lbl_algo)
        self._apply_tool_status()

    def resizeEvent(self, event):
        """窗口缩放时截断文件名显示省略号"""
        super().resizeEvent(event)
        if hasattr(self, '_file_name_full'):
            metrics = self.file_name_label.fontMetrics()
            w = self.file_name_label.width()
            elided = metrics.elidedText(self._file_name_full, Qt.ElideRight, w)
            self.file_name_label.setText(elided)

    def _apply_tool_status(self):
        """Show engine availability in the status bar and disable GPU
        checkboxes when hashcat is missing (they'd silently fall back)."""
        parts = []
        if HASHCAT_BIN:
            parts.append("GPU: hashcat ✓")
        else:
            parts.append("GPU: 未安装hashcat")
        if BKCRACK_BIN:
            parts.append("KPA: bkcrack ✓")
        else:
            parts.append("KPA: 未安装bkcrack")
        self.lbl_algo.setText("  |  ".join(parts))

        gpu_available = bool(HASHCAT_BIN)
        for tab in (self.bf_tab, self.mask_tab, self.dict_tab):
            chk = getattr(tab, 'chk_hashcat', None)
            if chk is not None:
                chk.setEnabled(gpu_available)
                if not gpu_available:
                    chk.setChecked(False)

    # ── Theme ──
    def _toggle_theme(self):
        self._theme = "dark" if self._theme == "light" else "light"
        app = QApplication.instance()
        app.setStyleSheet(THEMES[self._theme])
        self.theme_btn.setText("☀" if self._theme == "dark" else "🌙")
        self._apply_theme_status_color()

    def _apply_theme_status_color(self):
        c = STATUS_COLORS[self._theme]
        if self._running:
            self.lbl_status_dot.setStyleSheet(f"color: {c['accent']}; font-weight: 600;")
        else:
            self.lbl_status_dot.setStyleSheet(f"color: {c['muted']};")

    # ── File browse ──
    def _browse_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "选择压缩包",
            "", "压缩文件 (*.zip *.rar *.7z *.tar.gz *.tgz *.tar.bz2 *.tbz2 "
                 "*.tar.xz *.txz *.cab *.arj *.iso);;所有文件 (*)")
        if not p:
            return
        self._load_file(p)

    def _load_file(self, p):
        """加载压缩包文件并更新文件卡片（浏览/拖拽共用）"""
        self._file_path = p
        fname = os.path.basename(p)
        self._file_name_full = fname
        self.file_name_label.setText(fname)
        # File size
        try:
            sz = os.path.getsize(p)
            if sz < 1024: s = f"{sz} B"
            elif sz < 1024*1024: s = f"{sz/1024:.1f} KB"
            else: s = f"{sz/(1024*1024):.1f} MB"
            self.file_size_label.setText(s)
        except:
            self.file_size_label.setText("")
        fmt = self._detect_format(p)
        self.format_label.setText(fmt.upper() if fmt else "")

    # ── Drag & drop 支持：拖压缩包文件进来直接加载，不用点浏览 ──
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            p = url.toLocalFile()
            if p and os.path.isfile(p):
                self._log(f"拖入压缩包: {os.path.basename(p)}")
                self._load_file(p)
                break
        event.acceptProposedAction()

    def _detect_format(self, path):
        low = path.lower()
        for ext, fmt in sorted(ALL_FORMATS.items(), key=lambda x: -len(x[0])):
            if low.endswith(ext):
                return fmt
        return None

    def _get_current_archive_type(self):
        return self._detect_format(getattr(self, '_file_path', ''))

    # ── Logging (structured with timestamp) ──
    def _log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.log_box.append(f'<span style="color:#9E9E9E">{ts}</span>  {msg}')
        sb = self.log_box.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ── Copy password ──
    def _copy_password(self):
        if self._found_pw:
            QApplication.clipboard().setText(self._found_pw)
            self._log("密码已复制到剪贴板")

    # ── Start ──
    def _start(self):
        path = getattr(self, '_file_path', '')
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "错误", "请先选择有效的压缩包文件")
            return
        atype = self._detect_format(path)
        if not atype:
            QMessageBox.warning(self, "错误", "无法识别文件格式")
            return

        self._running = True
        self._start_time = time.time()
        self._total_tried = 0
        self._found_pw = None
        self.progress_bar.setValue(0)
        self.lbl_pct.setText("0%")
        self.result_card.setVisible(False)
        self.log_box.clear()

        # Show status group, switch button to stop
        self.status_group.setVisible(True)
        self.start_btn.setText("■  停止破解")
        self.start_btn.setObjectName("stopBtn")
        self.start_btn.clicked.disconnect()
        self.start_btn.clicked.connect(self._stop)
        self.style().unpolish(self.start_btn)
        self.style().polish(self.start_btn)

        self.lbl_status_dot.setText("● 运行中")
        self.lbl_status_dot.setObjectName("statusRunning")
        self._apply_theme_status_color()

        algo_info = f"算法：{atype} | 哈希模式：{HASHCAT_MODES.get(atype, 'CPU')}"
        self.lbl_algo.setText(algo_info)

        self._timer.start(500)
        self._log("开始破解")

        tab_idx = self.mode_list.currentRow()
        if tab_idx == 0: self._start_bruteforce(path, atype)
        elif tab_idx == 1: self._start_mask(path, atype)
        elif tab_idx == 2: self._start_dict(path, atype)
        elif tab_idx == 3: self._start_kpa(path, atype)
        elif tab_idx == 4: self._start_crc32(path, atype)

    # ── Stop ──
    def _stop(self):
        self._running = False
        for w in self.workers:
            if hasattr(w, 'stop'): w.stop()
        self.workers.clear()
        self._timer.stop()
        self._reset_button()
        self._log("已停止")
        self.lbl_status_dot.setText("● 已停止")
        self.lbl_status_dot.setObjectName("statusError")
        self.lbl_status_dot.setStyleSheet(f"color: {STATUS_COLORS[self._theme]['error']};")

    def _reset_button(self):
        self.start_btn.setText("▶  开始破解")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.disconnect()
        self.start_btn.clicked.connect(self._start)
        self.style().unpolish(self.start_btn)
        self.style().polish(self.start_btn)

    # ── Found callback ──
    def _on_found(self, pw):
        self._found_pw = pw
        self._running = False
        self._timer.stop()
        for w in self.workers:
            if hasattr(w, 'stop'): w.stop()
        self.workers.clear()

        self._reset_button()
        self.progress_bar.setValue(100)
        self.lbl_pct.setText("100%")

        # Show result card
        self.result_pw.setText(pw)
        self.result_card.setVisible(True)
        self._log(f'<span style="color:#00C853;font-weight:600">密码已找到</span>')

        self.lbl_status_dot.setText("● 完成")
        self.lbl_status_dot.setObjectName("statusRunning")
        self.lbl_status_dot.setStyleSheet(f"color: {STATUS_COLORS[self._theme]['success']};")

    # ── Worker finished ──
    def _on_worker_finished(self):
        if self._found_pw or not self._running:
            return
        if any(w.isRunning() for w in self.workers):
            return
        self._running = False
        self._timer.stop()
        self._reset_button()
        self._log("破解完成，未找到密码")
        self.lbl_status_dot.setText("● 未找到")
        self.lbl_status_dot.setObjectName("statusError")
        self.lbl_status_dot.setStyleSheet(f"color: {STATUS_COLORS[self._theme]['error']};")

    def _on_hashcat_finished(self, ok, msg):
        if not self._found_pw:
            self._running = False
            self._timer.stop()
            self._reset_button()
            if ok:
                self._log(f"hashcat: {msg}")
            else:
                self._log(f"hashcat失败: {msg}")
                self.lbl_status_dot.setText("● 失败")
                self.lbl_status_dot.setObjectName("statusError")
                self.lbl_status_dot.setStyleSheet(f"color: {STATUS_COLORS[self._theme]['error']};")

    # ── Stats update ──
    def _update_stats(self):
        if not self._running:
            return
        elapsed = time.time() - self._start_time
        if elapsed < 60:
            self.lbl_time.setText(f"{elapsed:.0f}秒")
        else:
            self.lbl_time.setText(f"{int(elapsed//60)}分{int(elapsed%60)}秒")

    def _on_progress(self, count):
        self._total_tried += count
        if self._total_tried < 10000:
            self.lbl_tried.setText(f"{self._total_tried:,}")
        elif self._total_tried < 1000000:
            self.lbl_tried.setText(f"{self._total_tried/1000:.0f}千")
        else:
            self.lbl_tried.setText(f"{self._total_tried/1000000:.1f}百万")
        elapsed = time.time() - self._start_time
        if elapsed > 0:
            spd = self._total_tried / elapsed
            self.lbl_speed.setText(f"{spd:,.0f} 次/秒")

    def _on_speed(self, spd):
        self.lbl_speed.setText(f"{spd:,.0f} 次/秒")

    def _on_hashcat_progress(self, line):
        if "Progress" in line and ":" in line:
            try:
                pct_str = line.split(":")[1].strip().split()[0]
                pct = float(pct_str.replace("%", ""))
                self.progress_bar.setValue(int(pct))
                self.lbl_pct.setText(f"{int(pct)}%")
            except: pass
        # Log meaningful lines only
        if any(k in line for k in ["Speed", "Progress", "Cracked", "Started", "Stopped"]):
            self._log(line.strip())

    # ============================================================
    #  Attack dispatchers
    # ============================================================

    def _start_bruteforce(self, path, atype):
        charset, min_l, max_l = self.bf_tab.get_mask()
        if not charset:
            QMessageBox.warning(self, "错误", "字符集为空")
            self._stop(); return

        use_gpu = self.bf_tab.chk_hashcat.isChecked() and atype in GPU_FORMATS and HASHCAT_BIN

        if use_gpu:
            self._log(f"GPU加速已启用（模式：{HASHCAT_MODES.get(atype, '?')}）")
            hash_file, hash_err = _extract_hash_to_file(path, atype, self._log)
            result_file = _make_temp_path(suffix='.result')
            if hash_err:
                self._log(f"哈希提取失败: {hash_err}，回退CPU模式")
                use_gpu = False

        if use_gpu:
            hc_charset = _escape_hashcat_charset(charset)
            hc_mask = "?1" * min_l
            args = [
                "-m", HASHCAT_MODES[atype], "-a", "3",
                hash_file, "-1", hc_charset, hc_mask,
                "-o", result_file, "--outfile-format=2",
                "--force", "--potfile-disable",
            ]
            if max_l > min_l:
                args += ["--increment", "--increment-min", str(min_l), "--increment-max", str(max_l)]
            hw = HashcatWorker(args, hash_type=atype)
            hw.progress.connect(self._on_hashcat_progress)
            hw.found.connect(self._on_found)
            hw.finished_signal.connect(self._on_hashcat_finished)
            self.workers = [hw]
            hw.start()
        else:
            self._log(f"CPU暴力破解: {min_l}-{max_l}位, 字符集{len(charset)}个")
            n_threads = self.bf_tab.spin_threads.value()
            self._cpu_batch_brute(path, atype, charset, min_l, max_l, n_threads)

    def _cpu_batch_brute(self, path, atype, charset, min_l, max_l, n_threads):
        self._current_bf_len = min_l
        self._bf_charset = charset
        self._bf_max = max_l
        self._bf_n_threads = n_threads
        self._bf_path = path
        self._bf_atype = atype
        self._start_bf_length()

    def _start_bf_length(self):
        if self._current_bf_len > self._bf_max or not self._running:
            if not self._found_pw: self._on_worker_finished()
            return
        length = self._current_bf_len
        charset = self._bf_charset
        total = len(charset) ** length
        self._log(f"搜索 {length}位密码 ({total:,} 组合)")
        n = self._bf_n_threads
        chunk_size = max(1, total // n)
        self.workers = []
        for tid in range(n):
            start_idx = tid * chunk_size
            end_idx = total if tid == n - 1 else min(start_idx + chunk_size, total)
            if start_idx >= total: break
            chunk = _IndexChunk(charset, length, start_idx, end_idx)
            w = CPUWorker(self._bf_path, self._bf_atype, chunk, name=f"bf-{length}-{tid}")
            w.found.connect(self._on_found)
            w.progress.connect(self._on_progress)
            w.finished_signal.connect(self._on_bf_len_finished)
            self.workers.append(w)
            w.start()

    def _on_bf_len_finished(self):
        alive = [w for w in self.workers if w.isRunning()]
        if not alive:
            self._current_bf_len += 1
            if self._found_pw or not self._running: return
            self._start_bf_length()

    def _start_mask(self, path, atype):
        mask = self.mask_tab.mask_input.text().strip()
        if not mask:
            QMessageBox.warning(self, "错误", "请输入掩码模板")
            self._stop(); return
        use_gpu = self.mask_tab.chk_hashcat.isChecked() and atype in GPU_FORMATS and HASHCAT_BIN
        if use_gpu:
            hash_file, hash_err = _extract_hash_to_file(path, atype, self._log)
            result_file = _make_temp_path(suffix='.result')
            if hash_err:
                self._log(f"哈希提取失败: {hash_err}，回退CPU模式")
                use_gpu = False
        if use_gpu:
            self._log(f"GPU掩码攻击: {mask}")
            args = ["-m", HASHCAT_MODES[atype], "-a", "3", hash_file, mask,
                    "-o", result_file, "--outfile-format=2",
                    "--force", "--potfile-disable"]
            hw = HashcatWorker(args)
            hw.progress.connect(self._on_hashcat_progress)
            hw.found.connect(self._on_found)
            hw.finished_signal.connect(self._on_hashcat_finished)
            self.workers = [hw]; hw.start()
        else:
            self._log("回退CPU掩码模式")
            pws = self._expand_mask(mask)
            if not pws:
                QMessageBox.warning(self, "错误", "掩码无法展开"); self._stop(); return
            self._log(f"掩码展开 {len(pws)} 个候选")
            n_threads = 4
            chunk_size = max(1, len(pws) // n_threads)
            self.workers = []
            for i in range(0, len(pws), chunk_size):
                w = CPUWorker(path, atype, pws[i:i+chunk_size], name="mask")
                w.found.connect(self._on_found)
                w.progress.connect(self._on_progress)
                w.finished_signal.connect(self._on_worker_finished)
                self.workers.append(w); w.start()

    def _expand_mask(self, mask):
        mask_map = {
            '?l': string.ascii_lowercase, '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': "!@#$%^&*()_-+=[]{}|;:',.<>?/`~",
            '?a': string.ascii_letters + string.digits + "!@#$%^&*()_-+=[]{}|;:',.<>?/`~",
        }
        parts = []
        i = 0
        while i < len(mask):
            if mask[i] == '?' and i + 1 < len(mask):
                key = mask[i:i+2]
                parts.append(mask_map.get(key, mask[i+1]))
                i += 2
            else:
                parts.append(mask[i]); i += 1
        total = 1
        for p in parts:
            if len(p) > 1: total *= len(p)
        if total > 1_000_000:
            self._log(f"掩码组合数 {total:,} 过大(>1M)")
            return []
        return [''.join(combo) for combo in itertools.product(*[c if len(c) > 1 else c for c in parts])]

    def _start_dict(self, path, atype):
        dict_path = self.dict_tab.dict_path.text().strip()
        if not dict_path or not os.path.isfile(dict_path):
            QMessageBox.warning(self, "错误", "请选择有效的字典文件")
            self._stop(); return
        use_gpu = self.dict_tab.chk_hashcat.isChecked() and atype in GPU_FORMATS and HASHCAT_BIN
        use_rules = self.dict_tab.chk_auto_rule.isChecked()
        if use_gpu:
            hash_file, hash_err = _extract_hash_to_file(path, atype, self._log)
            result_file = _make_temp_path(suffix='.result')
            if hash_err:
                self._log(f"哈希提取失败: {hash_err}，回退CPU模式")
                use_gpu = False
        if use_gpu:
            self._log(f"GPU字典攻击: {dict_path}")
            args = ["-m", HASHCAT_MODES[atype], "-a", "0", hash_file, dict_path,
                    "-o", result_file, "--outfile-format=2",
                    "--force", "--potfile-disable"]
            if use_rules: args += ["-r", "best64.rule"]
            hw = HashcatWorker(args)
            hw.progress.connect(self._on_hashcat_progress)
            hw.found.connect(self._on_found)
            hw.finished_signal.connect(self._on_hashcat_finished)
            self.workers = [hw]; hw.start()
        else:
            self._log(f"CPU字典攻击: {dict_path}")
            pws = []
            with open(dict_path, 'r', errors='ignore') as f:
                for line in f:
                    pw = line.strip()
                    if pw: pws.append(pw)
            self._log(f"字典加载 {len(pws):,} 个密码")
            n_threads = 4
            chunk_size = max(1, len(pws) // n_threads)
            self.workers = []
            for i in range(0, len(pws), chunk_size):
                w = CPUWorker(path, atype, pws[i:i+chunk_size], name="dict")
                w.found.connect(self._on_found)
                w.progress.connect(self._on_progress)
                w.finished_signal.connect(self._on_worker_finished)
                self.workers.append(w); w.start()

    def _start_crc32(self, path, atype):
        if atype != 'zip':
            QMessageBox.warning(self, "限制", "CRC32碰撞仅支持ZIP格式")
            self._stop(); return
        entry_name = self.crc_tab.entry_name.text().strip()
        max_len = self.crc_tab.spin_max.value()
        charset_idx = self.crc_tab.charset_combo.currentIndex()
        charsets = [string.digits, string.ascii_lowercase + string.digits,
                    string.ascii_letters + string.digits,
                    string.ascii_letters + string.digits + "!@#$%^&*"]
        charset = charsets[charset_idx]
        self._log(f"CRC32碰撞: {entry_name}, 最大长度 {max_len}")

        self._crc_worker = CRC32Worker(path, entry_name, max_len, charset)
        self._crc_worker.progress.connect(self._log)
        self._crc_worker.done.connect(self._on_crc32_done)
        self.workers = [self._crc_worker]
        self._crc_worker.start()

    def _on_crc32_done(self, content):
        if not self._running:
            return
        if content:
            decoded = content.decode('utf-8', errors='replace')
            self._log(f'<span style="color:#00C853;font-weight:600">CRC32碰撞成功</span>')
            self._log(f"内容: {decoded}")
            self.result_pw.setText(decoded)
            self.result_card.setVisible(True)
            QMessageBox.information(self, "成功",
                f"碰撞成功!\n内容: {decoded}\n\n此为内容恢复，非密码破解")
        else:
            self._log("未找到碰撞")
        self._running = False
        self._timer.stop()
        self._reset_button()
        self.workers = []

    def _start_kpa(self, path, atype):
        entry_name = self.kpa_tab.entry_name.text().strip()
        plain_path = self.kpa_tab.plain_path.text().strip()
        offset = self.kpa_tab.spin_offset.value()
        if not entry_name:
            QMessageBox.warning(self, "错误", "请指定ZIP内文件名")
            self._stop(); return
        if not plain_path or not os.path.isfile(plain_path):
            QMessageBox.warning(self, "错误", "请选择明文文件")
            self._stop(); return
        self._log(f"已知明文攻击: {entry_name}")
        self._kpa_worker = KPAWorker(path, plain_path, entry_name, offset)
        self._kpa_worker.progress.connect(self._log)
        self._kpa_worker.done.connect(self._on_kpa_done)
        self.workers = [self._kpa_worker]
        self._kpa_worker.start()

    def _on_kpa_done(self, result, err):
        if not self._running:
            return
        if result:
            self._on_found(result)
        else:
            self._log(f"KPA失败: {err}")
            self._running = False
            self._timer.stop()
            self._reset_button()
        self.workers = []


# ============================================================
#  Entry Point
# ============================================================
def main():
    # 高 DPI 支持（必须在 QApplication 创建前设置，解决高分屏显示不全）
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setStyleSheet(LIGHT_QSS)
    window = MainWindow()
    # 初始窗口尺寸随 DPI 缩放（高分屏默认开大点，避免"拉大才显示全"）
    dpr = app.primaryScreen().devicePixelRatio()
    if dpr > 1.0:
        window.resize(int(960 * dpr), int(720 * dpr))
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
