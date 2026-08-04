# ArchiveCracker 压缩包密码破解工具

压缩包密码暴力破解工具，支持 ZIP / RAR / 7Z / TAR.GZ / TAR.BZ2 / TAR.XZ / CAB / ARJ / ISO。

## 功能

- 🚀 5 种攻击模式：暴力破解 / 掩码攻击 / 字典攻击 / CRC32碰撞 / 已知明文(KPA)
- ⚡ GPU 加速（hashcat）+ CPU 多线程双后端，GPU 不可用时自动回退
- 📦 支持 ZIP、RAR、7Z 等 9 种格式
- 🎯 实时显示破解速度、已尝试数量、用时
- 🎨 浅色/深色双主题（默认浅色，蓝色主色）

## Windows 免安装版（推荐）

从 Releases 或 Actions artifact 下载 `ArchiveCracker-windows.zip`：

1. 解压得到 `ArchiveCracker/` 文件夹
2. **整个文件夹一起移动**（不要只拿 exe），`tools/` 里的 hashcat / bkcrack / john 是破解引擎
3. 双击 `ArchiveCracker.exe`

> tools/ 已内置 hashcat（GPU引擎）、bkcrack（已知明文攻击）、john（哈希提取），开箱即用。

## 直接运行 Python

```bash
pip install -r requirements.txt
python cracker.py
```

## 依赖

- Python 3.8+
- PyQt5、rarfile、py7zr、pyzipper
- 可选：hashcat（GPU）、bkcrack（KPA）、john（哈希提取）— 缺失时自动回退 CPU 或提示

## 常见问题

- **GPU 加速是灰的**：未检测到 hashcat，确认 `tools/hashcat/hashcat.exe` 存在
- **KPA 提示未安装 bkcrack**：确认 `tools/bkcrack/bkcrack.exe` 存在
- **杀毒软件误报**：PyInstaller 打包的工具常见误报，添加信任即可
