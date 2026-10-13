# 👻 SpecterNet

A full-featured network sniffer and analysis suite with a PyQt6 GUI. Live packet capture, protocol dissection, plaintext credential detection, real-time traffic graphs, and a built-in port scanner — all in one dark-themed desktop app.

> ⚠️ **Requires root/sudo for packet capture. For authorized testing and CTF use only.**

---

## ⚙️ Installation

### Option 1: Development Install (Recommended)
```bash
git clone https://github.com/H3M4N1H/SpecterNet.git
cd SpecterNet
pip install -e .

# Run anywhere
sudo specternet
```

### Option 2: Basic Install
```bash
pip install -r requirements.txt
sudo python main.py
```

---

## 🚀 Features

### 📦 Packet Capture
- Select any network interface
- BPF filter support (`tcp port 80`, `host 192.168.1.1`, etc.)
- Live packet table with protocol color coding
- Click any packet → full layer-by-layer dissection
- Search/filter packets in real-time
- Save and load PCAP files

### 🔑 Credential Sniffing
Detects plaintext credentials in:
- HTTP POST (login forms — username/password fields)
- FTP (USER/PASS commands)
- Telnet (keystrokes)
- SMTP AUTH

### 📊 Traffic Graph
- Real-time bytes/sec graph (last 60 seconds)
- Protocol distribution breakdown with percentages
- Live status bar showing packets, bytes, speed

### 🔍 Port Scanner
- Threaded TCP port scanner (100 concurrent threads)
- Top 1024 ports + known service ports
- Service detection via banner grabbing
- Color-coded open/closed results

---

## 🖥️ UI Layout

```
┌──────────────────────────────────────────────────────────┐
│  [Interface ▼] [BPF Filter] [▶ Start] [⏹ Stop] [💾 Save] │
├──────────────┬───────────────────────────────────────────┤
│ 📊 Traffic   │  🔍 Filter: ____________                   │
│ Graph        ├───────────────────────────────────────────┤
│              │ [📦 Packets] [🔑 Credentials] [🔍 Scanner] │
│ 📡 Protocol  ├───────────────────────────────────────────┤
│ Distribution │  #   Time     Src→Dst       Proto  Info   │
│              │  1   12:00:01 192.1.1:1234  HTTP   GET /  │
│              │  2   12:00:02 8.8.8.8:80    TCP    SYN    │
│              ├───────────────────────────────────────────┤
│              │ [Packet Detail — Layer dissection]        │
└──────────────┴───────────────────────────────────────────┘
│ Packets: 142  Bytes: 94.2 KB  Speed: 12.3 KB/s  ● Capture│
└──────────────────────────────────────────────────────────┘
```

---

## 🎨 Protocol Colors

| Protocol | Color |
|----------|-------|
| TCP | Blue |
| UDP | Green |
| HTTP | Orange |
| HTTPS | Pink |
| DNS | Purple |
| FTP | Yellow |
| ICMP | Cyan |
| ARP | Red |

---

## 📁 Project Structure

```
SpecterNet/
├── main.py                    # Entry point
├── core/
│   ├── sniffer.py             # Scapy capture engine
│   ├── analyzer.py            # Protocol dissection + cred detection
│   ├── scanner.py             # Threaded port scanner
│   └── stats.py               # Traffic stats aggregator
├── gui/
│   ├── main_window.py         # Main PyQt6 window
│   ├── packet_table.py        # Live packet table
│   ├── traffic_graph.py       # Real-time graph widget
│   ├── cred_panel.py          # Credentials panel
│   └── scan_panel.py          # Port scanner panel
└── utils/
    └── helpers.py             # Utilities
```

---

## 📦 Dependencies

```
PyQt6    — GUI framework
scapy    — Packet capture and analysis
```

---

## 👤 Author

**Dreadonyx** — [github.com/H3M4N1H](https://github.com/H3M4N1H)
