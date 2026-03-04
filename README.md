ZMap: The Internet Scanner
==========================

![Build Status](https://github.com/zmap/zmap/actions/workflows/cmake.yml/badge.svg)

ZMap is a fast stateless single packet network scanner designed for Internet-wide network
surveys. On a typical desktop computer with a gigabit Ethernet connection, ZMap
is capable of scanning the entire public IPv4 address space on a single port in 
under 45 minutes. For example, sending a TCP SYN packet to every IPv4 address
on port 25 to find potential SMTP servers. With a 
10gigE connection and either [netmap](http://info.iet.unipi.it/~luigi/netmap/) or 
[PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/), ZMap can scan 
the IPv4 address space in under 5 minutes.

ZMap operates on GNU/Linux, Mac OS, and BSD. ZMap currently has fully implemented
probe modules for TCP SYN scans, ICMP, DNS queries, UPnP, BACNET, and can send a
large number of [UDP probes](https://github.com/zmap/zmap/blob/master/examples/udp-probes/README).
If you are looking to do more involved scans (e.g., banner grab or TLS handshake), 
take a look at [ZGrab 2](https://github.com/zmap/zgrab2), ZMap's sister project 
that performs stateful application-layer handshakes.

> [!CAUTION]
> Ethical Scanning
> 
> Performing Internet-wide scans can have serious ethical and operational implications. While ZMap defaults to usually safe
> settings, it is your responsibility to ensure that you're a good internet citizen. Rules of thumb are to scan at the
> slowest speed necessary, scan slower if you're scanning a smaller target space, and provide a way for network operators
> to opt-out. More information can be found [here](https://github.com/zmap/zmap/wiki/Getting-Started-Guide#%EF%B8%8F-warning-on-scanning-rate).


Using ZMap
----------

ZMap is easy to use. A simple scan of the entire IPv4 space on TCP port 80 can be performed with the following command (requires root privileges):

```sh
sudo zmap -p 80
```

```
$ sudo zmap -p 80
...
 0:00 0%; send: 5 1 p/s (185 p/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
52.8.107.196
...
 0:01 0%; send: 10327 10.3 Kp/s (10.1 Kp/s avg); recv: 118 118 p/s (115 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 1.14%
````

If you haven't used ZMap before, we have a step-by-step [Getting Started Guide](https://github.com/zmap/zmap/wiki/Getting-Started-Guide) that details how to perform basic scans. Documentation about all of ZMap's options and more advanced functionality can be found in our [Wiki](https://github.com/zmap/zmap/wiki). For best practices, see [Scanning Best Practices](https://github.com/zmap/zmap/wiki/Scanning-Best-Practices). 

If you have questions, please first check our [FAQ](https://github.com/zmap/zmap/wiki/FAQ). Still have questions? Ask the community in [Github Discussions](https://github.com/zmap/zmap/discussions/categories/q-a). Please do not create an Issue for usage or support questions.

Installation
------------

The latest stable release of ZMap is [4.3.4](https://github.com/zmap/zmap/releases/tag/v4.3.4) and supports Linux, macOS, and
BSD. See [INSTALL](INSTALL.md) for instructions on to install ZMap through a package manager or from source.

Windows Build and Usage (This Fork)
-----------------------------------

This repository contains Windows send/receive backends (XDP + Npcap) in addition to the upstream Unix paths.

### Prerequisites

1. MSYS2 MinGW64 toolchain (for `gcc`, `cmake`, `mingw32-make`), for example under `C:\msys64\mingw64\bin`.
2. Npcap installed on the machine (runtime DLLs under `C:\Windows\System32\Npcap\`).
3. Npcap SDK headers/libs under `C:\npcap-sdk` (or set `NPCAP_SDK` environment variable).
4. Optional for XDP backend: XDP for Windows runtime (`xdpapi.dll` available in `PATH`).

### Build (PowerShell)

```powershell
$env:PATH = 'C:\msys64\mingw64\bin;' + $env:PATH
$cmake = 'C:\msys64\mingw64\bin\cmake.exe'
& $cmake -S . -B build_ascii -G 'MinGW Makefiles' -DCMAKE_BUILD_TYPE=Release
& $cmake --build build_ascii --target zmap -j 8
```

### Package `zmap.exe` with runtime DLLs

`src/CMakeLists.txt` already copies MinGW + Npcap runtime DLLs to the executable directory after build. To stage a distributable folder with all dynamic libraries:

```powershell
$dist = 'dist\zmap-win64'
New-Item -ItemType Directory -Force $dist | Out-Null
Copy-Item build_ascii\src\zmap.exe $dist
Copy-Item build_ascii\src\*.dll $dist
```

Typical DLLs in `build_ascii\src\`:
`libpcap.dll`, `Packet.dll`, `wpcap.dll`, `libwinpthread-1.dll`, `libgcc_s_seh-1.dll`, `libgmp-10.dll`, `libjson-c-5.dll`, `libiconv-2.dll`, `libunistring-5.dll` (and `xdpapi.dll` when XDP runtime is installed).

### Windows usage

Run from an elevated terminal (Administrator), and specify the Npcap interface:

```powershell
.\build_ascii\src\zmap.exe -p 80 -i '\Device\NPF_{YOUR-ADAPTER-GUID}' -o result.csv
```

Backend control via environment variables:

- `ZMAP_WIN_BACKEND=auto|xdp|npcap|rawip` (default `auto`, prefers XDP then falls back to Npcap).
- `ZMAP_WIN_RX_BACKEND=xdp` to enable XDP receive path.
- `ZMAP_WIN_XDP_RX_MULTI=1` to try opening multiple RX queues (queue 0..N).
- `ZMAP_WIN_XDP_RX_QUEUE=<id>` to pin XDP RX to a single queue.

### Why Windows host is slower than WSL2 on RTL8125

On common Realtek RTL8125 Windows drivers, XDP works in Generic mode (NDIS/LWF path), not Native mode (miniport fast path).  
WSL2 traffic uses Hyper-V guest networking (`netvsc` + VMQ/VMBus data path), which bypasses most host-side LWF overhead.  
The host/root partition cannot use guest `netvsc` semantics directly, so this performance gap is architectural on this NIC/driver stack.

To get closer to WSL2 performance from a native Windows process, use hardware/driver stacks that support Native XDP.

Architecture
------------

More information about ZMap's architecture and a comparison with other tools can be found in these research papers:

 * [ZMap: Fast Internet-Wide Scanning and its Security Applications](https://zmap.io/paper.pdf)
 * [Zippier ZMap: Internet-Wide Scanning at 10 Gbps](https://jhalderm.com/pub/papers/zmap10gig-woot14.pdf)
 * [Ten Years of ZMap](https://arxiv.org/pdf/2406.15585)

Citing ZMap
-----------

If you use ZMap for published research, please cite the original research paper:

```
@inproceedings{durumeric2013zmap,
  title={{ZMap}: Fast Internet-wide scanning and its security applications},
  author={Durumeric, Zakir and Wustrow, Eric and Halderman, J Alex},
  booktitle={22nd USENIX Security Symposium},
  year={2013}
}
```

Citing the ZMap paper helps us to track ZMap usage within the research community and to pursue funding for continued development.


License and Copyright
---------------------

ZMap Copyright 2024 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
