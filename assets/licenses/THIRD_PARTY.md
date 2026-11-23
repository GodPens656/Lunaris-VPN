# Third-party components

Lunaris VPN source code is GPL-3.0-or-later. The complete license is in `LICENSE`.
The name Lunaris VPN does not imply affiliation with sing-box or SagerNet.

| Component | License / source |
| --- | --- |
| sing-box 1.14.4, Windows executable | GPL-3.0-or-later; upstream additionally prohibits implying association without consent. Original notice preserved in assets/licenses/sing-box-LICENSE. [Source at the matching tag](https://github.com/SagerNet/sing-box/tree/v1.14.4), commit c005f35300ce76427dc285481ec5695f5b179cd2 |
| Xray-core 26.11.9, Windows and Android executables | MPL-2.0; official [release](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9), [matching source](https://github.com/XTLS/Xray-core/tree/v26.11.9). Original LICENSE preserved in assets/licenses/xray-LICENSE. Archive and executable SHA-256 values pinned in scripts/fetch_core.py; Android executes the upstream binary as libxray.so in a separate OS process |
| Mihomo 1.19.34, Windows and Android executables | GPL-3.0; official [release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34), [matching source](https://github.com/MetaCubeX/mihomo/tree/v1.19.34). Original LICENSE preserved in assets/licenses/mihomo-LICENSE. Archive, executable and license SHA-256 values pinned in scripts/fetch_core.py; Android executes upstream binaries as libmihomo.so in a separate OS process |
| FlClashCore v0.9.4, Tauri Windows and Android | GPL-3.0. [FlClash source and build inputs](https://github.com/chen08209/FlClash/tree/89791d7c11978bf9b580ba71bffcb00506a17659) and [Mihomo fork](https://github.com/chen08209/Clash.Meta/tree/5b453f80dbcee6b3ecfb0415bcace24a48c88707). Windows extracts the core from the official FlClash portable archive. Android builds it with Lunaris's JNI bridge using `scripts/build_flclash_android.py`. See `GPL-3.0-or-later.txt`. |
| Wintun, Windows Xray TUN | [WireGuard Wintun](https://www.wintun.net/), redistributed unmodified from the pinned Xray Windows archive under the Prebuilt Binaries License in `wintun-LICENSE`. |
| Android libbox.aar | sing-box-derived native library, GPL-3.0-or-later obligations apply. **Third-party prebuilt binary**, [release](https://github.com/singbox-android/libbox/releases/tag/1.14.4), [publisher repository](https://github.com/singbox-android/libbox). Reproducibility and exact correspondence to upstream have not been established. Pinned asset checksum is in README and fetch_core.py |
| libcronet.dll in the official Windows archive | Chromium/Cronet, BSD and included dependency licenses; [Chromium source](https://chromium.googlesource.com/chromium/src/). Retained as a companion of the upstream archive. The supported Go TLS/QUIC paths were tested without invoking a Cronet transport |
| Flet 1.0.3 (legacy tests only; not in 0.6.0 binaries) | Apache-2.0; [source](https://github.com/flet-dev/flet/tree/v1.0.3) |
| Twemoji 14.0.2 country flag SVGs | Graphics by Twitter, Inc and other contributors, CC-BY-4.0; [matching source](https://github.com/twitter/twemoji/tree/v14.0.2). Unmodified graphics are bundled in src/sever/flag_assets, renamed to country codes. Original license preserved in assets/licenses/twemoji-LICENSE-GRAPHICS |
| Flutter engine/framework (legacy builds only) | BSD-3-Clause and dependency notices; [source](https://github.com/flutter/flutter). Flutter build bundles its generated NOTICES |
| Tauri 2 / Wry / Tao | MIT or Apache-2.0; [Tauri source](https://github.com/tauri-apps/tauri). Versions and transitive dependencies pinned in app/src-tauri/Cargo.lock |
| Chaquopy 17.0.0, Android Python runtime | MIT; [source](https://github.com/chaquo/chaquopy). Android cryptography 42.0.8 wheel is used only by the QUIC latency probe; Windows cryptography is 46.0.3 |
| dayplanner | Architecture reference only: [MixiYT/dayplanner](https://github.com/MixiYT/dayplanner), Apache-2.0. No planner logic, artwork or source files are bundled |
| CPython | Python Software Foundation license, including bundled dependency notices; [source](https://github.com/python/cpython), [Android runtime](https://github.com/chaquo/chaquopy) |
| HTTPX/httpcore/h11/certifi/idna/anyio/sniffio/socksio | Their own MIT/BSD/MPL and other package license notices, retained by packaging where provided. [HTTPX](https://github.com/encode/httpx/tree/0.28.1); certifi's Mozilla CA bundle is MPL-2.0 |
| Kotlin / kotlinx.coroutines | Apache-2.0; [Kotlin](https://github.com/JetBrains/kotlin), [coroutines](https://github.com/Kotlin/kotlinx.coroutines) |
| Dart JNI support (legacy builds only) | BSD-3-Clause; [dart-lang/native](https://github.com/dart-lang/native) |
| cryptography (Windows 46.0.3, Android 42.0.8) | Apache-2.0 or BSD-3-Clause; used by the QUIC latency probe; TLS for VPN traffic is implemented by the selected native core |
| pytest, pytest-asyncio (development only) | MIT; test tools, excluded from production |

Before distributing a binary to other people, provide the corresponding source
and required notices for the included GPL components, including their build
inputs/modifications. The third-party Android release provides a download, but
we have not verified a reproducible mapping to an exact source/build. The
upstream CI workflow offers a route to build from a fixed official commit; it
has not yet been executed. Do not describe that CI route or the downloaded AAR
as a verified official Android release.

This table records the direct components and their provenance; it is not a
complete license audit of every transitive dependency. Python package licenses
are retained where provided by the packager. Keep the full
portable Windows folder, these project notices and the matching source when
sharing a development build.
