# IP_Scan_Set_CLI v1.0.4

## 執行方式
1. 以系統管理員身分執行：雙擊 **IP_Scan_Set_CLI v1.0.4.exe**（或右鍵→以系統管理員執行）。

> 註：需管理員權限才能套用/還原網路設定與進行預測試（暫掛 IP、寫入臨時路由）。

---

## 功能

### 子網掃描
- 針對整個 CIDR（預設 `192.168.131.0/24`）逐一探測 `1~253`，分出「已使用 / 可用」。
- 支援排除清單（預設排除閘道 `192.168.131.254`）、並行掃描（workers）、逾時（timeout）可調。

### 網卡選擇與相容性
- 自動列出「可用有線 IPv4」網卡（排除 Loopback、Wi‑Fi），支援中文介面名稱。
- 內建安全解碼（避免 `cp950`/`UnicodeDecodeError`）。

### 「不變更現有設定」的預測試
- 對每個候選 IP 以 **暫掛次要位址（alias）** + **/32 主機路由** 方式做真連線測試，不動原本設定。
- 模式可選：`internet`（外網） / `intranet`（僅驗證 GW 可達） / `hybrid`。
- 測試 TCP 連線時會綁定來源 IP，並為每個目標臨時新增/刪除主機路由。

### 測試目標來源（可自訂）
- 讀取 EXE 同資料夾 `targets.txt`（格式：`主機或IP:Port 說明`；支援主機名，會用該介面 DNS 解析）。
- 自動補齊目標：該介面 DNS（:53）、系統 Proxy（若設定）、Cloudflare `1.1.1.1`/`1.0.0.1`（備援）。
- 執行前會列出本次實際使用的測試目標。

### 一鍵套用網路設定
- 互動式從「**預測試通過清單**」中選擇要套用的 IP。
- 套用靜態 `IP/Mask/GW`。
- **DNS 改為沿用該網卡目前的公司 DNS**；若未偵測到則不改動。`netsh` 設定採 `validate=no`，避免公司網路阻擋直連時誤判失敗。
- 提供 **還原 DHCP**（位址與 DNS）功能。

### 連線驗證與輸出
- 套用後再做外網檢查：ICMP `8.8.8.8` / `1.1.1.1`、`www.google.com` 解析與多個 TCP 目標（含臨時主機路由）。
- 全部輸出於命令列，**結尾停住等待 Enter**，避免「跑完即關」。

### 錯誤處理
- 例外時輸出 traceback 並停住；子程序輸出一律經過安全解碼避免亂碼/崩潰。

### 使用流程摘要
1) 掃描整段 → 2) 對所有候選做「不變更設定」預測試 → 3) 顯示通過名單讓你選 → 4) 一鍵套用靜態設定（沿用公司 DNS）→ 5) 再次驗證並列印結果。

---

## 適用環境
- Windows 11 / Windows 10 22H2 以上（需系統管理員權限）。

---

## 檔案與設定

### `targets.txt`（可選）
- 放在 EXE 同資料夾，每行一個目標：
  ```txt
  proxy.company.local:8080 公司Proxy
  203.66.181.1:443 公司出口FW
  1.1.1.1:443 Cloudflare
  ```
- 若寫主機名，會以**所選網卡的 DNS** 解析為 IP 後再做 TCP 測試。
- 實務建議：加入公司 Proxy 或一定可直連的內部/外部 IP:Port，以符合企業網路策略。

---

## 更新紀錄

### v1.0.4 — 企業網路相容（Proxy/DNS/策略）
- 不再強制把 DNS 設為 8.8.8.8；改為先讀取並沿用該網卡原本的公司 DNS，`netsh ... validate=no` 以避免被防火牆驗證擋下。
- 新增 `targets.txt`：可於 EXE 同資料夾自訂測試目標（`主機名或IP:port 說明`）。主機名會用該介面 DNS 解析後測試。
- 內建測試目標改為以「該介面 DNS」與「系統 Proxy」為主，並於畫面列出本次實際驗證的目標。

### v1.0.3 — 「不變更現有設定」的預測試
- 新增預測試：對候選 IP 以「暫掛別名 (`netsh add address`) + /32 主機路由 (`route add IF <index>`) + socket 綁定來源位址」做實連測試。
- 支援 `internet` / `intranet` 模式（外網走 TCP 目標、內網驗證 GW 可達）。
- 預測試通過清單讓使用者再選擇實際套用；預設排除閘道 `192.168.131.254`。
- 修正 f-string 中 PowerShell 大括號造成的語法/靜態分析誤報。

### v1.0.2 — 介面/編碼與 `netsh` 相容
- 列網卡改採 PowerShell（`Get-NetAdapter` / `Get-NetIPInterface`），排除 Loopback/Wi‑Fi，支援中文字介面名稱。
- 修正 Windows `cp950`/UnicodeDecodeError：所有 `subprocess` 輸出改自行 `safe_decode`。
- `netsh set dnsservers` 語法修正：`name="介面" source=static address=<IP> register=primary`。
- 可一次列出整段可用 IP，不再只顯示 50 筆。

### v1.0.1 — 啟動/權限
- 加入權限偵測與自動提權（`ShellExecuteW runas`），非系統管理員時給出明確提示。

### v1.0.0 — 初版
- 掃描整個 CIDR（預設 `192.168.131.0/24`），以 ping 判斷使用/未用。
- 互動式選擇可用 IP，使用 `netsh` 一鍵套用 `IP/Mask/GW` 與 DNS（原先固定 `8.8.8.8`）。
- 提供 `--list-iface` 列網卡、`--dhcp` 還原 DHCP、`--workers` / `--timeout-ms` 等參數。
- 簡單外網檢查：`8.8.8.8` 及 `www.google.com` ping 測試。
