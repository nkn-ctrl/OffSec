# OFFSEC試験（PEN-200）情報収集・列挙チートシート

ペネトレーションテストにおける情報収集（Information Gathering）および列挙（Enumeration）は、アタックサーフェスを体系的にマッピングし、後続の脆弱性特定や攻撃フェーズの成否を決定づける極めて重要なプロセスです。本ドキュメントは、PEN-200カリキュラムに基づき、受動的（パッシブ）偵察から能動的（アクティブ）スキャン、主要プロトコル別の列挙、さらにWindows環境下での「Living Off the Land（LOLBAS）」手法に至るまで、実技試験および演習で直ちに使用できる実践的なコマンドと構文を網羅したリファレンスです。

---

## 1. パッシブ情報収集（OSINT & Web Reconnaissance）

ターゲットと直接的なパケット通信を行わず、公開データベースやサードパーティのインフラを通じて組織のインフラ、人員、技術スタックを特定します。

### 1.1 WHOIS によるドメイン・IP列挙
WHOISプロトコル（TCP 43）を用いて登録機関のデータベースに問い合わせ、ネームサーバー、管理者連絡先、CIDRブロックを特定します。

```bash
# 正引きWHOISクエリ（指定した内部/外部WHOISサーバーを使用）
whois megacorpone.com -h <WHOIS_SERVER_IP>

# 逆引きWHOISクエリ（IPアドレスから所属組織、ISP、CIDR範囲を特定）
whois <TARGET_IP> -h <WHOIS_SERVER_IP>
```

- **主要な着目フィールド**:
  - `Name Server`: 権威DNSサーバーのホスト名
  - `Registrant / Admin / Tech Contact`: 担当者名、メールアドレス、電話番号
  - `NetRange / CIDR`: 組織が所有するIPアドレス範囲

### 1.2 Google Hacking (Google Dorks)
検索エンジンの検索演算子を組み合わせて、意図せずインデックスされた機密ファイル、認証情報、管理インターフェースを抽出します。

```text
# ドメイン全体のインデックス特定
site:megacorpone.com

# サブドメインの探索（wwwを除外）
site:megacorpone.com -www

# ディレクトリリスティング（設定ミスによるファイル一覧表示）の探索
site:megacorpone.com intitle:"index of" "parent directory"

# バックエンド技術・スクリプトの探索
site:megacorpone.com ext:php | ext:html | ext:asp | ext:jsp

# 設定ファイルおよび機密データの探索
site:megacorpone.com ext:env | ext:yaml | ext:json | ext:xml
site:megacorpone.com ext:conf | ext:ini | ext:log
site:megacorpone.com "password" filetype:txt | filetype:csv

# 認証・管理ページの探索
site:megacorpone.com inurl:"admin"
site:megacorpone.com inurl:"login"
site:megacorpone.com inurl:"upload"

# 外部リポジトリ連携の痕跡探索
site:megacorpone.com intext:"github.com" OR intext:"gitlab.com"
```

### 1.3 公開コードリポジトリ・外部サービスの調査
- **GitHub検索**:
  - `path:users` などの検索演算子でコミットされたユーザーリストや設定ファイル（例: `xampp.users`）を特定。
  - **自動シークレットスキャンツール**: `Gitleaks` や `Gitrob` を使用して、正規表現およびエントロピーベースのスキャンによりコミット履歴内のAPIキーやパスワードを検出。
- **Shodan**:
  - `hostname:megacorpone.com` を検索し、公開されているポート、OpenSSH等の詳細バージョン、サービスバナー、既知の脆弱性（CVE）をパッシブに確認。
- **Webサイトセキュリティ設定分析**:
  - `Security Headers`: `Content-Security-Policy` や `X-Frame-Options` 等の防御ヘッダーの有無からサーバーハードニング状況を評価。
  - `Qualys SSL Labs`: サポートされているTLSバージョン（レガシーなTLS 1.0/1.1の有無）や暗号スイートの安全性を評価。

---

## 2. DNS 列挙 (Active & Living Off the Land)

DNSレコードの調査は、ターゲットネットワーク上のアクティブなホストやサーバーの役割を把握するための出発点となります。

### 2.1 Linux (host コマンド & Bashスクリプト)
Linux環境の標準的なコマンドを用いたDNSレコードの直接問い合わせおよびブルートフォース手法です。

```bash
# 基本的なAレコードの正引き
host www.megacorpone.com

# メールサーバー（MXレコード）の照会（優先度の数値が低いほど高優先）
host -t mx megacorpone.com

# TXTレコードの照会（検証文字列や内部情報の確認）
host -t txt megacorpone.com

# ワードリストを使用した正引きサブドメインブルートフォース
for ip in $(cat list.txt); do host $ip.megacorpone.com; done

# 指定IP範囲に対する逆引き（PTRレコード）ブルートフォース（未解決・タイムアウトを除外）
for ip in $(seq 64 79); do host 167.114.21.$ip; done | grep -Ev "not found|timed out"
```

### 2.2 DNS自動化ツール (dnsrecon, dnsenum, gobuster)
複数のレコードタイプの網羅的収集やゾーン転送試行を自動化します。

```bash
# dnsrecon: 標準スキャン（SOA, NS, A, MX, TXT等の一括取得）
dnsrecon -d megacorpone.com -t std

# dnsrecon: 辞書ファイルを用いたサブドメインブルートフォース
dnsrecon -d megacorpone.com -D list.txt -t brt

# dnsenum: ゾーン転送の試行、サブドメイン列挙、クラスCネットワーク範囲の抽出
dnsenum megacorpone.com

# gobuster: DNSモジュールによるマルチスレッドブルートフォース
gobuster dns -d megacorpone.com -w wordlist.txt -t 10
```

### 2.3 Windows LOLBAS (nslookup)
Windowsクライアントを侵害した後に、追加ツールのインストールなしで内部DNSを調査する手法です。

```cmd
:: デフォルトDNSサーバーを使用したホスト名の正引き
nslookup mail.megacorptwo.com

:: DNSサーバーを指定した特定のレコード（TXT等）の照会
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

---

## 3. ネットワークスイープ & ポートスキャン

ネットワーク上の稼働ホストの特定と、各ホストで動作しているトランスポート層ポートおよびサービスの検出手順です。

### 3.1 Nmap スイープ & ホスト検出
ネットワーク全体から稼働中のマシンのみを高速かつ効率的に洗い出します。

```bash
# ネットワークスイープ（ICMP Echo, TCP SYN 443, TCP ACK 80, ICMP Timestamp等）
nmap -sn 192.168.50.1-253

# grep可能形式（-oG）で保存し、稼働中ホストのIPアドレスのみを抽出
nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2

# 特定ポート（例: 80番HTTP）が開いているホストの特定とIP抽出
nmap -p 80 192.168.50.1-253 -oG web-sweep.txt
grep open web-sweep.txt | cut -d" " -f2
```

### 3.2 Nmap ポートスキャン手法
権限やネットワーク経路（プロキシ経由など）、調査目的に応じて適切なスキャン手法を選択します。

```bash
# 上位1000ポートスキャン（デフォルト）
# ※ホストがpingに応答しない場合は -Pn を付与
nmap 192.168.50.149 -Pn

# 全TCPポートスキャン（1〜65535）
nmap -p 1-65535 192.168.50.149

# TCP SYNステルススキャン（root権限必須、3ウェイハンドシェイク未完了、高速）
sudo nmap -sS 192.168.50.149

# TCP Connectスキャン（非root環境、またはプロキシ経由時に使用）
nmap -sT 192.168.50.149

# UDPポートスキャン（ポート161等には専用プローブ、その他はICMP port-unreachで判定）
sudo nmap -sU 192.168.50.149

# TCP SYNスキャンとUDPスキャンの同時実行
sudo nmap -sU -sS 192.168.50.149

# 上位20ポートに対してOS検出、スクリプトスキャン、トレースルートを実行（-A）
nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt
```

### 3.3 詳細分析: バナーグラビング、OS検出、NSE
ポート検出後、正確なサービスバージョンと基盤OSを特定します。

```bash
# サービスバージョン検出のみを素早く実行
nmap -sV <TARGET_IP>

# 積極的なスキャン（OS検出、バージョン検出、デフォルトスクリプト、Traceroute）
nmap -sT -A <TARGET_IP>

# OSフィンガープリンティング（TTLやTCPウィンドウサイズから推測）
sudo nmap -O <TARGET_IP> --osscan-guess

# Nmap Scripting Engine (NSE) の実行
nmap --script <script-name> <TARGET_IP>

# NSEスクリプトのヘルプ・使用方法の確認
nmap --script-help <script-name>
```

### 3.4 Netcat による軽量スキャン
外部スキャナーが持ち込めない環境や、特定ポートの疎通確認を行う際に活用します。

```bash
# TCPポートスキャン（-w 1: 1秒タイムアウト, -z: ゼロI/Oモード）
nc -nvv -w 1 -z 192.168.50.152 3388-3390

# UDPポートスキャン（-u オプションを付与）
nc -nv -u -z -w 1 192.168.50.149 120-123
```

### 3.5 Windows LOLBAS によるポートスキャン (PowerShell)
侵害したWindows端末からピボット先や内部ネットワークを調査するコマンドです。

```powershell
# 単一ポートの疎通確認
Test-NetConnection -Port 445 192.168.50.151

# PowerShellワンライナーによるTCPポートスキャン（1〜1024番ポート）
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

---

## 4. サービス別列挙 (Service-Specific Enumeration)

開いているポートを発見した後は、プロトコル固有の対話手法やツールを用いて認証情報やユーザー名、システム内部情報を抽出します。

### 4.1 SMB / NetBIOS 列挙 (TCP 139 / 445)
ファイル共有、ユーザー一覧、ドメイン名、共有フォルダーを特定します。

```bash
# NmapによるSMB/NetBIOSポート（139, 445）のスキャン
nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254

# nbtscan によるNetBIOS名およびMACアドレスの収集（UDP 137）
sudo nbtscan -r 192.168.50.0/24

# Nmap NSEスクリプトによるSMB/OS情報収集
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152

# enum4linux による総合的なSMB列挙（ユーザー、グループ、共有等）
enum4linux <TARGET_IP>
```

**Windows端末からのSMB共有確認 (net view)**:
```cmd
:: リモートホスト上の全共有（管理共有 C$, ADMIN$, IPC$ を含む）を一覧表示
net view \\<HOSTNAME_OR_IP> /all
```

---

### 4.2 SMTP 列挙 (TCP 25)
SMTPサーバーに対して`VRFY`コマンドを発行し、内部ユーザーアカウントの有無を検証します。

```bash
# Netcatでの手動VRFY検証（252: 受理/有効候補, 550: 存在しないユーザー）
nc -nv 192.168.50.8 25
VRFY root
VRFY idontexist
```

**Pythonソケットによる自動化スクリプト (`smtp.py`)**:
```python
import socket
import sys

if len(sys.argv) != 3:
    print("Usage: python3 smtp.py <username> <target_ip>")
    sys.exit(0)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[2], 25))
banner = s.recv(1024)
s.send(b'VRFY ' + sys.argv[1].encode() + b'\r\n')
result = s.recv(1024)
print(result.decode(errors='ignore'))
s.close()
```

**Windows環境からのSMTP対話**:
```cmd
:: 管理者権限でTelnetクライアントをインストール
dism /online /Enable-Feature /FeatureName:TelnetClient

:: Telnetを使用した対話的接続
telnet 192.168.50.8 25
```

---

### 4.3 SNMP 列挙 (UDP 161)
コミュニティストリング（デフォルトの`public`等）が設定されたSNMPから、MIBツリーを通じてOS、プロセス、インストール済みソフト、ポート一覧を抽出します。

```bash
# 開いているSNMPポート（UDP 161）のNmapスキャン
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt

# onesixtyone によるコミュニティストリングのブルートフォース
onesixtyone -c <community_file> -i <ips_file>

# snmpwalk によるMIBツリー全体のダンプ（タイムアウト10秒）
snmpwalk -c public -v1 -t 10 <TARGET_IP>

# snmpwalk に -Oa オプションを付与して16進数文字列をASCIIに自動デコード
snmpwalk -c public -v1 -Oa <TARGET_IP>
```

#### SNMP 特定OIDの個別照会コマンド
```bash
# ユーザーアカウントの列挙
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.4.1.77.1.2.25

# 実行中プロセスの列挙
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.4.2.1.2

# インストール済みソフトウェアの列挙
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.6.3.1.2

# リスニング中のTCPローカルポート一覧
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.6.13.1.3
```

#### Windows SNMP MIB OID リファレンス一覧
| MIB OID | 取得できるシステム情報 |
| :--- | :--- |
| `1.3.6.1.2.1.25.1.6.0` | システムプロセス |
| `1.3.6.1.2.1.25.4.2.1.2` | 実行中のプログラム名 |
| `1.3.6.1.2.1.25.4.2.1.4` | 実行中プロセスのパス |
| `1.3.6.1.2.1.25.2.3.1.4` | ストレージユニット |
| `1.3.6.1.2.1.25.6.3.1.2` | インストール済みソフトウェア名 |
| `1.3.6.1.4.1.77.1.2.25` | ユーザーアカウント |
| `1.3.6.1.2.1.6.13.1.3` | TCPローカルリスニングポート |

---

## 5. LLMを活用した列挙の効率化

大規模言語モデル（LLM）を活用して、ターゲット組織に最適化されたワードリストの作成や偵察結果の整理を迅速に行います。

### 5.1 サブドメイン用カスタムワードリストの生成プロンプト
```text
Using public data from MegacorpOne's website and any information that can be inferred about its organizational structure, products, or services, generate a comprehensive list of potential subdomain names.
* Incorporate common patterns used for subdomains, such as:
  - Infrastructure-related terms (e.g., "api", "dev", "test", "staging").
  - Service-specific terms (e.g., "mail", "auth", "cdn", "status").
  - Departmental or functional terms (e.g., "hr", "sales", "support").
  - Regional or country-specific terms (e.g., "us", "eu", "asia").
* Factor in industry norms and frequently used terms relevant to MegacorpOne's sector.
Finally, compile the generated terms into a structured wordlist of 1000 words, optimized for subdomain brute-forcing against megacorpone.com.
Ensure the output is in a clean, lowercase format with no duplicates, no bulletpoints and ready to be copied and pasted.
```

生成されたリストを `wordlist.txt` として保存し、Gobuster等のツールに渡して実行します。
