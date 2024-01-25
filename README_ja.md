DMARCのDNSレコードの rua に指定したメールアドレスにくるレポートファイルを解析するスクリプト

## 使い方
レポートファイルは zip や gzip で圧縮されて送られますが、展開せずに解析できます。
簡単な統計情報の出力(標準出力)とCSVファイルの出力を行います。

```
$ bundle install
$ bundle exec ruby dmarc_analyzer.rb REPORT_FILES...
Reading REPORT_FILE1
Reading REPORT_FILE2
...
Wrote dmarc_analyzer_result.csv

--- Statistics ---
Time Range: 2024-01-10 09:00:00 +0900 - 2024-01-18 09:00:00 +0900
Total Mails: 13471
Pass: 13184 (97.9%)
Pass(direct): 7182 (53.3%)
Pass(transfer): 6002 (44.6%)
Fail: 287 (2.1%)
By providers:
  Enterprise Outlook: 1167 (Pass:99.1%, Fail:0.9%)
  google.com: 12196 (Pass:97.9%, Fail:2.1%)
  Outlook.com: 108 (Pass:79.6%, Fail:20.4%)
```

## 出力の見方
```
--- Statistics ---
Time Range: 2024-01-10 09:00:00 +0900 - 2024-01-18 09:00:00 +0900
Total Mails: 13471
Pass: 13184 (97.9%)
Pass(direct): 7182 (53.3%)
Pass(transfer): 6002 (44.6%)
Fail: 287 (2.1%)
By Providers:
  Enterprise Outlook: 1167 (Pass:99.1%, Fail:0.9%)
  google.com: 12196 (Pass:97.9%, Fail:2.1%)
  Outlook.com: 108 (Pass:79.6%, Fail:20.4%)
```

- Time Range - 解析したレポートの時間範囲
- Total Mails - レポートに含まれるメールの総数
- Pass - DMARC(またはARC)の認証をパスして、正しく届くメール数
- Pass(direct) - Pass のうち直接受信先に送られたメールの数
- Pass(transfer) - Pass のうちメール転送サービスで転送されたメールの数
- Fail - DMARC(またはARC)の認証をパスしなかったメール数
- By Providers - DARCレポートの提供先ごとのメール数

## CSVの列の意味
- Source IP - メール送信元IP(転送メールの場合は、転送サーバーのIP)
- Source Host Name - Source IP を逆引きしたホスト名
- Report Provider	- DMARCレポートの発行者(google.com, Outlook.com など)
- Header From - メーラーで見える送信者メールアドレス
- Envelope To - メールの送り先(To, Cc, Bcc に指定されたメールアドレス)
- Mail Count - メール数
- DMARC or ARC Result - DMARC Result か ARC Result のどちらかが pass か(おそらくこれがメールが正しく届く条件)
- DMARC Result - DMARCの認証をパスしたか(pass, fail)
- ARC Result - ARCの認証をパスしたか(pass or 空欄)
- SPF Alignment - SPFレコードのドメイン(Envelope From のドメイン)と Header From のドメインが一致するか
- DKIM Alignment - DKIM Signature のドメインと Header From のドメインが一致するか
- SPF Result - SPFの認証をパスしたか(pass, fail)
- SPF Domain - SPFレコードのドメイン(Envelope From のドメイン)
- DKIM Result - DKIMの認証をパスしたか(pass, fail)
- DKIM Domain - DKIM Signature のドメイン
- Additional DKIM - DMARCのレポートにDKIM認証の情報が複数含まれることがまれにあるので二個目以降の情報

`DMARC Result`, `DMARC or ARC Result` は他の列に依存して計算されます。

```
DMARC Result =
  (SPF Result == pass && SPF alignment == pass) ||
  (DKIM Result == pass && DKIM alignment == pass) ? pass : fail
DMARC or ARC Result = (DMARC Result == pass || ARC Result == pass) ? pass : fail
```

## 説明
`DMARC or ARC Result` が `pass` になっていればメールは正しく届くはずです。

SPF/DKIMが正しく設定されていて、FromがSPF/DKIMのドメインになっていれば、直接受信元に届くメールについては問題なく `pass` になります。
転送メールは、転送サーバーや受信サーバーの仕様次第で `fail` になることがあります。

|SPF Result |SPF Alignment|DKIM Result|DKIM Alignment|DMARC Result| ARC Result | DMARC or ARC Result | |
|-----|-----|-----|-----|---|------|----|---|
| ◯  | ◯   | ◯  | ◯  | ◯ | なし | ◯ | 正規のメールが直接届いた|
| any | ☓   | ◯  | ◯  | ◯ | any  | ◯ | メールをそのまま転送 |
| any | ☓   | ◯  | ☓   | ☓ | ◯    | ◯ | メールタイトル等を変更して転送(ARCあり) |
| any | ☓   | any | ☓   | ☓ | なし  | ☓  | メールタイトル等を変更して転送(ARCなし) or From詐称メール |


### 転送メールの認証について
メーリングリスト、メールサービス(gmail, outlook.com, ...)の転送機能、その他サービスのメール転送機能によりメールが転送された場合は、SPF/DKIMの認証結果は以下のようになります。

* `SPF alignment` は必ず `fail` になる(`Envelope From` が転送サービスのメールアドレスになるため、メールの表示用の送信元アドレス `Header From` と一致しない)
* 転送時にメールのタイトルや本文等に変更が加わる場合(メーリングリストではよくある)は `DKIM Result`, `DKIM alignment` が `fail` になる(電子署名したタイトルや本文等が変更されるため、改ざん扱いになる)

`DMARC Result` は以下のような条件で決まるので、転送時にメールが変更された場合は DMARC の認証をパスしません。

```
DMARC Result =
  (SPF Result == pass && SPF alignment == pass) ||
  (DKIM Result == pass && DKIM alignment == pass) ? pass : fail
```

転送時にメールが変更される場合にもメールの正しさを検証する仕組みとして ARC (Authenticated Received Chain) があります。
転送サーバーや受信サーバーが ARC に対応していれば、メールが変更される転送メールについても正しさの検証ができます。

例えば Gmail や Google Groups は ARC に対応しているので、Google Groups で転送されて Gmail に届くメールに関しては、転送メールでも問題なく届きます。

ARCに対応していないメール転送サービスを使っている場合は、正規のメールの転送とFrom詐称メールを区別できませんが、CSVの以下の列を見るとメールの素性をある程度予測できます。

* `Source Host Name` がメールを送信した組織のドメインになっていることがある
* `SPF Domain` がメールを送信した組織のドメインになっていることがある(`SPF Result == pass` のときのみ信頼できる)
* `Envelope To` はメールの送信先アドレスのドメイン(Gmailのレポートには含まれない)
