# ansible-role-basic-security

CentOS 7 のセキュリティ設定をおこなう ansible role です。

- 不要なサービスの停止と無効化
- カーネルパラメータの設定
 - ipv6 の無効化
 - Smurf 攻撃対策
 - IP Spoofing 攻撃対策
 - MITM 攻撃対策
 - バッファオーバーフロー対策
- sshの設定
- aideの適用
- clamavの適用
- firewalld & fail2banの適用
- rkhunterの適用

## 設定項目

以下の設定項目は上書き可能。

| 項目名                           | デフォルト値 | 説明                                          |
| -------------------------------- | ------------ | --------------------------------------------- |
| sec_unnecessary_services         | ['postfix']  | 不要なサービスのリスト                        |
| sec_sshd_listen_port             | 22           | sshポート番号                                 |
| sec_sshd_permit_root_login       | no           | sshで rootログインを許可するか                |
| sec_sshd_password_authentication | no           | sshで パスワード認証を許可するか              |
| sec_aide_enabled                 | yes          | ファイル改ざん検知機能を使用するか            |
| sec_clamav_enabled               | yes          | ウイルス検知機能を使用するか                  |
| sec_fail2ban_enabled             | yes          | ssh 不正アクセス拒否機能を使用するか          |
| sec_firewalld_enabled            | yes          | ファイアウォール機能を使用するか              |
| sec_rkhunter_enabled             | yes          | マルウェア(バックドア)検知機能を使用するか    |


