# 多要素認証の勉強

## 使い方

### 実行

Python app.py

### 接続先

http://localhost:5000/login

## 設計

### 構成

- フロント：html+JS
- バック：Python
- DB：sqlite

### 画面設計

- ログイン画面：/login
- ユーザ登録画面：/register
- 認証方式選択画面：/post_login
- ログイン後画面：/index
- OTP認証登録画面：/otp_setup
- OTP認証画面：/otp_auth
- FIDO認証登録画面：/fido_setup
- FIDO認証画面：/fido_auth
