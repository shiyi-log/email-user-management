# 邮箱验证用户管理系统

基于 Python 标准库与 SQLite 的轻量用户管理示例。用户通过邮箱接收一次性验证码完成注册，之后可用邮箱和密码登录。

## 功能

- 邮箱格式校验，验证码 60 秒发送冷却，10 分钟后过期
- 连续输错 5 次后验证码作废，需重新发送
- 注册必须提供匹配且未过期的邮箱验证码，成功注册后验证码即作废
- PBKDF2-HMAC-SHA256 密码哈希，不以明文保存密码
- 邮箱登录、会话 Cookie 和退出登录
- Python 3.9+，无需安装第三方依赖

## 配置 SMTP

复制 .env.example 为 .env 并填入邮件服务商提供的 SMTP 地址、端口、账号及应用专用密码。启动程序时会自动读取项目目录中的 .env；现有进程环境变量优先，不会被文件内容覆盖：

    cp .env.example .env
    python3 user_management.py

通常使用 587 端口和 STARTTLS。若服务商提供 SSL SMTP，设置 SMTP_USE_SSL=true、SMTP_PORT=465、SMTP_USE_TLS=false。SMTP_FROM 必须是该账号获准使用的发件地址。将 APP_SECRET 替换成长随机值；更换后尚未验证的验证码会失效。

## 启动

    python3 user_management.py

打开 http://127.0.0.1:8000。未配置 SMTP 时服务可以启动，但验证码发送会提示配置错误。对外部署请使用 HTTPS 反向代理并保护 SMTP 凭据。

## 测试

    python3 -m unittest discover -s tests -v
