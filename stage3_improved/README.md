# 阶段 3：改进 DH 协议并抵御 MITM

目标：

- 在阶段 1 的基础上改进协议，抵抗阶段 2 的中间人攻击
- 不允许两端直接写死共享密码
- 建议展示多种抵御方式并说明

本目录当前提供：

- 改进握手：引入服务端长期静态 DH 密钥对进行身份认证（不需要写死共享密码）
- 会话密钥派生同时包含：
  - 临时 DH（前向安全）
  - 静态-临时 DH（认证，抵御 MITM）
- AES-256-GCM 加密传输与客户端可触发的周期性 rekey

## 构建与运行

```bash
make
./bin/keygen --priv server_static.key --pub server_static.pub
./bin/server --host 0.0.0.0 --port 9100 --static-key server_static.key
./bin/client --host 127.0.0.1 --port 9100 --server-pub server_static.pub --message "hello" --count 3 --rekey-every 1
```
