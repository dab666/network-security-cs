# network-security-cs

Linux 环境下的 C 语言课设代码仓库，用于逐阶段实现：

- 阶段 1：TCP C/S + Diffie-Hellman 协商 + AES-256-GCM 加密传输（密钥周期更新）
- 阶段 2：Diffie-Hellman 中间人攻击（可解密通信内容）
- 阶段 3：改进协议以抵御中间人攻击（并用阶段 2 验证）

## 目录结构

- `stage1_dh/`：阶段 1 代码
- `stage2_mitm/`：阶段 2 代码
- `stage3_improved/`：阶段 3 代码

每个阶段目录都是一个可独立编译运行的小项目（各自带 Makefile）。

## 通用运行方式（各阶段目录内）

```bash
make
./bin/server --host 0.0.0.0 --port 9000
./bin/client --host 127.0.0.1 --port 9000 --message "hello"
```

部分阶段会额外提供 `--daemon` 等参数以支持后台运行。
