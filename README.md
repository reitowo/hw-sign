# 登录态硬件绑定机制

最小原型验证

## 概述

将登录会话与设备上硬件安全模块的一对非对称密钥绑定，并使其不可导出，从原理上防止令牌被盗或在未授权设备上进行使用。

## 设计

### 硬件密钥绑定
- 硬件安全模块直接生成密钥对，私钥不可导出
- 每个请求都通过签名进行验证

### 降级机制
首选硬件绑定，当硬件安全不可用时，系统会降级：
- Windows：系统版本过低，TPM 不存在或在 BIOS 中禁用
- Android：系统版本过低，TEE 与 StrongBox 都不存在
在这些情况下，登录态不受硬件密钥保护，不影响正常使用

### 流程解耦合
- 不关心登陆态实现，如 Cookie 或是各种应用维护的 Token 体系
- 与登陆流程分离，登陆可以使用其他更安全的认证，如 WebAuthn

## 技术实现

### 密钥架构

#### 硬件密钥（设备绑定）
- 存储在硬件中的不可提取密码学密钥对
- 每个登录会话都生成新的密钥
- 专用于签署加速密钥
- 与登录态关联，而非用户账户

#### 加速密钥（仅存储于内存）
- 仅存储于内存的密码学密钥对，用于提高性能
- 由硬件密钥签名以验证真实性
- 用于常规 API 请求签名
- 支持轮转与重新生成（应用重启/会话过期）

### 算法优先级和格式要求

1. ED25519
2. ECDSA (P-256)
3. RSA-PSS (2048)

### 平台特定实现

#### 浏览器（Web Crypto API）
- 使用SubtleCrypto API
- 算法降级链：ED25519 → ECDSA → RSA-PSS
- 不可提取的硬件密钥生成
- 基于内存的加速密钥管理

示例实现：`hw-sign-browser/src/services/authService.ts`

#### Windows（CNG/NCrypt）
- 使用 Windows CryptoNG (NCrypt) API
- 基于 TPM 的密钥存储

示例实现：`hw-sign-win/main.cpp`

#### Apple（安全隔区）
- 使用 SecKey API
- 安全隔区 (Security Enclave) 密钥存储

示例实现：`hw-sign-apple/hw-sign-apple/Services/AuthService.swift`

#### Android（Keystore）
- 使用 Android Keystore API
- TEE / StrongBox 密钥存储

示例实现：`hw-sign-android/app/src/main/java/fan/ovo/hwsign/AuthService.kt`

### 示例API协议规范

#### 认证流程

1. 注册（POST /register）
   - 标准用户注册，不包含硬件绑定
   ```json
   {
     "username": "string",
     "password": "string"
   }
   ```

2. 带硬件绑定的登录（POST /login）
   - 请求头:
     - `x-rpc-sec-dbcs-hw-pub`: 硬件公钥（base64编码）
     - `x-rpc-sec-dbcs-hw-pub-type`: 密钥算法（"ed25519", "ecdsa", "rsa-pss"）
   - 请求体:
   ```json
   {
     "username": "string",
     "password": "string"
   }
   ```
   - 响应:
   ```json
   {
     "token": "string"
   }
   ```

3. 一个需要登录态的接口（GET /authenticated）
   通用请求头:
   - `Authorization: Bearer <token>`
   - `x-rpc-sec-dbcs-data`: 请求数据哈希/时间戳
   - `x-rpc-sec-dbcs-data-sig`: 请求签名

   对于新加速密钥:
   - `x-rpc-sec-dbcs-accel-pub`: 加速公钥
   - `x-rpc-sec-dbcs-accel-pub-type`: 密钥算法
   - `x-rpc-sec-dbcs-accel-pub-sig`: 硬件签名的加速密钥

   新加速密钥时的响应头:
   - `x-rpc-sec-dbcs-accel-pub-id`: 新加速密钥ID

   对于现有密钥:
   - `x-rpc-sec-dbcs-accel-pub-id`: 加速密钥ID

### 请求签名

即 `x-rpc-sec-dbcs-data`，按安全性从高到低排序：

1. 带 Redis 的随机字符串
   - 签名随机 nonce
   - 存储在 Redis 中以防止重放
   - 最佳安全性，需要 Redis

2. 请求体哈希
   - 签名请求体的 SHA256 哈希
   - 无需额外存储
   - 需要访问原始请求体 (Grpc 接口可能不适用)

3. 时间戳
   - 签名当前时间戳
   - 设置较短的过期窗口
   - 最简单，安全性略低


## 示例

所有子文件夹对应了每个平台的示例实现，都可直接打开工程进行编译

> 注：超过 90% 代码由 AI 辅助生成，人工保证正确性