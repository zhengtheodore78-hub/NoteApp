# HMAC 成绩导出保护 - Class 4 实验实现

## 📋 实现概述

根据 **Class 4: Hashing, Integrity & Asymmetric Encryption** 课程内容，为 NotesApp 的成绩导出功能添加了 HMAC 完整性保护。

### 核心原理
- **哈希函数**: 证明数据未被修改（雪崩效应）
- **HMAC**: 哈希 + 密钥，证明数据完整性 + 发送者身份
- **密钥保护**: 只有服务器知道 HMAC 密钥，Eve 无法伪造有效 HMAC

---

## 📁 新增/修改的文件

### 1. `web/hmac_utils.py` (新建)
HMAC 工具模块，提供以下功能：

| 函数 | 功能 |
|------|------|
| `compute_hmac(data)` | 计算 HMAC-SHA256 |
| `verify_hmac(data, provided_hmac)` | 验证 HMAC 是否匹配 |
| `add_hmac_to_csv(csv_content)` | 在 CSV 末尾添加 HMAC |
| `verify_csv_integrity(csv_content)` | 验证 CSV 完整性 |

**密钥配置**:
```python
# 开发环境默认密钥
HMAC_KEY = b'notesapp_hmac_secret_key_2024'

# 生产环境应使用环境变量
HMAC_KEY = os.environ.get('HMAC_SECRET_KEY')
```

### 2. `web/app.py` (修改)
修改了两个路由：

#### `/export.csv` - 导出时添加 HMAC
```python
# 修改前
return Response(
    buf.getvalue(), mimetype="text/csv",
    headers={"Content-Disposition": "attachment; filename=grades.csv"},
)

# 修改后
csv_content = buf.getvalue()
csv_with_hmac = add_hmac_to_csv(csv_content)
return Response(
    csv_with_hmac, mimetype="text/csv",
    headers={"Content-Disposition": "attachment; filename=grades.csv"},
)
```

#### `/verify-hmac` (新增) - 验证上传的 CSV
```python
@app.route("/verify-hmac", methods=["POST"])
def verify_hmac_upload():
    # 验证上传的 CSV 文件的 HMAC
    # 返回：{"valid": True/False, "message": "..."}
```

### 3. `web/test_hmac.py` (新建)
演示和测试 HMAC 保护功能

---

## 🧪 测试结果

### 测试场景 1: 正常导出验证
```
✅ INTEGRITY CHECK (ORIGINAL FILE): PASSED ✓
```

### 测试场景 2: Eve 篡改攻击
```
 Eve 将 alice 的成绩从 14 改为 18
❌ INTEGRITY CHECK (TAMPERED FILE): FAILED ✗
   CHECK FAILED - Tampering detected!
```

### 测试场景 3: 雪崩效应演示
```
Original HMAC:  d7f9afb4b8ba5c8f10a749d440e44d1be32c2ad9c4f6b038beb7919bdc8cc335
Tampered HMAC:  e5a5f652640c0275242526449e0c1d4891e5ea50c4c3270519a2c8d6d1ad8302
Matching characters: 7 / 64 (10.9%)

🎯 AVALANCHE EFFECT CONFIRMED!
```

---

## 📊 CSV 文件格式

### 导出格式（带 HMAC）
```csv
student,class,grade,comment
alice,Math,14,good work
bob,Math,9,late twice
carol,Math,16,excellent
# HMAC: d7f9afb4b8ba5c8f10a749d440e44d1be32c2ad9c4f6b038beb7919bdc8cc335
```

### HMAC 验证流程
```
1. 服务器导出 CSV → 计算 HMAC → 附加到文件
2. Eve 篡改文件 → 修改成绩
3. 服务器验证 → 重新计算 HMAC → 不匹配 → 拒绝
```

---

## 🔐 安全特性

| 特性 | 说明 |
|------|------|
| ✅ 完整性保护 | 任何修改都会导致 HMAC 不匹配 |
| ✅ 身份认证 | 只有持有密钥的服务器能生成有效 HMAC |
| ✅ 抗篡改 | Eve 无法伪造 HMAC（无密钥） |
| ✅ 雪崩效应 | 1 位变化 → ~50% HMAC 位翻转 |
| ✅ SHA-256 | 当前安全标准，无已知弱点 |

---

## 🚀 部署步骤

### 1. 本地测试
```bash
cd web
python test_hmac.py
```

### 2. 部署到服务器
```bash
# 复制文件到服务器
scp web/hmac_utils.py web/app.py user@server:/path/to/notesapp/web/

# 设置 HMAC 密钥（生产环境）
export HMAC_SECRET_KEY="your-secure-random-key-here"

# 重启应用
docker-compose restart web
```

### 3. 验证功能
```bash
# 1. 登录教师账号
# 2. 导出成绩 CSV
# 3. 检查文件末尾的 HMAC 行
# 4. 使用 /verify-hmac 接口验证
```

---

## 📝 Class 4 知识点对照

| 课程内容 | NotesApp 实现 |
|---------|--------------|
| 哈希函数 | SHA-256 (`hashlib.sha256`) |
| 雪崩效应 | 修改 1 个字符 → HMAC 完全不同 |
| HMAC | `hmac.new(key, data, sha256)` |
| 密钥保护 | 服务器独占 `HMAC_KEY` |
| Eve 攻击 | 篡改成绩 → HMAC 验证失败 |
| 完整性验证 | `verify_csv_integrity()` |

---

## ⚠️ 生产环境注意事项

### 密钥管理
```python
# ❌ 不要硬编码
HMAC_KEY = b'notesapp_hmac_secret_key_2024'

# ✅ 使用环境变量
HMAC_KEY = os.environ.get('HMAC_SECRET_KEY')

# ✅ 或使用密钥管理服务
import boto3
secrets = boto3.client('secretsmanager')
HMAC_KEY = secrets.get_secret_value('notesapp/hmac-key')
```

### 密钥生成
```bash
# 生成安全的随机密钥 (32 字节)
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 📚 参考资料

- Class 4 幻灯片：`Class 4 — Hashing, integrity & asymmetric encryption.pdf`
- 课程示例：`grades_export.csv` HMAC 保护
- NIST SP 800-38D: GCM 和 HMAC 规范
- Python 文档：`hmac` 和 `hashlib` 模块

---

## ✅ Class 4 实验完成清单

- [x] 理解 HMAC 原理（哈希 + 密钥）
- [x] 创建 `hmac_utils.py` 工具模块
- [x] 修改 `/export.csv` 添加 HMAC
- [x] 创建 `/verify-hmac` 验证路由
- [x] 编写测试脚本 `test_hmac.py`
- [x] 验证雪崩效应
- [x] 验证 Eve 攻击检测
- [x] 编写实现文档

**Class 4 实验完成！** 🎉
