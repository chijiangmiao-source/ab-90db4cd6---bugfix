# 隔离维护站 · 设备指令委托链裁决服务（MDMS Decision）

外部签发的设备指令**委托包**进入隔离维护站后，值班员在提交前需要确认：每一级
权限只会**收窄**、每一级都是父主体对子主体的真实签名、末级凭据**一次性**使用、
被**撤销/过期/越权/篡改**的请求不得驱动设备。本服务提供真实接口完成逐级裁决，
并将每一次裁决**持久化**：相同叶项的并发提交、响应丢失后的重传，都在一次
裁决中收敛为**一次执行**与**同一回执**，重启后仍可复核。

## 安全模型

- 输入只接受**规范 UTF-8 JSON**（严格 UTF-8、禁止重复键、JCS 风格规范化），
  签名对象一律是规范化后的字节。
- 委托链为 **Ed25519**：根项由 `root_pubkey` 自签（`parent_digest` 为 64 个 0），
  其后每一项由父项主体（`subject_pubkey`）签发。
- 每个子项的 `parent_digest` 必须等于父项 `header` 规范字节的 SHA-256；
  `devices` 与 `commands` 都必须相对父项为**真子集（严格收窄）**。
- 任一项 `expires_at <= now` 即拒；请求载荷须由**叶项主体**签名，且
  `device` / `command` 落在叶项范围内。
- 撤销采用包级、根公钥签署的 CRL（`revocations`），避免在链内引用下游摘要产生
  依赖环。撤销目标一旦验签通过即写入**站内持久名册**（按签发根公钥与叶项标识
  共同定位）：之后即使提交方剥离撤销声明重传，命中名册的项仍被拒绝；独立签发根
  之间互不共享撤销状态。
- 裁决身份由四要素共同决定：`root_pubkey`、`chain_digest`、`leaf_id`、
  规范载荷字节 → `request_digest`。
- 持久层用 SQLite 单写事务（`BEGIN IMMEDIATE`）串行化临界区：同 `request_digest`
  永远返回同一历史回执；同一签发根下同一 `leaf_id` 只可能执行一次（再次驱动 →
  `LEAF_CONSUMED`），不同签发根的相同叶项标识互不影响。
  篡改签名、越权命令、过期、撤销等只产生 `REJECTED` 记录，**绝不留下执行记录**。

拒因（按检查顺序，界面展示“首个拒因”）：
`MALFORMED_JSON` → `PACKET_STRUCTURE` → `ROOT_KEY_INVALID` → `CHAIN_EMPTY` →
`ITEM_STRUCTURE` → `PARENT_DIGEST_MISMATCH` → `SIGNATURE_INVALID` →
`SCOPE_NOT_NARROWED` → `EXPIRED` → `REVOCATION_INVALID` → `REVOKED` →
`PAYLOAD_STRUCTURE` → `PAYLOAD_SIGNATURE_INVALID` → `DEVICE_OUT_OF_SCOPE` →
`COMMAND_OUT_OF_SCOPE`；运行期：`LEAF_CONSUMED`。

## 目录

```
app/canonical.py   规范 JSON / Ed25519 验签
app/chain.py       委托链纯裁决逻辑（逐级校验、首个拒因、视图）
app/store.py       SQLite 持久化裁决（幂等、一次性凭据、撤销名册、回执）
app/device.py      受控设备模拟执行器（确定性 command_id）
app/drill.py       两套内置演练包（确定性种子密钥，跨重启稳定）
app/main.py        FastAPI：核验 / 执行 / 回执 / 台账 / 健康 / 值班界面
app/static/        无外部依赖的值班页面
tests/             45 个单元 / 并发 / HTTP / 重启复核测试
verify/            verify 验收容器入口（HTTP 场景 + pytest）
```

## 本地运行（不使用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
MDMS_DB_PATH=./data/mdms.db uvicorn app.main:app --host 0.0.0.0 --port 8000
# 打开 http://localhost:8000 ：“加载内置演练包” → “逐级核验” → “发起一次执行”
pytest -q
```

## Docker / Compose

宿主端口可通过 `MDMS_HOST_PORT` 配置（默认 8080），数据在命名卷 `mdms-data`
中持久化，`app` 自带容器健康检查并暴露 `GET /healthz`：

```bash
MDMS_HOST_PORT=18080 docker compose up -d --build app
curl -s http://localhost:18080/healthz
```

### verify 验收容器

`verify` 服务等待 `app` 健康后运行：有效执行、并发重传收敛、篡改/越权/过期/
撤销拒绝、API/HTTP 冒烟，并运行全部 pytest；**以退出状态码报告结果后退出**：

```bash
docker compose build
docker compose run --rm verify            # 只跑验收（app 可在线或由 compose 管理）
docker compose up --build --abort-on-container-exit verify   # 一键：起 app + 验收
docker inspect -f '{{.State.ExitCode}}' mdms-verify         # 0=通过 非0=失败
```

## HTTP 接口

| 方法 路径 | 说明 |
| --- | --- |
| `GET  /healthz` | 健康响应（含执行记录数） |
| `GET  /` | 值班界面（粘贴委托包与请求、逐级展示、执行、台账） |
| `GET  /api/drill` | 内置有效/撤销两套演练包的可粘贴文本 |
| `POST /api/inspect` | 只核验不落盘：逐级签名、父子主体、范围、失效、首个拒因 |
| `POST /api/execute` | 持久化裁决并执行（幂等；返回信封 + 稳定回执） |
| `GET  /api/receipt/{request_digest}` | 按裁决标识复核回执（重启后逐字一致） |
| `GET  /api/decisions?limit=` | 持久化裁决台账 |

执行/核验请求体：

```json
{
  "packet_text": "{\"root_pubkey\":\"…\",\"chain\":[{\"header\":{…},\"signature\":\"…\"}]}",
  "request_text": "{\"payload\":{\"device\":\"dev-alpha\",\"command\":\"status\",\"nonce\":\"…\"},\"payload_signature\":\"…\"}"
}
```
