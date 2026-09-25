# 桥梁结构监测与限行决策

融合传感、巡检、交通荷载和天气数据，生成限载限行或恢复建议。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8318
```

默认端口为`8318`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`（异常记录，可带`severity`；增改会推进告警版本）
- `POST /api/items/{id}/records/{rid}/close`（关闭异常记录）
- `POST /api/items/{id}/assess`，处置评估，结果带评估依据和告警版本
- `GET /api/items/{id}/assessments`
- `POST /api/items/{id}/notices`（仅traffic_authority；`direction`为`restrict`或`close`）
- `GET /api/items/{id}/notices`
- `POST /api/items/{id}/transition`，必须提交`expected_version`；确认限行/封闭还须提交`assessment_id`
- `GET /api/audit`

允许角色：sensor_operator, bridge_engineer, traffic_authority, viewer。

### 处置评估与确认规则

- **封闭**：监测读数达到阈值（比值≥1），或存在严重级（critical）未关闭异常记录。
- **限行**：读数达到阈值四分之三（比值≥0.75），或存在两项及以上未关闭异常。
- **继续观察**：其余情况。
- 评估返回建议、逐条评估依据（读数比值、阈值标志、未关闭数量、严重级数量）与评估时的`alert_version`；同一告警仅保留最新一条active评估。
- 路政（traffic_authority）确认限行或封闭前，必须先存在**方向一致且当前有效**的交通通告（`restrict`通告对应限行、`close`通告对应封闭；生效中且未到期、未撤销）。
- 确认时若告警版本已经变化（新读数或异常记录增改），原评估标记为`invalid`并审计，接口返回409提示重新评估，不能按旧读数放行。
- 封闭建议强度高于限行，可用于限行确认；观察建议不能确认任何措施。
- 恢复（restored）前必须关闭全部异常记录，系统同时撤销该告警下原限行或封闭通告。
- 评估依据、通告新建与撤销、确认、评估失效全部进入SHA-256审计链。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
