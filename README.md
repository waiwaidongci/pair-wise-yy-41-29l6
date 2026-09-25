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
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/records/{record_id}/close`，关闭异常记录
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `POST /api/items/{id}/assessment`，处置评估，结果带评估依据的告警版本
- `POST /api/items/{id}/notices`、`GET /api/items/{id}/notices`，交通通告
- `POST /api/items/{id}/confirm`，路政确认限行或封闭，须提交`notice_id`与评估时的`expected_version`
- `POST /api/items/{id}/restore`，全部异常关闭后恢复并撤销原通告
- `GET /api/audit`

允许角色：sensor_operator, bridge_engineer, traffic_authority, viewer。监测偏差与预警阈值之比和多条异常记录决定告警等级；限行与封闭决策必须绑定交通通告记录。

## 处置评估流程

1. 评估：读数达到阈值或存在严重级（kind为critical）未关闭记录时建议封闭；读数超过阈值四分之三或有两项及以上未关闭异常时建议限行；其余继续观察。评估依据与告警版本写入审计。
2. 通告：路政确认前须新建方向一致（restricted/closed）且当前有效的交通通告。
3. 确认：新增或关闭异常记录都会推进告警版本；确认时版本与评估版本不一致，原建议失效并提示重新评估，不能按旧读数放行。
4. 恢复：全部异常记录关闭后方可恢复，恢复时撤销原限行或封闭通告。评估、通告、确认、失效与恢复均进入审计链。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
