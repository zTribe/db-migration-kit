# db-migration-kit 测试/发布 SOP

本仓库只负责通用 runner、事务/锁、checksum、ledger、catalog/ACL/安全审计和 CLI。Chat/Indexer 实际业务 SQL、迁移清单、schema/权限策略在各自仓库维护；业务 SQL 变动**通常不修改 Kit**。阅读 ARCHITECTURE-AND-REGRESSION.md 和 ADAPTER-MIGRATION-ACCEPTANCE.md。

## 1. 本地测试

```bash
npm install --no-audit --no-fund
npm test
```

`npm test` 运行全部 `test/*.test.js`，某些以 integration 命名的测试需要 PG_TEST_URL；检查 skip，不能把未运行的集成测试算成通过。使用**专用可清空的本机 PostgreSQL17** 数据库（绝不使用 Dev/Production），确认实例身份后：

```bash
export PG_TEST_URL='postgres://postgres:postgres@127.0.0.1:5432/migration_kit_test'
npm run test:integration
```

必须验证：按序迁移、checksum/未知 ledger fail-closed、锁并发、回滚原子性、已部署 baseline 与新建库、真实角色/owner/SET ROLE/ACL/RLS、独立目标身份校验、read-only audit 和远程写入禁用。真实 PG 测试不能被 SQL 正则或 mock 取代。改动公共 API 后须实际验证服务适配器，而非只跑 Kit fixture。

## 2. CI 和发布

`.github/workflows/ci.yml` 对所有 push/PR 运行：unit job 用 Node22 `npm test`，独立 postgres-integration job 用 PG17 和 PG_TEST_URL 跑 `npm run test:integration`。

`.github/workflows/publish.yml` 只在 v* tag 触发；校验 tag 与包版本一致，再做单测/PG17 集成并发布 GitHub Packages。**发布可能真实推送包，未经用户授权不可建 tag**。CI 通过不意味着 Chat/Indexer 已升级到对应 Kit 版本。

## 3. 跨仓库与交付门禁

公共 runner/API/适配协议变化必须分别检查 Chat/Indexer pinned Kit 实际版本、旧 SQL 链升级、真实业务身份/ACL/owner、向前兼容和失败恢复。服务只改普通业务表时不强制改 Kit。先本地 Review、单测、PG17，再集中提交；逐个核对 CI 的实际 job/commit 和 skip。交付报告区分代码变更、本地与 PG 测试、两个消费者验证、CI、发布状态及未验证项。Production apply 需单独授权。
