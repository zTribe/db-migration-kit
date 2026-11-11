# db-migration-kit Agent Rules

修改前必读 [测试与发布 SOP](docs/TESTING-SOP.zh-CN.md) 和 [架构与回归规范](docs/ARCHITECTURE-AND-REGRESSION.md)。

- Kit 仅维护通用迁移框架；业务 SQL、迁移清单与 schema 安全策略由 Chat、Indexer 各自维护，不要把 Kit 的 examples 当作生产迁移目录。
- 任何公共行为变动必须单测、隔离 PostgreSQL17 集成和对应服务适配器验证；查看 skipped 测试，不得用 mock 或字符串断言替代真实 SQL。
- 禁止改写已应用 checksum/ledger、放宽 RLS/权限、绕过数据库身份检查、对生产运行破坏性测试。远程 apply 必须单独授权。
- 先本地 Review，集中提交，逐 job 核对 GitHub CI；区分本地通过、服务兼容、CI、发布/生产部署状态。
- 发布 workflow 由 v* tag 触发；未经授权不得创建发布 tag。
