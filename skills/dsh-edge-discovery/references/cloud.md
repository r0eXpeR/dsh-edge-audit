<!-- 改编自 Cloudflare security-audit-skill CLOUD-AND-DEPLOYMENT.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/cloud.md -->

# 云与部署

## 核心方法

适用：仓库定义云身份、基础设施、容器、Kubernetes、service mesh、serverless、edge worker、ingress、对象存储、托管服务或环境相关配置。问题是已部署组件是否获得预期的身份、隔离、网络可达性、secret 和策略。源码往往表达意图而非线上事实，必须区分源码确认的缺陷与待部署验证项。构建与晋升信任见 supply-chain，HTTP 代理语义见 web-auth，数据存储租户范围见 tenant-lifecycle。

- 不要仅凭 manifest 推断线上暴露。确定哪个环境消费它、默认值或 overlay 如何修改、源路径是否活跃。
- 把每个 workload 身份映射到具体操作和资源。宽策略只有在低信任输入能到达越权动作时才是发现。
- Ingress、代理、mesh、metadata service、admission policy 是真实边界，但只有其配置和 attachment 可见才算控制存在。
- Secret 引用不是 secret 泄露。需要低信任读者、输出、制品、日志路径或不安全 fallback。
- 渲染每个维护中的环境，建矩阵：外部端口、workload 身份、网络 peer、挂载 secret、云资源。差异需要 owner 或策略解释。
- 跟随低信任请求、对象、label、事件进入云策略，指出最终操作用哪个 workload 凭据，以及应限定它的条件。
- 比较正常部署、migration、restore、节点维护、failover、本地/emulator 路径；审查 mesh、admission、身份、secret、策略服务不可用时的行为。

## 类目检查点

### Workload 身份与 IAM
- **Workload identity 越权**：workload、pod、function、edge worker、node 身份可作用于超出角色的租户、账号、资源或 API，且不可信请求或 job 输入选择目标。查云策略 condition、资源模式、service account 绑定、namespace 映射、fallback 凭据。
- **跨账号/租户角色混淆**：role assumption、external ID、token exchange、workload federation、resource policy 接受未绑定预期 source account、audience、repository、namespace、workload 的身份声明。同时确定 trust policy 和调用方可控 claim。
- **应用授权委托给云元数据**：应用信任调用方提供的身份 header、tag、label、account ID、资源元数据，未核实其来自云控制面或可信代理。云 IAM 与应用授权是两道独立检查。

### Ingress、网络与控制面
- **服务/管理面意外可达**：ingress、service、listener、security group、load balancer annotation、端口映射、server bind 把 admin、debug、metrics、node、control-plane 或内部 API 暴露给低信任网络。仅缺网络控制记 Needs Validation；仓库控制的公开路由到敏感 handler 可确认。
- **可信代理/mesh 身份绕过**：后端接受预期 ingress/sidecar 之外 peer 的转发身份、mTLS subject、授权元数据，或备用端口、health、legacy 路径绕过 mesh。核实 header 清除、peer 可达性、代理缺失时是否 fail open。
- **Metadata 与内部服务可达**：不可信 URL、目的地、协议选择到达实例/容器 metadata、control-plane socket、内部 API 并带 workload 凭据。URL 解析与重定向处理见 attack-classes 的 SSRF；此处确定部署网络、metadata 版本（如 IMDSv2）、身份边界。

### 容器与编排
- **Host/控制面能力暴露**：低信任 workload 可选 privileged、capabilities、host namespace、hostPath、device mount、容器 runtime socket、service account token，从而跨入节点或控制面权限。单缺 seccomp 或只读文件系统是加固项，除非有可达操作跨越该边界。
- **Admission/策略路径不一致**：一条部署路径强制镜像身份、namespace、资源、secret、特权策略，另一 controller、job、upgrade、restore、兼容路径没有。确认备用路径和最终部署对象。
- **Namespace/label 信任混淆**：网络、admission、secret、workload identity 策略依赖低信任 principal 可设置的 label、annotation、name、namespace。比较谁控制 selector 与匹配后授予什么权限。

### 配置与 secret 生命周期
- **安全控制优先级漂移**：开发值、chart 默认值、环境变量、命令行 flag、feature gate、sidecar 注入、按区域 overlay 在已部署环境关闭认证、传输安全、租户范围、审计策略。渲染每个维护部署的最终配置，不只看 base 文件。
- **Secret 跨 workload 暴露**：secret 进入日志、crash report、进程参数、共享环境、宽 volume、构建输出、service discovery、read API，被其他 workload 或租户访问。核实 secret 类型与权限；公开 endpoint 或 key ID 不是凭据。
- **凭据续期与中断 fallback**：挂载、刷新、轮换、撤销 workload 凭据失败时，陈旧凭据继续生效，或应用接受信任度更低的身份模式。查启动、readiness、重连、缓存 client。

### 托管存储、事件与 edge
- **对象与 signed URL 策略混淆**：bucket/container policy、object key、CDN origin、signed URL 未绑定 principal、操作、对象 namespace、audience、expiry。除读外也查 list/version 操作和写路径。
- **事件源身份混淆**：function 或 worker 把事件 body 字段当来源身份，不校验 provider 签名 envelope、subscription/topic、account、region、replay 状态。比较 push、pull、retry、dead-letter 路径。
- **Edge/runtime 边界不匹配**：edge 或 serverless runtime 假定的 secret、API、文件系统、隔离、租户策略与 origin runtime 不同，回落 origin 时改变权限或缓存行为。确认哪项配置选择每条路径。

## 验证与反证

1. 确定活跃源路径和实际部署对象；否则记 Needs Validation，并说明缺哪个渲染后 manifest 或所有者观察到的 attachment。
2. 写出低信任调用方/workload、云或应用身份、可控 selector、受影响资源、越权操作或泄露。
3. 核实所用版本的 provider 与 orchestrator 默认值。不假设公网 IP、可达 metadata service、宽松防火墙或 admission 缺席。
4. 本地验证可渲染模板、评估策略、在隔离 fixture 内检查容器/用户 namespace、用假身份跑 emulator。不探测线上 endpoint，不改共享云资源。
5. **常见误报**：manifest 有宽权限但无低信任输入可达；只看 base 文件而 overlay 已覆盖；secret 引用被当泄露；缺 seccomp、read-only rootfs 等加固项；公开 endpoint/key ID；非活跃示例配置。
6. 确认需完整活跃源码路径和具体边界结果。账号策略、网络 attachment、运行时 admission、托管 metadata、漂移无法观察时记 Needs Validation，写明确切的部署策略、身份绑定、overlay、网络或漂移观察项。
