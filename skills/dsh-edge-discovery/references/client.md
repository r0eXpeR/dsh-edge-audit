<!-- 改编自 Cloudflare security-audit-skill CLIENT-SIDE.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/client.md -->

# 客户端与浏览器

## 核心方法

适用：浏览器内发生信任决策或渲染不可信内容的场景，包括 SPA、浏览器扩展、内嵌 webview、service worker、离线应用，以及把攻击者可影响内容渲染进 DOM、接收跨窗口消息、使用浏览器存储的代码。这些路径的 source 可能服务端根本看不到：URL fragment、`window.name`、`postMessage`、已缓存内容。webview 的 native 侧见 desktop；服务端 CSRF、session、auth callback 见 web-auth。

- 候选需要可控 source 与可执行或可泄露的 sink，写出两者并证明攻击者数据到达 sink。
- 影响必须落到受害者 session、其他 origin 或共享持久化。self-injection、泄露攻击者自己的数据都不算。
- 框架转义、同源策略、CSP、COOP/CORP、service-worker scope、现代 noopener 默认值都是真实控制，定影响前先核实。
- 浏览器存储和缓存按 origin 共享，可能比登录状态活得久：确定谁写、谁读，哪个账号、租户、worker 生命周期负责清理每条记录。
- 从 DOM、导航、worker、消息、存储 sink 出发，反向追到浏览器专属 source 与服务端可控 source，记录本应阻止路径的浏览器策略。
- 用本地测试 origin 和假账号检查账号切换、logout、worker 更新、离线 fallback、过期标签页状态；不碰生产用户、origin 或共享服务。
- XS-Leaks 只列源码和本地浏览器行为已证明的 predicate，再指出能消除 oracle 的响应头或渲染选择。

## 类目检查点

### DOM 与对象状态
- **DOM XSS**：追 `location` 各字段、`document.referrer`、`window.name`、消息数据、storage、浏览器控制的文档状态，到 `innerHTML`、`outerHTML`、`document.write`、字符串求值 API、可执行 URL、jQuery HTML API、框架逃生口。框架已转义的插值不算。
- **DOM clobbering**：注入的 `id`/`name` 遮蔽 global、form 属性、配置对象或初始化标志。需同时证明保留属性的 markup 路径和被遮蔽值的安全相关使用。
- **Prototype pollution + gadget**：攻击者控制的 key 进入递归写（deep merge、path assignment）修改原型，随后可达 gadget 读取被污染属性并改变授权、执行、导航或渲染。`JSON.parse`、浅拷贝、无 gadget 的污染都不够。

### 跨 origin 消息与网络
- **`postMessage` 信任**：handler 用 `event.data` 做敏感动作，却没有精确 origin allowlist；同 origin 多 frame 时还要校验 `event.source`。发送侧把敏感数据发给 `*` 会到达非预期 embedder。子串、前缀、后缀、未锚定正则都不是 origin 检查。
- **Cross-site WebSocket hijacking**：upgrade 接受不可信 origin 的 ambient cookie，无 `Origin` 检查或 channel token，受害者 session 可被读写。需同时确认 upgrade 行为和安全相关消息 handler。
- **带凭据 CORS**：服务端反射或弱匹配 `Origin` 且允许 credentials，并返回敏感响应。裸 `*` 加 credentials 会被浏览器拒绝；只报告实际反射/允许的 origin 路径和跨 origin 数据或变更。

### Service worker 与浏览器存储
- **注册与 scope 接管**：攻击者可影响内容成为被注册 worker 脚本，控制拿到过宽 `Service-Worker-Allowed` 的路径，或无完整性控制地改变 update import。核实最终脚本 URL、响应 MIME、origin、scope、每个被 import 脚本的控制者。正常同 origin 且 scope 符合预期的 worker 不是缺陷。
- **缓存与身份混淆**：worker 缓存个性化响应，策略未含账号、租户、授权状态或 request mode，账号切换或 logout 后仍提供。查 fetch event 路由、cache 名与 key、navigation fallback、清理逻辑，错误/离线路径是否返回他人先前响应。
- **存储泄露与陈旧授权**：token、私有响应、草稿、授权决定留在 `localStorage`、`sessionStorage`、IndexedDB、Cache Storage、扩展存储或客户端状态，被其他账号或低信任同 origin 组件读取。仅存 token 不算；需有现实的低权限读者，或撤销/logout 后继续使用。
- **跨上下文存储/广播混淆**：`storage` event、`BroadcastChannel`、shared worker、origin 级缓存在标签页间传递身份或命令却未绑定当前 session。查账号切换、隐私/公共窗口、租户变更、过期标签页覆盖较新 auth 状态。

### 跨站信息泄露
- **XS-Leaks/跨 origin 状态 oracle**：攻击页面在浏览器附带受害者凭据时，通过资源 load/error 事件、frame/window 状态、重定向行为、timing、cache 状态、响应大小区分受保护状态。需一个具体含秘密的 predicate，如私有对象、角色或账号是否存在。泛化 timing 差异、公开资源可用性不算。
- **窗口与 opener 状态泄露**：跨 origin 窗口允许读取的元数据或导航结果暴露受保护状态，或保留的 opener/命名窗口关系使攻击页面影响特权导航。查 COOP、frame 保护、`noopener`、精确 origin、可观察状态是否机密。

### UI redress 与导航
- **Clickjacking**：可 frame 的状态变更动作缺有效 `frame-ancestors`、`X-Frame-Options` 或等效 UI 隔离。需有敏感动作并确认在 frame 内可完成；只读内容缺 header 属加固项。
- **客户端导航混淆**：client source 控制重定向或导航而无 scheme 与目标策略，包括可执行的 `javascript:`、`data:`。Reverse tabnabbing 仅适用于代码显式保留 `window.opener`、`window.open` 无隔离，或支持无隐式 `noopener` 的浏览器。

## 验证与反证

1. 引用 source、sink、浏览器策略、受影响 origin/session，以及可观察的变更或泄露。
2. Prototype pollution 必须证明递归写和安全相关 gadget；DOM clobbering 必须证明 markup 存活且被遮蔽值确被使用。
3. Service worker 与存储必须证明生命周期可达：攻击者控制的写入或缓存条目能到达不同账号、租户或后续授权状态。
4. 消息、CORS、WebSocket、XS-Leaks 要给出确切 origin/source 校验及暴露的受保护状态或动作，并确认 CSP、COOP/CORP、cookie、SameSite 未已阻止。
5. **常见误报**：self-XSS、框架转义的插值、无 gadget 的污染、裸 `*` + credentials、只存 token、只读页面缺 frame header、公开资源的 timing 差异、有隐式 `noopener` 的 tabnabbing、预期 scope 的 worker。
6. 确认需完整客户端路径和有界本地证据。依赖部署 header、扩展权限、浏览器版本、渲染器行为而无法观察时记 Needs Validation，并写明所有者需核实的确切事实。
