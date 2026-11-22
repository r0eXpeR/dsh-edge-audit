<!-- 改编自 Cloudflare security-audit-skill WEB-PROTOCOL-AND-AUTH.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/web-auth.md -->

# Web 协议与身份认证

## 核心方法

适用：Web 应用、API、反向代理、CDN、网关、自研 HTTP server，以及 session、JWT、OAuth/OIDC、SAML、密码找回、MFA、passkey、API key、mTLS。访问控制问“principal 能否做此操作”；本领域问 HTTP 或身份层是否会混淆“操作属于哪个 principal、请求、assurance 级别或 token”。大型目标拆为：framing 与 cache、浏览器认证、联邦身份、强认证与恢复、服务凭据、session 生命周期。托管代理后的单一 server 几乎没有可由源码确认的 smuggling 面，自研代理或 parser 则多得多。

- Framing/cache 问题需要同一请求、响应或 key 的两种解释：写出两个组件及各自归一化后的确切值。
- 每个凭据都先找签名或 secret 校验，再找角色所需的全部绑定：issuer、audience、origin、RP、client、session、principal、resource、assurance、expiry、一次性状态。
- Host、Forwarded、X-Forwarded-*、Origin、Referer、重定向目标、callback state、由请求派生的 URL 都是信任决策，追到受影响的身份或响应。
- 对每个凭据和 challenge 走完 issue → store → transmit → consume → refresh → revoke，比较 normal、error、retry、migration、legacy、account-switch 路径。
- 枚举通往同一身份的每扇门、通往同一敏感操作的每条路由；实际策略取最弱的并行路径，不取最完善的 UI。
- 并排比较 parser、proxy、router、cache、应用的归一化结果。找回与账号关联要画前后账号图，每条边标明当前 principal、新身份证明、所需 assurance、callback/session 绑定、撤销效果。

## 类目检查点

### HTTP framing 与 cache
- **Request smuggling/desync**：多个 `Content-Length`、`Transfer-Encoding`、HTTP/2、HTTP/3 降级、header 名归一化、forbidden connection header、CR/LF 转换；确认两侧各把哪些字节归入当前与下一请求。
- **Cache poisoning**：值改变内容或安全 header 却不在 key 中；对比 key 构造与 forwarded host/scheme、部分 cookie、query 归一化、语言/设备 header、授权状态。
- **Cache deception/私有响应缓存**：私有动态路径被当静态资源；比较边缘可缓存判定、路由解析、后缀与 path parameter 归一化、响应 cache 指令。
- **Host/Forwarded 信任**：影响绝对 URL、租户路由、callback、reset link、cache key、授权用客户端地址；确认谁能提供，可信入口是否清除客户端副本。
- **响应头注入**：进入 `Location`、`Set-Cookie`、CSP 的控制字符；先核实框架拒绝行为，且须有安全相关响应变化。

### 浏览器 session
- **CSRF**：盘点所有 cookie 认证的变更端点，含 form、类 JSON、multipart、method override、legacy 路由；anti-CSRF token、same-site 绑定、严格 Origin/Referer 是否有效。SameSite 只对实际 cookie 与浏览器上下文有效；login CSRF、跨站子资源请求要求不同。
- **Session fixation/失效**：login、账号切换、MFA 完成、impersonation、提权后未轮换；logout、改密、撤销、停用后仍有效。检查服务端 session、refresh token、签名 cookie、websocket 状态、cache 副本、fallback 端点。
- **Cookie 作用域**：`Domain`/`Path` 过宽、跨不安全传输、sibling cookie 被另一组件优先选中。单纯缺 flag 只是加固项，除非有现实的低信任 origin、网络位置或浏览器路径可取得或替换凭据。

### 联邦身份（先定角色：授权服务器控制不属于 relying party）
- **JWT**：签名确实校验；`alg` 由服务端固定（`none`、算法混淆）；key 来源固定；`exp`、`nbf`、`aud`、`iss`；`kid`、`jku`、`x5u` 是不可信 key 选择器；重复 header 与归一化；decode-without-verify 路径。可信 issuer 给其他服务签发的 token 在此仍无效。
- **OAuth/OIDC**：授权服务器侧 `redirect_uri` 精确归属；`state` 绑定 session；PKCE 与 code 绑定；ID token 的 issuer/audience/签名/`nonce`；多 IdP 流程绑定所选 IdP。比较首次 callback、retry、移动端/deep link、account-link 路由。
- **SAML**：被验签的元素必须就是作为身份使用的元素（signature wrapping）；未签名/fallback 路径、XML parser 安全配置、canonicalization 差异；有效期、audience/recipient、请求关联、replay 状态。

### MFA、passkey、账号迁移
- **MFA 注册/降级**：注册、替换、停用、recovery code、受信设备、fallback 登录需预期的先前 assurance；第一因子不能绕过 fresh 认证换第二因子；失效因子不再授权 session。
- **Step-up 绑定**：challenge 绑定 principal、当前 session、assurance 目标、必要时的操作/资源、expiry、一次性完成；比较 UI、API、batch、recovery、resumed flow。
- **WebAuthn/passkey**：注册绑定 challenge、RP ID、expected origin、credential、user/userHandle、算法、UV 策略到发起 session；认证校验 challenge、RP/origin、credential 归属、签名、UP/UV。查 userHandle 或 credential→账号混淆。signature counter 仅在产品把回退视为克隆信号时才有意义。
- **账号关联**：加 IdP、passkey、邮箱、手机、设备需当前认证 session、新身份所有权证明、step-up、绑定发起账号的 callback state；查 unlink/relink、邀请接受的已验证标识或租户碰撞。
- **密码重置/恢复**：token 随机性、用户/动作绑定、expiry、一次性、限速计数、投递 URL 信任、旧 token 与 session 失效；客服恢复、backup code、设备迁移、改邮箱/手机常是最弱路径。

### API key 与 mTLS
- **API key 范围**：key 认证范围超出服务端记录（租户/资源/动作/环境），请求参数可覆盖绑定；查 lookup、prefix 与完整 secret 校验、publishable/secret 类型混淆、rotation、撤销缓存、bulk 端点。
- **API key 暴露**：client bundle、URL、redirect、日志、错误路径、构建产物、低信任响应；确认 key 类型和泄露后获得的权限。
- **mTLS 身份混淆**：信任任意网络 peer 发来的证书身份 header；验链后把可影响的 subject 文本错误映射到账号；接受错误 trust domain、EKU、audience、有效期。可信代理终止时核实只有代理能连、清除入站身份 header、后端绑定净化后身份。
- **证书生命周期 fallback**：过期、吊销、缺失、续期失败时静默退回 bearer 或匿名；长连接池在吊销后保留授权。

## 验证与反证

1. **源码可见性闸门**：代理链、边缘 cache key、IdP 策略、证书信任、浏览器 cookie 行为、secret、部署认证模式可能在仓库外，缺失时记 Needs Validation 并写明缺失事实，不断言基础设施行为。
2. Framing/cache：写出两个组件及分歧解析/key，证明跨请求、跨用户或私有响应影响，只用有界本地 fixture，不向线上发流量。
3. Token、MFA、passkey、账号关联、恢复、API key、mTLS：引用验证行及缺失的 principal/session/resource/origin/audience/action/assurance 绑定，证明服务端接受非法迁移或凭据。
4. CSRF：写出 ambient 凭据、状态变更路由、被接受的跨站请求形态、cookie 策略、缺失的有效检查。只读操作、要求非 ambient bearer token 的路由不算。
5. 核实框架与库在所用版本的默认值；版本或配置未知记 Needs Validation，不把未验证的高危主张降级成低危 confirmed。
6. **常见误报**：单缺 header、cookie flag、MFA 提示、rate limit；公开标识符被称为 key；响应差异只暴露公开账号存在性。须有被接受的非法请求、跨 principal 影响、assurance 降级或凭据泄露。
7. 确认需完整源码路径和可观察的越权身份、状态或泄露；Needs Validation 写明缺失事实和安全的本地或所有者侧检查。
