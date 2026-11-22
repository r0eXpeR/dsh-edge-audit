// 仅虚拟租户和内存数据。用于证明业务对象边界，不能作为模型检出率。
import { readInvoice } from './route.mjs'
const session = { user: { id: 'alice', role: 'member', tenantId: 'tenant-a' } }
const store = [{ id: 'invoice-a', tenantId: 'tenant-a', amount: 10 }, { id: 'invoice-b', tenantId: 'tenant-b', amount: 99 }]
const own = readInvoice(session, { invoiceId: 'invoice-a' }, store)
let crossTenantVisible = false
try { crossTenantVisible = readInvoice(session, { invoiceId: 'invoice-b' }, store).tenantId === 'tenant-b' }
catch (error) { if (error.code !== 'DENIED') throw error }
console.log(JSON.stringify({ crossTenantVisible, ownTenantStillWorks: own.id === 'invoice-a' }))
