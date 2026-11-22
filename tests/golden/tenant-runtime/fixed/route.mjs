import { findInvoice } from './service.mjs'
export function readInvoice(session, request, store) {
  if (!session?.user) throw Object.assign(new Error('Authentication required'), { code: 'DENIED' })
  return findInvoice(store, request.invoiceId, session.user)
}
