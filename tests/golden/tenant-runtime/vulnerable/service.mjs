export function findInvoice(store, id, principal) {
  const invoice = store.find(row => row.id === id)
  if (!invoice) throw Object.assign(new Error('Denied'), { code: 'DENIED' })
  return invoice
}
