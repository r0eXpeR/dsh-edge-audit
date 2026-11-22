/** 在序列化前分页，保持完整 JSON；超大单行需专门的详情工具，不能从字符串中间截断。 */
export function boundedPage<T>(items:readonly T[],offset:number,limit:number,key:string,envelope:Record<string,unknown>,maxBytes=24576):Record<string,unknown>{
  const start=Math.max(0,Math.floor(offset)),size=Math.max(1,Math.min(100,Math.floor(limit))),rows=items.slice(start,start+size)
  const make=()=>({...envelope,[key]:rows,total:items.length,...(start+rows.length<items.length?{nextOffset:start+rows.length}:{})})
  while(Buffer.byteLength(JSON.stringify(make()))>maxBytes&&rows.length>1)rows.pop()
  if(Buffer.byteLength(JSON.stringify(make()))>maxBytes)throw new Error('One tool page exceeds its safe JSON budget; use the supplied paginated detail/context tool or a smaller assignment.')
  return make()
}
