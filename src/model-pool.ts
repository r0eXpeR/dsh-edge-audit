interface Ticket {limit:number;signal?:AbortSignal;start:()=>void;reject:(error:unknown)=>void;abort?:()=>void}
let active=0
const queue:Ticket[]=[]
function drain(){
 while(queue.length&&active<queue[0].limit){const ticket=queue.shift()!;ticket.signal?.removeEventListener('abort',ticket.abort!);active++;ticket.start()}
}
/** 共享 FIFO 配额覆盖 Deep 子审计和所有审计角色；排队取消不会创建空 Agent。 */
export async function acquireModelSlot(limit=6,signal?:AbortSignal):Promise<()=>void>{
 signal?.throwIfAborted();if(!Number.isFinite(limit))throw new Error('Audit model concurrency must be finite.');limit=Math.max(1,Math.min(32,Math.floor(limit)))
 await new Promise<void>((resolve,reject)=>{
  const ticket:Ticket={limit,signal,start:resolve,reject}
  ticket.abort=()=>{const index=queue.indexOf(ticket);if(index>=0)queue.splice(index,1);reject(signal?.reason??new Error('Queued audit worker cancelled.'));drain()}
  signal?.addEventListener('abort',ticket.abort,{once:true});queue.push(ticket);drain()
 })
 let released=false
 return ()=>{if(released)return;released=true;active--;drain()}
}
export function modelPoolStatus(){return {active,queued:queue.length}}

interface BudgetTicket {start:()=>void;reject:(error:unknown)=>void;abort?:()=>void}
interface BudgetQueue {active:boolean;waiting:BudgetTicket[]}
const budgetQueues=new Map<string,BudgetQueue>()
function drainBudget(key:string,state:BudgetQueue){
 if(state.active)return
 const ticket=state.waiting.shift()
 if(ticket){state.active=true;ticket.start()}
 else budgetQueues.delete(key)
}
/** 同一预算账户一次只放行一个模型 Worker；上一 Worker 的实测 usage 落账后才放行下一个。 */
export async function acquireBudgetScanSlot(key:string,signal?:AbortSignal):Promise<()=>void>{
 signal?.throwIfAborted()
 const state=budgetQueues.get(key)??{active:false,waiting:[]}
 budgetQueues.set(key,state)
 await new Promise<void>((resolve,reject)=>{
  const ticket:BudgetTicket={start:()=>{signal?.removeEventListener('abort',ticket.abort!);resolve()},reject}
  ticket.abort=()=>{const index=state.waiting.indexOf(ticket);if(index<0)return;state.waiting.splice(index,1);signal?.removeEventListener('abort',ticket.abort!);reject(signal?.reason??new Error('Queued budgeted audit worker cancelled.'));if(!state.active)drainBudget(key,state)}
  state.waiting.push(ticket)
  signal?.addEventListener('abort',ticket.abort,{once:true})
  if(signal?.aborted)ticket.abort()
  else drainBudget(key,state)
 })
 let released=false
 return ()=>{if(released)return;released=true;state.active=false;drainBudget(key,state)}
}
