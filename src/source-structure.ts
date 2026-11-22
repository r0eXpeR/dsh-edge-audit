import { redactSensitive } from './audit-context.js'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { cachedAnalysis } from './analysis-cache.js'
import { parse } from '@typescript-eslint/typescript-estree'
export type BoundaryKind='entrypoint'|'control'|'sink'|'identity'|'lifecycle'
export interface SourceFact {file:string;line:number;column?:number;kind:BoundaryKind;symbol:string;evidence:'syntax'|'textual_lead';syntaxKind?:'call'|'member'}
interface Node {type?:string;name?:string;value?:unknown;loc?:{start:{line:number;column:number}};range?:[number,number];[key:string]:unknown}
const patterns:Array<{kind:BoundaryKind;pattern:RegExp}>=[
 {kind:'entrypoint',pattern:/\b(?:app|router|Route)[.:]+(?:get|post|put|patch|delete|use|any|route|resource)\b|\b(?:GetMapping|PostMapping|RequestMapping|HttpGet|HttpPost|HandleFunc|doGet|doPost|ipcMain|WebSocket|subscribe|webhook)\b|\b(?:req|request)\.(?:body|query|params|args|form)|\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)/i},
 {kind:'control',pattern:/\b(?:authorize|authorizeResource|can|cannot|Gate|Policy|checkPermission|requireAuth|isAuthenticated|hasRole|middleware|validate|sanitize|allowlist|escape)\b/i},
 {kind:'sink',pattern:/\b(?:eval|exec|execFile|spawn|system|shell_exec|unserialize|deserialize|render_template_string|innerHTML|query|execute|fetch|writeFile|file_put_contents|sendFile)\b/i},
 {kind:'identity',pattern:/\b(?:tenant(?:Id|_id)?|owner(?:Id|_id)?|user_id|accountId|principal|session|jwt)\b/i},
 {kind:'lifecycle',pattern:/\b(?:refund|restore|revoke|delete|cancel|retry|rollback|commit|expire|catch|finally|default|idempotency|transaction)\b/i},
]
function name(raw:unknown):string{const n=raw as Node|undefined;if(!n)return '';if(n.type==='Identifier')return n.name??'';if(n.type==='Literal')return typeof n.value==='string'?n.value:'';if(n.type==='MemberExpression')return `${name(n.object)}.${name(n.property)}`;if(n.type==='ChainExpression')return name(n.expression);return ''}

function localImportLeads(file:string,line:string,lineNumber:number):Array<{specifier:string;line:number;evidence:'textual_lead'}>{
 const leads:string[]=[]
 if(file.endsWith('.py')){
  const from=/^\s*from\s+([.\w]+)\s+import\s+([\w,\s]+)/.exec(line)
  if(from){if(/^\.+$/.test(from[1]))leads.push(...from[2].split(',').map(name=>`${from[1]}${name.trim()}`).filter(value=>/^[.\w]+$/.test(value)));else leads.push(from[1])}
  const direct=/^\s*import\s+([\w.]+)/.exec(line);if(direct)leads.push(direct[1])
 }else if(/\.(?:php|phtml|php5|inc)$/.test(file)){
  const include=/\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?(?:__DIR__\s*\.\s*)?['"]([^'"]+)['"]/.exec(line)
  if(include)leads.push(include[1])
 }else if(file.endsWith('.java')){
  const imported=/^\s*import\s+(?:static\s+)?([\w.]+)\s*;/.exec(line)
  if(imported&&!imported[1].endsWith('.*'))leads.push(imported[1])
 }else if(file.endsWith('.rs')){
  const module=/^\s*mod\s+([A-Za-z_]\w*)\s*;/.exec(line)
  if(module)leads.push(`./${module[1]}`)
 }
 return leads.map(specifier=>({specifier,line:lineNumber,evidence:'textual_lead'}))
}

/** JS/TS 使用语法节点，其他语言仅提供带不确定性标记的文本线索。 */
function collectSourceStructureUncached(file:string,content:string){
 const facts:SourceFact[]=[],imports:Array<{specifier:string;line:number;evidence:'syntax'|'textual_lead'}>=[],limitations:string[]=[]
 const add=(line:number,symbol:string,evidence:SourceFact['evidence'],syntaxKind?:SourceFact['syntaxKind'],column?:number)=>{for(const {kind,pattern}of patterns)if(pattern.test(symbol)&&!facts.some(f=>f.line===line&&f.column===column&&f.kind===kind&&f.symbol===symbol))facts.push({file,line,kind,symbol:symbol.slice(0,180),evidence,...(syntaxKind?{syntaxKind}:{}),...(column!==undefined?{column}:{})})}
 if(/\.(?:[cm]?[jt]s|[jt]sx)$/.test(file)){
  try{
   const ast=parse(content,{loc:true,range:true,jsx:/[jt]sx$/.test(file)}) as unknown as Node
   const visit=(node:Node)=>{
    const line=node.loc?.start.line??1
    if(node.type==='ImportDeclaration'||node.type==='ExportNamedDeclaration'||node.type==='ExportAllDeclaration'||node.type==='ImportExpression'){const value=(node.source as Node|undefined)?.value;if(typeof value==='string')imports.push({specifier:value,line,evidence:'syntax'})}
    if(node.type==='CallExpression'||node.type==='NewExpression'){
     const symbol=name(node.callee);add(line,symbol,'syntax','call',node.loc?.start.column)
     const args=node.arguments as Node[]|undefined;if(symbol==='require'&&typeof args?.[0]?.value==='string')imports.push({specifier:args[0].value,line,evidence:'syntax'})
    }
    if(node.type==='MemberExpression'||node.type==='AssignmentExpression')add(line,name(node.type==='MemberExpression'?node:node.left),'syntax','member',node.loc?.start.column)
    if(node.type==='Identifier'&&patterns.find(p=>p.kind==='control')!.pattern.test(node.name??''))add(line,node.name??'','syntax')
    if(node.type==='CatchClause')add(line,'catch','syntax')
    if(node.type==='TryStatement'&&node.finalizer)add(line,'finally','syntax')
    for(const [key,value]of Object.entries(node)){if(['loc','range','tokens','comments'].includes(key))continue;if(Array.isArray(value)){for(const child of value)if(child&&typeof child==='object'&&'type'in child)visit(child as Node)}else if(value&&typeof value==='object'&&'type'in value)visit(value as Node)}
   }
   visit(ast);return {facts,imports,limitations}
  }catch(error){limitations.push(`${file}: JS/TS syntax map unavailable; textual leads only (${(error as Error).message.slice(0,160)}).`)}
 }
 content.split(/\r?\n/).forEach((line,index)=>{
  if(/^\s*(?:\/\/|#|\*|\/\*)/.test(line))return
  add(index+1,line.trim(),'textual_lead')
  imports.push(...localImportLeads(file,line,index+1))
 })
 return {facts,imports,limitations}
}

const structureVersion=createHash('sha256').update(readFileSync(new URL(import.meta.url))).update(process.versions.node).digest('hex')
export function collectSourceStructure(file:string,content:string){return cachedAnalysis(structureVersion,'source-structure-only',{file,content},()=>collectSourceStructureUncached(file,redactSensitive(content)))}
