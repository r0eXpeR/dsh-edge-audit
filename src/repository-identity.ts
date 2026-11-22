/** 同一仓库的干净版本、工作树和 Diff 使用同一身份；不把远程 URL 凭据写入状态。 */
export function repositoryIdentity(root:string,remote:string):string{
 const value=remote.trim().replace(/[?#].*$/,'')
 const github=/^(?:git@github\.com:|ssh:\/\/git@github\.com\/|https:\/\/(?:[^/@]+@)?github\.com\/)([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i.exec(value)
 if(github)return `${github[1]}/${github[2]}`.toLowerCase()
 if(!value)return root
 try{const url=new URL(value);return `${url.hostname.toLowerCase()}${url.port?':'+url.port:''}/${url.pathname.replace(/^\/+|\/+$/g,'').replace(/\.git$/,'')}`}catch{const scp=/^(?:[^@]+@)?([^:]+):(.+)$/.exec(value);return scp?`${scp[1].toLowerCase()}/${scp[2].replace(/\.git$/,'')}`:value}
}
