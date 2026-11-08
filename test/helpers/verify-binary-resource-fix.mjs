// Run only in the remote gVisor validation sandbox with explicit read-only roots.
import {readFileSync,readdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const sha=b=>createHash('sha256').update(b).digest('hex');
function tree(root){const files={};function visit(dir){for(const e of readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){if(e.name==='node_modules'||e.name==='.git')continue;const p=join(dir,e.name);if(e.isDirectory())visit(p);else if(e.isFile())files[p.slice(root.length+1)]=sha(readFileSync(p))}}visit(root);return files}
const baseline='/baseline',candidate='/candidate',destination=process.argv[2];
if(process.platform!=='linux'||!destination)throw Error('Use the remote Linux gVisor sandbox and an explicit receipt path');
const a=tree(baseline),b=tree(candidate);
const versions=new Set(['package.json','package-lock.json','server.json','action.yml','.pre-commit-hooks.yaml','claude-plugin/.claude-plugin/plugin.json','claude-plugin/hooks/hooks.json','claude-plugin/skills/scan/SKILL.md','docs/landing/index.html','test/action.test.ts']);
const norm=s=>s.replaceAll('0.23.1-dev.20261107.1','<SOURCE_VERSION>').replaceAll('0.23.1-dev.20261107.2','<SOURCE_VERSION>');
const differences=[...new Set([...Object.keys(a),...Object.keys(b)])].sort().filter(file=>a[file]!==b[file]).map(file=>{
 let kind=null,allowed=false;
 if(versions.has(file)){kind='version-metadata-only';allowed=!!a[file]&&!!b[file]&&norm(readFileSync(join(baseline,file),'utf8'))===norm(readFileSync(join(candidate,file),'utf8'))}
 else if(file==='src/result-screen.ts'||/^dist\/result-screen\.(?:js|js\.map|d\.ts|d\.ts\.map)$/.test(file)){kind='return-path-resource-compatibility';allowed=true}
 else if(file==='test/two-sided-protocol.test.ts'){kind='same-test-count-resource-regressions';allowed=true}
 else if(file==='CHANGELOG.md'){kind='release-history';allowed=true}
 return {file,kind,allowed,before:a[file]??null,after:b[file]??null};
});
const classifierFiles=Object.keys(a).filter(file=>(file.startsWith('src/')||file.startsWith('dist/'))&&file!=='src/result-screen.ts'&&!/^dist\/result-screen\./.test(file)).sort();
const classifierByteEqual=classifierFiles.every(file=>a[file]===b[file]);
const classifierIdentitySha256=sha(JSON.stringify(Object.fromEntries(classifierFiles.map(file=>[file,a[file]]))));
const oldSdk=await import(pathToFileURL(baseline+'/dist/index.js').href),newSdk=await import(pathToFileURL(candidate+'/dist/index.js').href);
const expected={version:'19',digest:'sha256-XfRh1+VZoAM6PGtbmqprnSX/eF16qNYOk0o+ilRFxXw='};
const rulesetEqual=JSON.stringify(oldSdk.staticScanRulesetRef())===JSON.stringify(newSdk.staticScanRulesetRef())&&JSON.stringify(newSdk.staticScanRulesetRef())===JSON.stringify(expected);
const baselineVersion=JSON.parse(readFileSync(baseline+'/package.json')).version,candidateVersion=JSON.parse(readFileSync(candidate+'/package.json')).version;
const result={at:new Date().toISOString(),baselineVersion,candidateVersion,baselineFiles:Object.keys(a).length,candidateFiles:Object.keys(b).length,differences,classifierFiles:classifierFiles.length,classifierByteEqual,classifierIdentitySha256,rulesetEqual,ruleset:newSdk.staticScanRulesetRef()};
result.passed=baselineVersion==='0.23.1-dev.20261107.1'&&candidateVersion==='0.23.1-dev.20261107.2'&&classifierByteEqual&&rulesetEqual&&differences.every(d=>d.allowed);
writeFileSync(destination,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));process.exitCode=result.passed?0:1;
