const fs=require('fs'),vm=require('vm'),assert=require('assert');
const page=fs.readFileSync(process.argv[2],'utf8');
const source=page.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
const elements={};
function node(tag='div'){return {tag,children:[],style:{},dataset:{},value:'',textContent:'',hidden:false,disabled:false,checked:false,open:false,classList:{toggle(){}},append(...values){this.children.push(...values);},replaceChildren(...values){this.children=[...values];},setAttribute(){},querySelectorAll(){return [];},addEventListener(){},focus(){},scrollIntoView(){},showModal(){this.open=true;},close(){this.open=false;},reset(){for(const id of ['analyst-name','analyst-choice','analyst-reason'])get(id).value='';get('analyst-ack').checked=false;},reportValidity(){return true;}};}
const get=id=>elements[id]??=(node());
const assessment={decision:'RESTRICT',priority:'URGENT',coverage:.25,checks:[{rule_name:'Encryption',status:'FAIL'},...['Patch','Lifecycle','CVE'].map(rule_name=>({rule_name,status:'UNKNOWN'}))]};
const asset={id:1,vendor:'Test',product:'PLC',ip:'192.0.2.1',port:502,zone:'OT',service:'Modbus',key_factors:assessment,analyst_review:null};
let token='a'.repeat(64),posts=[],stale=false;
const context={document:{hidden:false,getElementById:get,createElement:node,createTextNode:text=>({textContent:text})},window:{matchMedia:()=>({matches:true})},requestAnimationFrame:fn=>fn(),CaveOT:{onScanState(){}},setInterval(){},console,
fetch:async(url,options={})=>{if(url==='/api/policy/assets')return {ok:true,json:async()=>[asset]};if(url==='/api/policy/review/1'&&options.method==='POST'){posts.push(JSON.parse(options.body));if(stale){stale=false;token='b'.repeat(64);return {ok:false,status:409,json:async()=>({error:'Evidence changed'})};}return {ok:true,json:async()=>({review:{analyst_decision:posts.at(-1).decision}})};}if(url==='/api/policy/review/1')return {ok:true,json:async()=>({asset,assessment,assessment_fingerprint:token,history:[]})};throw Error(url);}};
vm.createContext(context);vm.runInContext(source,context);
(async()=>{
 await new Promise(resolve=>setImmediate(resolve));
 const counts=vm.runInContext('ruleCounts(policyAssets[0].key_factors)',context);
 assert.equal(counts.fail,1);assert.equal(counts.missing,3);assert.equal(counts.pass,0);
 await vm.runInContext('openManualReview(1)',context);
 assert(get('analyst-dialog').open);
 get('analyst-choice').value='APPROVE';context.updateAcknowledgment();assert(get('analyst-ack').required);
 get('analyst-name').value='Analyst';get('analyst-reason').value='Reviewed compensating controls.';get('analyst-ack').checked=true;
 await get('analyst-form').onsubmit({preventDefault(){}});
 assert.equal(posts.length,1);assert.equal(posts[0].decision,'APPROVE');assert.equal(posts[0].assessment_fingerprint,'a'.repeat(64));assert(posts[0].acknowledge_findings);assert(!get('analyst-dialog').open);
 await vm.runInContext('openManualReview(1)',context);get('analyst-choice').value='APPROVE';get('analyst-name').value='Analyst';get('analyst-reason').value='Reviewed again after change.';get('analyst-ack').checked=true;stale=true;
 await get('analyst-form').onsubmit({preventDefault(){}});
 assert(get('analyst-dialog').open);assert(!get('analyst-ack').checked);assert(get('analyst-message').textContent.includes('Evidence changed'));
 assert.equal(vm.runInContext('manualReview.assessment_fingerprint',context),'b'.repeat(64));
 console.log('Passed: explicit rule counts, manual approval payload, acknowledgment, and stale-evidence recovery.');
})().catch(error=>{console.error(error);process.exitCode=1;});
