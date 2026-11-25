const fs = require('fs'), vm = require('vm'), assert = require('node:assert/strict');
const html = fs.readFileSync('/source/rdgenerator/templates/generator.html','utf8');
const save = html.slice(html.indexOf('async function saveFormData('),html.indexOf('async function readFileAsBase64'));
const load = html.slice(html.indexOf('function loadFormData()'),html.indexOf('</script>',html.indexOf('function loadFormData()')));
function setup(imported) {
  let listener, saved, unsafe = 0;
  const nodes = {};
  const node = id => nodes[id] ||= {value:'',type:'text',files:[],style:{},click(){},querySelectorAll(){return[]},addEventListener(_,f){listener=f},replaceChildren(img){this.firstChild=img}};
  for(const id of ['icon-preview','logo-preview','privacy-preview']) Object.defineProperty(node(id),'innerHTML',{set(v){unsafe++;this.markup=v}});
  node('csrfmiddlewaretoken').value='fresh-browser-token';
  node('{{ form.exename.id_for_label }}').value='client';
  node('iconfile').type='file';
  const document={getElementById:node,body:{appendChild(){},removeChild(){}},createElement(tag){return{tag,style:{},click(){}}},querySelectorAll(sel){if(sel.includes('csrfmiddlewaretoken'))return[node('csrfmiddlewaretoken')];if(sel.includes('iconfile'))return[node('iconfile')];return[]}};
  const context={document,console,carriedUnknownFields:{},showLoadWarnings(){},syncThemeColorFromText(){},updateThemeLive(){},File:class{},FormData:class{forEach(f){f('fresh-browser-token','csrfmiddlewaretoken');f('client','exename');if (html.includes('{{ form.relayServer }}')) f('relay.example:21117','relayServer')}},Blob:class{constructor(parts){saved=JSON.parse(parts.join(''))}},URL:{createObjectURL(){return'x'},revokeObjectURL(){}},FileReader:class{readAsText(){this.onload({target:{result:JSON.stringify(imported)}})}} ,alert(message){throw Error(message)}};
  vm.createContext(context);vm.runInContext(save+'\n'+load,context);
  return {context,nodes,node,load(){context.loadFormData();listener({target:{files:[{}]}})},saved:()=>saved,unsafe:()=>unsafe};
}
(async()=>{
 let failures=0;
 const tests={
 'local profile excludes unrelated form data':async()=>{const x=setup({});x.context.carriedUnknownFields.unrelatedSetting='active';await x.context.saveFormData(true);assert.equal(x.saved().relayServer,'relay.example:21117');assert.equal(x.saved().unrelatedSetting,undefined)},
 'export includes the local relay':async()=>{const x=setup({});await x.context.saveFormData();assert.equal(x.saved().relayServer,'relay.example:21117')},
 'export excludes browser csrf token':async()=>{const x=setup({});await x.context.saveFormData();assert.equal(x.saved().csrfmiddlewaretoken,undefined)},
 'import preserves fresh csrf token':async()=>{const x=setup({csrfmiddlewaretoken:'stale-token'});x.load();assert.equal(x.node('csrfmiddlewaretoken').value,'fresh-browser-token')},
 'imported image markup cannot enter HTML sink':async()=>{const x=setup({iconfile:'x" onerror="alert(1)'});x.load();assert.equal(x.unsafe(),0);assert.equal(x.node('id_iconbase64').value,'')},
 'valid PNG renders as img element':async()=>{const png='data:image/png;base64,iVBORw0KGgo=';const x=setup({iconfile:png});x.load();assert.equal(x.node('icon-preview').firstChild.src,png);assert.equal(x.unsafe(),0)}
 };
 for(const [name,fn] of Object.entries(tests)){try{await fn();console.log('PASS '+name)}catch(e){failures++;console.log('FAIL '+name+': '+e.message.split('\n')[0])}}
 process.exitCode=failures?1:0;
})();
