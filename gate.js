const form=document.querySelector('#accessForm'),password=document.querySelector('#accessPassword'),message=document.querySelector('#accessMessage'),submit=document.querySelector('#accessSubmit'),visibility=document.querySelector('#passwordVisibility');
const STORAGE_KEY='uxuy-encrypted-session-v1',SESSION_MS=12*60*60*1000,AAD=new TextEncoder().encode('UXUY-CONTENT-BUNDLE/v1');
let encryptedPackage=null,mounted=false,expiryTimer=null;
const bytes=value=>Uint8Array.from(atob(value),char=>char.charCodeAt(0));
const encoded=value=>btoa(String.fromCharCode(...new Uint8Array(value)));
function forget(){try{sessionStorage.removeItem(STORAGE_KEY);}catch{}}
function signOut(){forget();clearTimeout(expiryTimer);delete window.__UXUY_PRIVATE_CONTENTS__;delete window.uxuySignOut;document.body.replaceChildren();location.reload();}
async function loadPackage(){
 if(encryptedPackage)return encryptedPackage;
 const response=await fetch('./encrypted.json?v=20261103-github-v1',{cache:'no-store'});
 if(!response.ok)throw new Error('内容暂时无法载入，请刷新后重试。');
 const value=await response.json();
 if(value.format!=='uxuy-encrypted-v1'||value.kdf?.name!=='PBKDF2'||value.kdf?.hash!=='SHA-256'||value.kdf.iterations!==600000||value.cipher?.name!=='AES-GCM'||value.cipher.tagLength!==128||bytes(value.kdf.salt).length!==16||bytes(value.cipher.iv).length!==12||typeof value.id!=='string'||typeof value.payload!=='string'||value.payload.length>5_000_000)throw new Error('内容包无效，请联系管理员。');
 encryptedPackage=value;return value;
}
async function deriveKey(value,packageData){
 const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(value),'PBKDF2',false,['deriveBits']);
 return crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:bytes(packageData.kdf.salt),iterations:packageData.kdf.iterations},material,256);
}
async function decryptPackage(rawKey,packageData){
 const key=await crypto.subtle.importKey('raw',rawKey,{name:'AES-GCM'},false,['decrypt']);
 const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(packageData.cipher.iv),additionalData:AAD,tagLength:128},key,bytes(packageData.payload));
 const payload=JSON.parse(new TextDecoder().decode(plain));
 if(payload.version!==1||typeof payload.body!=='string'||typeof payload.app!=='string'||typeof payload.css!=='string'||!payload.content?.zh||!payload.content?.en)throw new Error('Invalid private payload');
 return payload;
}
function mount(payload,expiresAt){
 if(mounted)return;
 mounted=true;
 document.querySelector('#gateStyles')?.remove();
 const style=document.createElement('style');style.id='workspaceStyles';style.textContent=payload.css;document.head.append(style);
 document.body.className='';document.body.dataset.view='canvas';document.body.innerHTML=payload.body;
 window.__UXUY_PRIVATE_CONTENTS__=payload.content;window.uxuySignOut=signOut;
 document.title=payload.title;
 const url=URL.createObjectURL(new Blob([payload.app],{type:'text/javascript'}));
 const script=document.createElement('script');script.type='module';script.src=url;
 script.addEventListener('load',()=>URL.revokeObjectURL(url),{once:true});
 script.addEventListener('error',()=>{URL.revokeObjectURL(url);signOut();},{once:true});
 document.body.append(script);
 expiryTimer=setTimeout(signOut,Math.max(0,expiresAt-Date.now()));
}
async function restore(){
 let saved;try{saved=JSON.parse(sessionStorage.getItem(STORAGE_KEY)||'null');}catch{forget();return;}
 if(!saved||!Number.isFinite(saved.expiresAt)||saved.expiresAt<=Date.now()||saved.expiresAt>Date.now()+SESSION_MS+10000||typeof saved.key!=='string'){forget();return;}
 try{const packageData=await loadPackage();if(saved.id!==packageData.id){forget();return;}const raw=bytes(saved.key);if(raw.length!==32)throw new Error();const payload=await decryptPackage(raw,packageData);mount(payload,saved.expiresAt);}catch{forget();}
}
visibility.addEventListener('click',()=>{const show=password.type==='password';password.type=show?'text':'password';visibility.textContent=show?'隐藏':'显示';visibility.setAttribute('aria-label',show?'隐藏密码':'显示密码');visibility.setAttribute('aria-pressed',String(show));password.focus();});
form.addEventListener('submit',async event=>{
 event.preventDefault();if(submit.disabled||mounted||!password.value)return;
 submit.disabled=true;submit.querySelector('span').textContent='正在验证…';message.textContent='';password.removeAttribute('aria-invalid');
 let packageData;
 try{packageData=await loadPackage();}catch(error){message.textContent=error.message;submit.disabled=false;submit.querySelector('span').textContent='进入工作台';return;}
 try{
  const raw=await deriveKey(password.value,packageData);password.value='';const payload=await decryptPackage(raw,packageData),expiresAt=Date.now()+SESSION_MS;
  try{sessionStorage.setItem(STORAGE_KEY,JSON.stringify({id:packageData.id,key:encoded(raw),expiresAt}));}catch{}
  mount(payload,expiresAt);
 }catch{password.value='';message.textContent='密码不正确，请重试。';password.setAttribute('aria-invalid','true');password.focus();submit.disabled=false;submit.querySelector('span').textContent='进入工作台';}
});
addEventListener('pageshow',event=>{if(event.persisted&&mounted){document.body.replaceChildren();location.reload();}});
document.addEventListener('click',event=>{if(event.target.closest('[data-reload]'))location.reload();});
restore();
