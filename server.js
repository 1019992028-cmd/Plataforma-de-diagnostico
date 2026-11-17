'use strict';
/* Mente en Calma — servidor (Node >= 22.13, sin dependencias externas).
   SQLite (node:sqlite) · cifrado AES-256-GCM de datos sensibles · scrypt · sesiones HttpOnly · copias automáticas */
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
let DatabaseSync;try{({DatabaseSync}=require('node:sqlite'))}catch{console.error('Se requiere Node 22.13 o superior (node:sqlite).');process.exit(1)}
/* DATA_DIR: carpeta de datos (en Render, el disco persistente, p. ej. /var/data). BACKUP_DIR: copias (por defecto dentro de DATA_DIR). */
const DATA=process.env.DATA_DIR||path.join(__dirname,'data'),BK=process.env.BACKUP_DIR||path.join(process.env.DATA_DIR||__dirname,'backups'),PORT=+process.env.PORT||3000,
  SECURE=process.env.COOKIE_SECURE==='1'||!!process.env.RENDER,PROXY=process.env.TRUST_PROXY==='1'||!!process.env.RENDER;
fs.mkdirSync(DATA,{recursive:true,mode:0o700});fs.mkdirSync(BK,{recursive:true,mode:0o700});

/* ---- Clave de cifrado (DATA_KEY en hex, o data/secret.key generado al primer arranque) ---- */
let KEY;
if(process.env.DATA_KEY)KEY=Buffer.from(process.env.DATA_KEY,'hex');
else{const f=path.join(DATA,'secret.key');if(!fs.existsSync(f))fs.writeFileSync(f,crypto.randomBytes(32).toString('hex'),{mode:0o600});KEY=Buffer.from(fs.readFileSync(f,'utf8').trim(),'hex')}
if(KEY.length!==32){console.error('La clave debe tener 32 bytes (64 caracteres hex).');process.exit(1)}
const enc=o=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',KEY,iv),ct=Buffer.concat([c.update(JSON.stringify(o),'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),ct]).toString('base64')};
const dec=s=>{const b=Buffer.from(s,'base64'),d=crypto.createDecipheriv('aes-256-gcm',KEY,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));return JSON.parse(Buffer.concat([d.update(b.subarray(28)),d.final()]).toString('utf8'))};
const hp=(p,s=crypto.randomBytes(16).toString('hex'))=>s+':'+crypto.scryptSync(p,s,64).toString('hex');
const vp=(p,h)=>{const[s,x]=h.split(':'),y=hp(p,s).split(':')[1];return crypto.timingSafeEqual(Buffer.from(x),Buffer.from(y))};
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');

/* ---- Base de datos ---- */
const db=new DatabaseSync(path.join(DATA,'mente.db'));
db.exec(`PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;PRAGMA secure_delete=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,alias TEXT UNIQUE NOT NULL,pass TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created TEXT,consent_at TEXT);
CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires INTEGER);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
CREATE TABLE IF NOT EXISTS quizzes(id TEXT PRIMARY KEY,title TEXT,intro TEXT,items TEXT,opts TEXT,sensitive INTEGER DEFAULT 1,published INTEGER DEFAULT 1,builtin INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,kind TEXT,quiz_id TEXT,score INTEGER,payload TEXT NOT NULL,ts TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts TEXT,user_id INTEGER,action TEXT);`);
try{db.exec('ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0')}catch{}
/* share=1: la persona autorizó (casilla opcional del consentimiento) que el administrador consulte sus resultados individuales */
try{db.exec('ALTER TABLE users ADD COLUMN share INTEGER NOT NULL DEFAULT 0')}catch{}
try{db.exec('ALTER TABLE users ADD COLUMN share_at TEXT')}catch{}
const Q=(s,...a)=>db.prepare(s).all(...a),Q1=(s,...a)=>db.prepare(s).get(...a),R=(s,...a)=>db.prepare(s).run(...a);
const audit=(u,a)=>R('INSERT INTO audit(ts,user_id,action) VALUES(?,?,?)',new Date().toISOString(),u,a);
const WHO5=['Me he sentido alegre y de buen humor','Me he sentido tranquilo/a y relajado/a','Me he sentido activo/a y con energía','Me he despertado sintiéndome fresco/a y descansado/a','Mi día a día ha tenido cosas que me interesan'];
const WOPTS=['Nunca','De vez en cuando','Menos de la mitad del tiempo','Más de la mitad del tiempo','La mayor parte del tiempo','Todo el tiempo'];
if(!Q1("SELECT 1 x FROM settings WHERE k='games'"))R("INSERT INTO settings VALUES('games',?)",JSON.stringify({1:true,2:true,3:true}));
const CALMA10=['Me he sentido abrumado/a por todo lo que tengo por hacer','He tenido dificultad para desconectarme de mis preocupaciones','He podido disfrutar de momentos de calma durante el día','Me he sentido irritable o con los nervios de punta','He notado tensión en el cuerpo (cuello, hombros, mandíbula)','He sentido que puedo manejar los problemas que se me presentan','Me ha costado conciliar el sueño o dormir de corrido por pensar en cosas','Me he sentido solo/a aunque hubiera personas alrededor','He tenido a quién acudir cuando necesité apoyo o conversar','Me ha costado concentrarme en lo que estoy haciendo'];
if(!Q1("SELECT 1 x FROM quizzes WHERE id='calma10'"))R("INSERT INTO quizzes VALUES('calma10','Calma y carga diaria (10 preguntas)','Durante el último mes…',?,?,1,1,1)",JSON.stringify(CALMA10),JSON.stringify(['Nunca','Casi nunca','A veces','Casi siempre','Siempre']));
if(!Q1("SELECT 1 x FROM quizzes WHERE id='who5'"))R("INSERT INTO quizzes VALUES('who5','Cuestionario de bienestar (WHO-5)','En las últimas dos semanas…',?,?,1,1,1)",JSON.stringify(WHO5),JSON.stringify(WOPTS));
{const env=process.env.ADMIN_PASSWORD,ad=Q1("SELECT id FROM users WHERE role='admin' ORDER BY (alias='admin') DESC,id LIMIT 1");
 if(env){if(env.length<10){console.error('ADMIN_PASSWORD: mínimo 10 caracteres');process.exit(1)}
  ad?R('UPDATE users SET pass=? WHERE id=?',hp(env),ad.id):R("INSERT INTO users(alias,pass,role,created) VALUES('admin',?,'admin',?)",hp(env),new Date().toISOString())}
 else if(!ad){const p=crypto.randomBytes(9).toString('base64url');R("INSERT INTO users(alias,pass,role,created) VALUES('admin',?,'admin',?)",hp(p),new Date().toISOString());
  console.log('\n=== ADMINISTRADOR CREADO ===\n usuario: admin\n clave:   '+p+'\n (se muestra una sola vez; cámbiala en Sistema > Cambiar contraseña)\n');}}

/* ---- Copias de seguridad ---- */
function backup(){const f=path.join(BK,'mente-'+new Date().toISOString().replace(/[:.]/g,'-')+'.db');db.exec(`VACUUM INTO '${f.replace(/'/g,"''")}'`);fs.chmodSync(f,0o600);
  const all=fs.readdirSync(BK).filter(x=>x.endsWith('.db')).sort();while(all.length>14)fs.unlinkSync(path.join(BK,all.shift()));return path.basename(f)}
backup();setInterval(()=>{try{backup()}catch(e){console.error('Backup falló',e)}},24*3600*1000).unref();

/* ---- Informe orientativo (solo WHO-5; los juegos NO se usan) ---- */
const AVISO='Este informe es orientativo: se basa únicamente en el cuestionario de bienestar WHO-5 (los juegos no se usan) y no es un diagnóstico ni reemplaza la valoración de un profesional. El WHO-5 no evalúa riesgo de autolesión: si piensas en hacerte daño o te sientes en peligro, llama ya al 123 o, en Bogotá, a la Línea 106.';
const LV=[
 {min:68,nivel:'Bajo',color:'#3d664c',titulo:'Por ahora no parece urgente',texto:'Tus respuestas sugieren un bienestar bueno en las últimas semanas. Consultar a un psicólogo es opcional; puede ser útil si más adelante notas algún cambio.',pasos:['Mantén las rutinas que te hacen bien (sueño, movimiento, vínculos).','Repite el cuestionario si algo cambia.','Si lo deseas, una consulta preventiva siempre es válida.']},
 {min:50,nivel:'Moderado',color:'#b8862b',titulo:'Conviene estar atento/a',texto:'Tu bienestar parece moderado. No indica un problema por sí solo, pero si esta sensación se mantiene más de dos semanas, vale la pena consultar.',pasos:['Cuida el descanso y haz una actividad agradable cada día.','Habla con alguien de confianza sobre cómo te sientes.','Si continúa o empeora, considera una cita con un psicólogo.']},
 {min:28,nivel:'Alto',color:'#d9822b',titulo:'Es recomendable agendar una consulta',texto:'Tus respuestas sugieren un bienestar bajo sostenido. Te recomendamos hablar con un psicólogo o profesional de salud en las próximas semanas.',pasos:['Agenda una cita con un psicólogo o con tu médico/EPS.','Cuéntale a una persona cercana cómo te has sentido.','Elige hoy una sola cosa pequeña y amable para ti.']},
 {min:0,nivel:'Muy alto',color:'#b85450',titulo:'Te recomendamos buscar apoyo profesional pronto',texto:'Tus respuestas indican que lo has pasado muy difícil. Es muy recomendable consultar a un profesional lo antes posible. No tienes que atravesarlo solo/a.',pasos:['Solicita una cita con un profesional de salud mental cuanto antes.','Habla hoy mismo con alguien de confianza.','Si te sientes en peligro o con ganas de hacerte daño: 123 o, en Bogotá, Línea 106.']}];
const level=p=>LV.find(x=>p>=x.min);
const rep=(alias,w)=>{const l=level(w[0].score);return{alias,fecha:new Date().toLocaleDateString('es-CO',{day:'numeric',month:'long',year:'numeric'}),score:w[0].score,prev:w[1]?w[1].score:null,nivel:l.nivel,color:l.color,titulo:l.titulo,texto:l.texto,pasos:l.pasos,aviso:AVISO}};
const who5=uid=>Q("SELECT score,ts FROM results WHERE user_id=? AND quiz_id='who5' AND score IS NOT NULL ORDER BY ts DESC",uid);

/* ---- HTTP ---- */
const tries=new Map();
/* Detrás del proxy de Render, remoteAddress es la del proxy (igual para todos). Render recomienda True-Client-IP. */
const ipOf=req=>PROXY&&req.headers['true-client-ip']?String(req.headers['true-client-ip']).trim().slice(0,64):req.socket.remoteAddress;
const J=(res,c,o,h={})=>{res.writeHead(c,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...h});res.end(JSON.stringify(o))};
const E=(res,c,m)=>J(res,c,{error:m});
const body=req=>new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>1e6){no(new Error('Solicitud demasiado grande'));req.destroy()}});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{no(new Error('JSON inválido'))}})});
/* ---- Invitados: SOLO en memoria RAM (nunca en SQLite, copias de seguridad ni auditoría). Se borran al salir, al cerrar la página,
   tras 60 min sin actividad o al reiniciar el servidor. Del WHO-5 solo se guarda el puntaje (para armar el informe). ---- */
const guests=new Map(),GIDLE=60*60e3,GMAX=300,gtries=new Map();
setInterval(()=>{const n=Date.now();for(const[k,g]of guests)if(g.exp<n)guests.delete(k);for(const[k,t]of gtries)if(t.until<n)gtries.delete(k)},60e3).unref();
const who=req=>{const m=/(?:^|; )sid=([a-f0-9]{64})/.exec(req.headers.cookie||'');if(!m)return null;
  const h=sha(m[1]),g=guests.get(h);if(g){if(g.exp<Date.now()){guests.delete(h);return null}g.exp=Date.now()+GIDLE;return{guest:true,h,g,alias:g.alias,role:'user'}}
  return Q1('SELECT u.id,u.alias,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.h=? AND u.disabled=0 AND s.expires>?',sha(m[1]),Date.now())||null};
function startSession(res,u){const t=crypto.randomBytes(32).toString('hex');R('DELETE FROM sessions WHERE expires<?',Date.now());
  R('INSERT INTO sessions VALUES(?,?,?)',sha(t),u.id,Date.now()+8*3600e3);
  return{'Set-Cookie':`sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${SECURE?'; Secure':''}`}}
const quiz=r=>({id:r.id,title:r.title,intro:r.intro,items:JSON.parse(r.items),opts:JSON.parse(r.opts),sensitive:!!r.sensitive,published:!!r.published,builtin:!!r.builtin});
const nums=(a,n,max)=>Array.isArray(a)&&a.length<=n&&a.every(x=>x===null||(Number.isFinite(x)&&x>=0&&x<=max));
const quizCheck=b=>{const q=Q1('SELECT * FROM quizzes WHERE id=? AND published=1',String(b.quizId));if(!q)return{e:[404,'Cuestionario no disponible.']};
  const n=JSON.parse(q.items).length;if(!nums(b.answers,n,5)||b.answers.length!==n)return{e:[400,'Respuestas no válidas.']};
  return{q,score:q.id==='who5'?(b.answers.every(x=>x!==null)?b.answers.reduce((a,x)=>a+x,0)*4:null):null}};

const server=http.createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
  const url=new URL(req.url,'http://x'),p=url.pathname,m=req.method;
  try{
    if(m==='GET'&&p==='/healthz'){res.writeHead(200,{'Content-Type':'text/plain'});return res.end('ok')}
    if(m==='GET'&&(p==='/'||p==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});return res.end(fs.readFileSync(path.join(__dirname,'public','index.html')))}
    if(!p.startsWith('/api/'))return E(res,404,'No encontrado');
    const b=['POST','PUT','DELETE'].includes(m)?await body(req):{};
    /* Registro e inicio de sesión */
    if(p==='/api/register'&&m==='POST'){
      const a=String(b.alias||'').trim().toLowerCase(),pw=String(b.password||'');
      if(b.consent!==true)return E(res,400,'Se requiere tu consentimiento expreso.');
      if(!/^[\p{L}\p{N}_-]{3,24}$/u.test(a)||a==='admin'||a.startsWith('invitado'))return E(res,400,'Alias no válido (3 a 24 letras o números).');
      if(pw.length<8)return E(res,400,'La contraseña debe tener al menos 8 caracteres.');
      if(Q1('SELECT 1 x FROM users WHERE alias=?',a))return E(res,409,'Ese alias ya existe. Elige otro.');
      const now=new Date().toISOString(),share=b.share===true?1:0,id=R('INSERT INTO users(alias,pass,role,created,consent_at,share,share_at) VALUES(?,?,?,?,?,?,?)',a,hp(pw),'user',now,now,share,share?now:null).lastInsertRowid;
      audit(id,'register'+(share?':share':''));return J(res,200,{alias:a,role:'user',share:!!share},startSession(res,{id}));
    }
    if(p==='/api/login'&&m==='POST'){
      const a=String(b.alias||'').trim().toLowerCase(),k=ipOf(req)+'|'+a,t=tries.get(k)||{n:0,until:0};
      if(t.until>Date.now())return E(res,429,'Demasiados intentos. Espera unos minutos.');
      const u=Q1('SELECT * FROM users WHERE alias=?',a);
      if(!u||!vp(String(b.password||''),u.pass)){t.n++;if(t.n>=6){t.until=Date.now()+10*60e3;t.n=0}tries.set(k,t);audit(u?u.id:null,'login-fail');return E(res,401,'Alias o contraseña incorrectos.')}
      if(u.disabled){audit(u.id,'login-blocked');return E(res,403,'Esta cuenta está suspendida. Contacta a quien administra la plataforma.')}
      tries.delete(k);audit(u.id,'login');return J(res,200,{alias:u.alias,role:u.role,share:!!u.share},startSession(res,u));
    }
    /* Invitado: sin cuenta, sin consentimiento de guardado (no se guarda nada). Límite por IP y total para evitar abuso de memoria. */
    if(p==='/api/guest'&&m==='POST'){
      const ip=ipOf(req),now=Date.now();let t=gtries.get(ip);if(!t||t.until<now)t={n:0,until:now+600e3};
      if(++t.n>20||guests.size>=GMAX){gtries.set(ip,t);return E(res,429,'Hay muchos invitados en este momento. Intenta de nuevo en unos minutos.')}
      gtries.set(ip,t);const tok=crypto.randomBytes(32).toString('hex'),alias='invitado-'+crypto.randomBytes(2).toString('hex');
      guests.set(sha(tok),{alias,exp:now+GIDLE,scores:[]});
      return J(res,200,{alias,role:'user',guest:true},{'Set-Cookie':`sid=${tok}; HttpOnly; SameSite=Strict; Path=/${SECURE?'; Secure':''}`});
    }
    const me=who(req);if(!me)return E(res,401,'Inicia sesión.');
    if(p==='/api/logout'&&m==='POST'){if(me.guest)guests.delete(me.h);const c=/sid=([a-f0-9]{64})/.exec(req.headers.cookie||'');if(c)R('DELETE FROM sessions WHERE h=?',sha(c[1]));return J(res,200,{ok:1},{'Set-Cookie':'sid=; Max-Age=0; Path=/'})}
    if(p==='/api/config'&&m==='GET'){
      const rows=Q(me.role==='admin'?'SELECT * FROM quizzes':'SELECT * FROM quizzes WHERE published=1').map(quiz);
      return J(res,200,{games:JSON.parse(Q1("SELECT v FROM settings WHERE k='games'").v),quizzes:rows});
    }
    /* Invitado: nada se escribe en disco */
    if(me.guest){
      if(p==='/api/results'&&m==='POST'){
        if(b.kind==='games'){if(!nums(b.neg,50,5e4)||!nums(b.neu,50,5e4))return E(res,400,'Datos no válidos.');return J(res,200,{ok:1})}
        if(b.kind==='quiz'){const c=quizCheck(b);if(c.e)return E(res,c.e[0],c.e[1]);
          if(c.score!==null){me.g.scores.unshift({score:c.score,ts:Date.now()});me.g.scores.length=Math.min(me.g.scores.length,10)}return J(res,200,{ok:1,score:c.score})}
        return E(res,400,'Tipo no válido.');
      }
      if(p==='/api/my/report'&&m==='GET'){if(!me.g.scores.length)return E(res,404,'Primero responde el cuestionario de bienestar (WHO-5) para generar tu informe.');return J(res,200,rep(me.alias,me.g.scores))}
      return E(res,404,'Como invitado no se guarda ningún dato.');
    }
    /* Participante */
    if(me.role==='user'){
      if(p==='/api/results'&&m==='POST'){
        const ts=new Date().toISOString();
        if(b.kind==='games'){
          if(!nums(b.neg,50,5e4)||!nums(b.neu,50,5e4))return E(res,400,'Datos no válidos.');
          R("DELETE FROM results WHERE user_id=? AND kind='games'",me.id);
          R("INSERT INTO results(user_id,kind,payload,ts) VALUES(?,'games',?,?)",me.id,enc({neg:b.neg,neu:b.neu,effort:['facil','dificil'].includes(b.effort)?b.effort:null,done:!!b.done,tasks:Math.min(3,+b.tasks||0),plant:b.plant==null?null:Math.min(8,Math.max(0,Math.round(+b.plant)||0))}),ts);return J(res,200,{ok:1});
        }
        if(b.kind==='quiz'){
          const c=quizCheck(b);if(c.e)return E(res,c.e[0],c.e[1]);const{q,score}=c;
          R('INSERT INTO results(user_id,kind,quiz_id,score,payload,ts) VALUES(?,?,?,?,?,?)',me.id,'quiz',q.id,score,enc({title:q.title,answers:b.answers}),ts);
          audit(me.id,'quiz:'+q.id);return J(res,200,{ok:1,score});
        }
        return E(res,400,'Tipo no válido.');
      }
      if(p==='/api/my/data'&&m==='GET'){
        const u=Q1('SELECT alias,created,consent_at,share,share_at FROM users WHERE id=?',me.id);
        return J(res,200,{perfil:{alias:u.alias,created:u.created,consent_at:u.consent_at,comparte_con_administrador:!!u.share,autorizacion_desde:u.share_at},accesos_del_administrador:Q('SELECT ts FROM audit WHERE action=? ORDER BY id',  'admin-view:'+me.id).map(x=>x.ts),resultados:Q('SELECT kind,quiz_id,score,payload,ts FROM results WHERE user_id=?',me.id).map(r=>({tipo:r.kind,cuestionario:r.quiz_id,puntaje:r.score,fecha:r.ts,...dec(r.payload)}))});
      }
      if(p==='/api/my/data'&&m==='DELETE'){audit(me.id,'self-delete');R('DELETE FROM users WHERE id=?',me.id);return J(res,200,{ok:1},{'Set-Cookie':'sid=; Max-Age=0; Path=/'})}
      if(p==='/api/my/report'&&m==='GET'){
        const w=who5(me.id);if(!w.length)return E(res,404,'Primero responde el cuestionario de bienestar (WHO-5) para generar tu informe.');
        audit(me.id,'report');return J(res,200,rep(me.alias,w));
      }
      if(p==='/api/my/share'&&m==='PUT'){const on=b.share===true?1:0;R('UPDATE users SET share=?,share_at=? WHERE id=?',on,on?new Date().toISOString():null,me.id);audit(me.id,on?'share:on':'share:off');return J(res,200,{share:!!on})}
    }
    /* Administrador: datos agregados; resultados individuales SOLO de quienes lo autorizaron (share=1) y cada consulta queda en la auditoría */
    if(me.role!=='admin'||!p.startsWith('/api/admin/'))return E(res,403,'No autorizado.');
    if(p==='/api/admin/games'&&m==='PUT'){const g={};for(const i of[1,2,3])g[i]=!!b[i];R("UPDATE settings SET v=? WHERE k='games'",JSON.stringify(g));return J(res,200,g)}
    if(p==='/api/admin/quizzes'&&m==='PUT'){
      const id=String(b.id||''),it=b.items,t=String(b.title||'').trim();
      if(!/^[a-z0-9]{1,24}$/.test(id)||!t||t.length>120||!Array.isArray(it)||it.length<5||it.length>30||it.some(x=>typeof x!=='string'||!x.trim()||x.length>300))return E(res,400,'Cuestionario no válido (5 a 30 preguntas).');
      const old=Q1('SELECT * FROM quizzes WHERE id=?',id);
      if(old&&old.builtin)R('UPDATE quizzes SET published=? WHERE id=?',b.published?1:0,id);
      else R('INSERT OR REPLACE INTO quizzes VALUES(?,?,?,?,?,1,?,0)',id,t,String(b.intro||'').slice(0,200),JSON.stringify(it.map(x=>x.trim())),JSON.stringify(['Nunca','Casi nunca','A veces','Casi siempre','Siempre']),b.published?1:0);
      audit(me.id,'quiz-save:'+id);return J(res,200,{ok:1});
    }
    let mm;
    if((mm=/^\/api\/admin\/quizzes\/([a-z0-9]+)$/.exec(p))&&m==='DELETE'){R('DELETE FROM quizzes WHERE id=? AND builtin=0',mm[1]);return J(res,200,{ok:1})}
    if(p==='/api/admin/stats'&&m==='GET'){
      const us=Q("SELECT id,alias,created,share FROM users WHERE role='user' ORDER BY created DESC"),lv={Bajo:0,Moderado:0,Alto:0,'Muy alto':0};let sum=0,n=0;
      for(const u of us){const w=who5(u.id);if(w.length){lv[level(w[0].score).nivel]++;sum+=w[0].score;n++}}
      return J(res,200,{participants:us.length,quizzes:Q1("SELECT COUNT(*) c FROM results WHERE kind='quiz'").c,avg:n?Math.round(sum/n):null,levels:lv,guests:guests.size,users:us.map(u=>({id:u.id,alias:u.alias,created:u.created,share:!!u.share,n:Q1('SELECT COUNT(*) c FROM results WHERE user_id=?',u.id).c}))});
    }
    if((mm=/^\/api\/admin\/participants\/(\d+)\/results$/.exec(p))&&m==='GET'){
      const u=Q1("SELECT id,alias,created,share,share_at FROM users WHERE id=? AND role='user'",+mm[1]);if(!u)return E(res,404,'Participante no encontrado.');
      if(!u.share)return E(res,403,'Esta persona no autorizó que el administrador vea sus resultados individuales.');
      audit(me.id,'admin-view:'+u.id);const qz={};
      const out=Q('SELECT kind,quiz_id,score,payload,ts FROM results WHERE user_id=? ORDER BY ts DESC',u.id).map(r=>{const d=dec(r.payload);
        if(r.kind==='games')return{tipo:'juegos',fecha:r.ts,neg:d.neg,neu:d.neu,meta:d.effort,completada:d.done,habitos:d.tasks,planta:d.plant==null?null:d.plant};
        const q=qz[r.quiz_id]||(qz[r.quiz_id]=Q1('SELECT items,opts FROM quizzes WHERE id=?',r.quiz_id)),it=q?JSON.parse(q.items):[],op=q?JSON.parse(q.opts):[];
        return{tipo:'cuestionario',cuestionario:r.quiz_id,titulo:d.title,fecha:r.ts,puntaje:r.score,nivel:r.score!=null?level(r.score).nivel:null,
          respuestas:d.answers.map((v,i)=>({n:i+1,pregunta:it[i]??null,valor:v,texto:v==null?null:(op[v]??null)}))}});
      return J(res,200,{alias:u.alias,created:u.created,autorizacion_desde:u.share_at,resultados:out});
    }
    if((mm=/^\/api\/admin\/participants\/(\d+)$/.exec(p))&&m==='DELETE'){R("DELETE FROM users WHERE id=? AND role='user'",+mm[1]);audit(me.id,'admin-delete:'+mm[1]);return J(res,200,{ok:1})}
    if(p==='/api/admin/backup'&&m==='POST'){audit(me.id,'backup');return J(res,200,{name:backup()})}
    if(p==='/api/admin/backups'&&m==='GET')return J(res,200,{list:fs.readdirSync(BK).filter(x=>x.endsWith('.db')).sort().reverse().map(x=>({name:x,kb:Math.round(fs.statSync(path.join(BK,x)).size/1024)}))});
    if(p==='/api/admin/password'&&m==='POST'){
      const u=Q1('SELECT * FROM users WHERE id=?',me.id);if(!vp(String(b.old||''),u.pass))return E(res,401,'La contraseña actual no es correcta.');
      if(String(b.new||'').length<10)return E(res,400,'La nueva contraseña debe tener al menos 10 caracteres.');
      R('UPDATE users SET pass=? WHERE id=?',hp(b.new),me.id);audit(me.id,'admin-password');return J(res,200,{ok:1});
    }
    return E(res,404,'No encontrado');
  }catch(e){console.error(e);E(res,400,e.message||'Error')}
});
for(const sg of['SIGTERM','SIGINT'])process.on(sg,()=>{console.log('Cerrando…');server.close(()=>{try{db.close()}catch{}process.exit(0)});setTimeout(()=>process.exit(0),8000).unref()});
server.listen(PORT,()=>console.log('Mente en Calma en http://localhost:'+PORT+(SECURE?'':'  (usa HTTPS con un proxy inverso en producción)')));
