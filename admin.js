'use strict';
/* Mente en Calma — control de cuentas por terminal (Node >= 22.13, sin dependencias).
   Se ejecuta en el MISMO servidor/carpeta donde corre server.js. Puede usarse con el servidor encendido o apagado.
   Privacidad: esta herramienta NO descifra respuestas ni resultados de las personas (igual que el panel web). */
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const DB_FILE = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'mente.db'); // DATA_DIR igual que en server.js
const hp = (p, s = crypto.randomBytes(16).toString('hex')) => s + ':' + crypto.scryptSync(p, s, 64).toString('hex'); // idéntico a server.js
const vp = (p, h) => { try { const [s, x] = h.split(':'); return crypto.timingSafeEqual(Buffer.from(x), Buffer.from(hp(p, s).split(':')[1])); } catch { return false; } };

const c = { r: s => `\x1b[31m${s}\x1b[0m`, g: s => `\x1b[32m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`, d: s => `\x1b[2m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };
const die = m => { console.error(c.r('✖ ' + m)); process.exit(1); };
const pad = (s, n) => String(s ?? '').padEnd(n).slice(0, n);

function open() {
  if (!fs.existsSync(DB_FILE)) die(`No existe la base de datos:\n  ${DB_FILE}\nArranca el servidor una vez (node server.js) desde esta misma carpeta, o revisa que estés en la carpeta correcta del proyecto.`);
  const db = new DatabaseSync(DB_FILE);
  db.exec('PRAGMA busy_timeout=5000;PRAGMA foreign_keys=ON;PRAGMA secure_delete=ON;');
  try { db.exec('ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0'); } catch {}
  try { db.exec('ALTER TABLE users ADD COLUMN share INTEGER NOT NULL DEFAULT 0'); } catch {}
  try { db.exec('ALTER TABLE users ADD COLUMN share_at TEXT'); } catch {}
  return db;
}

const now = () => new Date().toISOString();
const log = (db, uid, a) => db.prepare('INSERT INTO audit(ts,user_id,action) VALUES(?,?,?)').run(now(), uid, a);
const find = (db, alias) => { if (!alias) die('Falta el alias.'); const u = db.prepare('SELECT * FROM users WHERE alias=?').get(alias.toLowerCase()); if (!u) die(`No existe la cuenta "${alias}". Mira las cuentas con: node admin.js list`); return u; };
/* Cuántos admins ACTIVOS quedarían sin contar a esta cuenta (siempre debe quedar al menos uno) */
const otherAdmins = (db, id) => db.prepare("SELECT COUNT(*) n FROM users WHERE role='admin' AND disabled=0 AND id<>?").get(id).n;

/* Lee una contraseña sin mostrarla en pantalla */
function ask(q) {
  return new Promise(res => {
    if (!process.stdin.isTTY) { /* modo no interactivo (tuberías/scripts): una línea por pregunta */
      if (!ask.q) ask.q = new Promise(r => { let b = ''; process.stdin.on('data', d => b += d).on('end', () => r(b.split(/\r?\n/))); });
      return ask.q.then(l => res(l.shift() ?? ''));
    }
    process.stdout.write(q);
    let v = ''; process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.setEncoding('utf8');
    const on = ch => {
      for (const k of ch) {
        if (k === '\r' || k === '\n') { process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.off('data', on); process.stdout.write('\n'); return res(v); }
        if (k === '\u0003') { process.stdout.write('\n'); process.exit(130); }
        if (k === '\u007f' || k === '\b') v = v.slice(0, -1); else v += k;
      }
    };
    process.stdin.on('data', on);
  });
}

const cmds = {
  /* ---------- diagnóstico ---------- */
  async check() {
    console.log(c.b('\nDiagnóstico de acceso\n'));
    console.log('Carpeta del proyecto :', __dirname);
    console.log('Base de datos        :', DB_FILE, fs.existsSync(DB_FILE) ? c.g('(existe)') : c.r('(NO existe)'));
    if (!fs.existsSync(DB_FILE)) return console.log(c.y('\n→ Arranca el servidor al menos una vez desde esta carpeta.'));
    const db = open();
    const ads = db.prepare("SELECT id,alias,pass,created FROM users WHERE role='admin'").all();
    if (!ads.length) return console.log(c.r('\nNo hay ningún administrador.'), c.y('\n→ Ejecuta: node admin.js reset-admin'));
    for (const a of ads) {
      const ok = /^[0-9a-f]{32}:[0-9a-f]{128}$/.test(a.pass);
      console.log(`\nAdmin  alias="${a.alias}"  id=${a.id}  creado=${a.created}`);
      console.log('Formato de clave guardada :', ok ? c.g('válido (scrypt salt:hash)') : c.r('CORRUPTO'));
      const last = db.prepare("SELECT ts FROM audit WHERE user_id=? AND action='login' ORDER BY id DESC LIMIT 1").get(a.id);
      console.log('Último ingreso exitoso    :', last ? last.ts : c.y('nunca'));
      const fails = db.prepare("SELECT COUNT(*) n FROM audit WHERE user_id=? AND action='login-fail' AND ts>?").get(a.id, new Date(Date.now() - 3600e3).toISOString()).n;
      console.log('Intentos fallidos (1 h)   :', fails >= 6 ? c.r(fails + ' → posible bloqueo temporal') : fails);
    }
    console.log('\nVariable ADMIN_PASSWORD en esta terminal:', process.env.ADMIN_PASSWORD ? c.y('definida (el servidor la aplicaría al arrancar si la ve)') : 'no definida');
    console.log(c.d('\nRecordatorios:\n • El usuario siempre es "admin" (en minúsculas) y se entra por "Acceso de administrador", no por el formulario normal.\n • La contraseña que se crea en "Registrarme" es de un participante y NUNCA sirve para admin.\n • Tras 6 fallos se bloquea 10 min (en memoria): reiniciar el servidor lo libera.\n • Si hay varias copias del proyecto, cada una tiene su propia base de datos y su propia clave de admin.\n'));
  },

  /* ---------- probar una clave sin tocar nada ---------- */
  async 'verify-admin'() {
    const db = open(), a = db.prepare("SELECT * FROM users WHERE role='admin' ORDER BY (alias='admin') DESC,id LIMIT 1").get();
    if (!a) die('No hay administrador.');
    const p = await ask('Contraseña a probar: ');
    console.log(vp(p, a.pass) ? c.g('✔ La contraseña es correcta para "' + a.alias + '".') : c.r('✖ No coincide.'));
  },

  /* ---------- crear / restablecer clave de admin ---------- */
  async 'reset-admin'(args) {
    const db = open(); let pw;
    if (args.includes('--generate')) pw = crypto.randomBytes(9).toString('base64url');
    else {
      pw = await ask('Nueva contraseña de admin (mín. 10 caracteres): ');
      if (pw.length < 10) die('Mínimo 10 caracteres.');
      if (pw !== await ask('Repítela: ')) die('No coinciden.');
    }
    if (pw.length < 10) die('Mínimo 10 caracteres.');
    const a = db.prepare("SELECT id FROM users WHERE role='admin' ORDER BY (alias='admin') DESC,id LIMIT 1").get();
    let id;
    if (a) { id = a.id; db.prepare('UPDATE users SET pass=? WHERE id=?').run(hp(pw), id); }
    else id = db.prepare("INSERT INTO users(alias,pass,role,created) VALUES('admin',?,'admin',?)").run(hp(pw), new Date().toISOString()).lastInsertRowid;
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);
    db.prepare('INSERT INTO audit(ts,user_id,action) VALUES(?,?,?)').run(new Date().toISOString(), id, 'cli:reset-admin');
    console.log(c.g(a ? '✔ Clave del administrador restablecida y sesiones cerradas.' : '✔ Administrador creado.'));
    console.log('  usuario: admin');
    if (args.includes('--generate')) console.log('  clave  : ' + c.b(pw) + c.d('   (anótala, no se vuelve a mostrar)'));
    console.log(c.d('  Si el servidor tiene bloqueo por intentos fallidos, reinícialo para liberarlo.'));
  },

  /* ---------- cuentas ---------- */
  /* node admin.js list [admin|user|blocked] */
  async list(args) {
    const db = open(), f = (args[0] || '').toLowerCase();
    const where = f === 'admin' ? "WHERE u.role='admin'" : f === 'user' ? "WHERE u.role='user'" : f === 'blocked' ? 'WHERE u.disabled=1' : '';
    const rows = db.prepare(`SELECT u.id,u.alias,u.role,u.disabled,u.share,u.created,
      (SELECT MAX(ts) FROM audit a WHERE a.user_id=u.id AND a.action='login') last,
      (SELECT COUNT(*) FROM results r WHERE r.user_id=u.id) n,
      (SELECT COUNT(*) FROM sessions s WHERE s.user_id=u.id AND s.expires>?) ses
      FROM users u ${where} ORDER BY u.role,u.id`).all(Date.now());
    console.log(c.b(pad('ID', 5) + pad('ALIAS', 24) + pad('ROL', 8) + pad('ESTADO', 12) + pad('COMPARTE', 10) + pad('CREADO', 12) + pad('ÚLTIMO INGRESO', 21) + pad('REG.', 6) + 'SES.'));
    for (const r of rows) {
      const rol = r.role === 'admin' ? c.y(pad('admin', 8)) : pad('user', 8), est = r.disabled ? c.r(pad('suspendida', 12)) : c.g(pad('activa', 12));
      console.log(pad(r.id, 5) + pad(r.alias, 24) + rol + est + pad(r.role === 'admin' ? '' : (r.share ? 'sí' : 'no'), 10) + pad((r.created || '').slice(0, 10), 12) + pad((r.last || '—').replace('T', ' ').slice(0, 19), 21) + pad(r.n, 6) + r.ses);
    }
    console.log(c.d(`\n${rows.length} cuenta(s).  Filtros: list admin | list user | list blocked`));
    console.log(c.d('COMPARTE = la persona autorizó que el administrador vea sus resultados individuales (decisión suya; no se puede forzar desde aquí).\nLos invitados no aparecen: viven solo en la memoria del servidor y no se guardan.'));
  },

  /* ---------- ROLES: tú decides quién es admin ---------- */
  async promote(args) {
    const db = open(), u = find(db, args[0]);
    if (u.role === 'admin') return console.log(c.y(`"${u.alias}" ya es administrador.`));
    if (u.disabled) die(`"${u.alias}" está suspendida. Actívala primero: node admin.js unblock ${u.alias}`);
    db.prepare("UPDATE users SET role='admin' WHERE id=?").run(u.id); db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id); log(db, u.id, 'cli:promote');
    console.log(c.g(`✔ "${u.alias}" ahora es ADMINISTRADOR.`) + c.d('  Su sesión se cerró; al volver a entrar verá el panel de administración.'));
    console.log(c.d('  Nota: un admin ve solo datos agregados, nunca respuestas individuales; y deja de ver la parte de participante.'));
  },
  async demote(args) {
    const db = open(), u = find(db, args[0]);
    if (u.role !== 'admin') return console.log(c.y(`"${u.alias}" ya es participante normal.`));
    if (!otherAdmins(db, u.id)) die('No puedes quitar al último administrador activo. Promueve primero a otra cuenta.');
    db.prepare("UPDATE users SET role='user' WHERE id=?").run(u.id); db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id); log(db, u.id, 'cli:demote');
    console.log(c.g(`✔ "${u.alias}" ahora es participante normal.`) + c.d('  Su sesión se cerró.'));
  },
  /* node admin.js create-admin <alias> : crea directamente una cuenta de administrador nueva */
  async 'create-admin'(args) {
    const a = String(args[0] || '').trim().toLowerCase();
    if (!/^[\p{L}\p{N}_-]{3,24}$/u.test(a)) die('Uso: node admin.js create-admin <alias>   (3 a 24 letras/números/_/-)');
    const db = open(); if (db.prepare('SELECT 1 x FROM users WHERE alias=?').get(a)) die(`"${a}" ya existe. Si es un participante, usa: node admin.js promote ${a}`);
    const pw = await ask('Contraseña (mín. 10 caracteres): '); if (pw.length < 10) die('Mínimo 10 caracteres.');
    if (pw !== await ask('Repítela: ')) die('No coinciden.');
    const id = db.prepare("INSERT INTO users(alias,pass,role,created) VALUES(?,?,'admin',?)").run(a, hp(pw), now()).lastInsertRowid; log(db, id, 'cli:create-admin');
    console.log(c.g(`✔ Administrador "${a}" creado.`));
  },

  /* ---------- SUSPENDER / REACTIVAR ---------- */
  async block(args) {
    const db = open(), u = find(db, args[0]);
    if (u.disabled) return console.log(c.y(`"${u.alias}" ya está suspendida.`));
    if (u.role === 'admin' && !otherAdmins(db, u.id)) die('No puedes suspender al último administrador activo.');
    db.prepare('UPDATE users SET disabled=1 WHERE id=?').run(u.id); db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id); log(db, u.id, 'cli:block');
    console.log(c.g(`✔ "${u.alias}" suspendida: no podrá entrar y su sesión se cerró.`) + c.d('  Sus datos se conservan.'));
  },
  async unblock(args) {
    const db = open(), u = find(db, args[0]);
    db.prepare('UPDATE users SET disabled=0 WHERE id=?').run(u.id); log(db, u.id, 'cli:unblock');
    console.log(c.g(`✔ "${u.alias}" activa de nuevo.`));
  },

  async sessions() {
    const db = open();
    const rows = db.prepare('SELECT u.alias,u.role,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.expires>? ORDER BY s.expires DESC').all(Date.now());
    if (!rows.length) return console.log('No hay sesiones activas.');
    console.log(c.b(pad('ALIAS', 26) + pad('ROL', 8) + 'EXPIRA'));
    rows.forEach(r => console.log(pad(r.alias, 26) + pad(r.role, 8) + new Date(r.expires).toLocaleString('es-CO')));
  },

  /* node admin.js logout <alias>   |   node admin.js logout --all */
  async logout(args) {
    const db = open();
    if (args[0] === '--all') { const n = db.prepare('DELETE FROM sessions').run().changes; return console.log(c.g(`✔ ${n} sesión(es) cerradas.`)); }
    if (!args[0]) die('Uso: node admin.js logout <alias> | --all');
    const u = db.prepare('SELECT id FROM users WHERE alias=?').get(args[0].toLowerCase()); if (!u) die('Alias no encontrado.');
    console.log(c.g(`✔ ${db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id).changes} sesión(es) cerradas.`));
  },

  /* node admin.js passwd <alias> : restablece la clave de CUALQUIER cuenta (participante o admin) */
  async passwd(args) {
    if (!args[0]) die('Uso: node admin.js passwd <alias>');
    const db = open(), u = db.prepare('SELECT id,role FROM users WHERE alias=?').get(args[0].toLowerCase());
    if (!u) die('Alias no encontrado.'); const min = u.role === 'admin' ? 10 : 8;
    const pw = await ask(`Nueva contraseña (mín. ${min} caracteres): `); if (pw.length < min) die(`Mínimo ${min} caracteres.`);
    db.prepare('UPDATE users SET pass=? WHERE id=?').run(hp(pw), u.id); db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);
    db.prepare('INSERT INTO audit(ts,user_id,action) VALUES(?,?,?)').run(new Date().toISOString(), u.id, 'cli:passwd');
    console.log(c.g('✔ Contraseña actualizada y sesiones cerradas.'));
  },

  /* node admin.js delete <alias> : borra cuenta y todos sus datos */
  async delete(args) {
    if (!args[0]) die('Uso: node admin.js delete <alias>');
    const db = open(), u = db.prepare('SELECT id,role FROM users WHERE alias=?').get(args[0].toLowerCase());
    if (!u) die('Alias no encontrado.'); if (u.role === 'admin') die(`"${u.alias}" es administrador. Primero quítale el rol: node admin.js demote ${u.alias}`);
    if (!args.includes('--yes')) { const t = await ask(`Se borrará "${args[0]}" y TODOS sus datos. Escribe el alias para confirmar: `); if (t.trim().toLowerCase() !== args[0].toLowerCase()) die('Cancelado.'); }
    db.prepare('DELETE FROM users WHERE id=?').run(u.id);
    db.prepare('INSERT INTO audit(ts,user_id,action) VALUES(?,?,?)').run(new Date().toISOString(), null, 'cli:delete:' + u.id);
    console.log(c.g('✔ Cuenta y datos borrados.'));
  },

  /* node admin.js audit [N] [alias] */
  async audit(args) {
    const db = open(), n = Math.min(+args[0] || 30, 500), al = args[1] ? args[1].toLowerCase() : null;
    const rows = db.prepare(`SELECT a.ts,a.action,u.alias,u.role FROM audit a LEFT JOIN users u ON u.id=a.user_id ${al ? 'WHERE u.alias=?' : ''} ORDER BY a.id DESC LIMIT ${n}`).all(...(al ? [al] : []));
    console.log(c.b(pad('FECHA (UTC)', 21) + pad('CUENTA', 24) + 'ACCIÓN'));
    rows.forEach(r => console.log(pad(r.ts.replace('T', ' ').slice(0, 19), 21) + pad(r.alias || '(borrada/anón.)', 24) + (/fail/.test(r.action) ? c.r(r.action) : r.action)));
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmd || !cmds[cmd]) {
  console.log(`${c.b('Mente en Calma — control de cuentas')}

${c.b('Ver')}
  node admin.js list [admin|user|blocked]  Cuentas, rol, estado, último ingreso, sesiones
  node admin.js audit [N] [alias]          Auditoría: ingresos, fallos, cambios de rol
  node admin.js sessions                   Sesiones activas
${c.b('Roles (tú decides quién es admin)')}
  node admin.js promote <alias>            Convierte una cuenta en ADMINISTRADOR
  node admin.js demote <alias>             La vuelve participante normal
  node admin.js create-admin <alias>       Crea un administrador nuevo
${c.b('Acceso')}
  node admin.js block <alias>              Suspende la cuenta (no entra; se conservan sus datos)
  node admin.js unblock <alias>            La reactiva
  node admin.js passwd <alias>             Restablece la clave de cualquier cuenta
  node admin.js logout <alias>|--all       Cierra sesiones
  node admin.js delete <alias>             Borra una cuenta de participante y sus datos
${c.b('Diagnóstico')}
  node admin.js check                      ¿Por qué no entra el admin?
  node admin.js reset-admin [--generate]   Restablece la clave del admin principal
  node admin.js verify-admin               Prueba una clave sin cambiar nada
`);
  process.exit(cmd ? 1 : 0);
}
process.removeAllListeners('warning');
cmds[cmd](args).then(() => process.exit(0)).catch(e => die(e.message));
