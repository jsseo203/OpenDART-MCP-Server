import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const file = process.env.OAUTH_STORE_PATH || '/tmp/opendart-oauth/state.sqlite';
mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
const db = new DatabaseSync(file);
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS oauth (model TEXT, id TEXT, payload TEXT NOT NULL, grant_id TEXT, uid TEXT, user_code TEXT, expires INTEGER, consumed INTEGER, PRIMARY KEY (model,id));
CREATE INDEX IF NOT EXISTS oauth_grant ON oauth(grant_id);
CREATE INDEX IF NOT EXISTS oauth_uid ON oauth(model,uid);`);
const key = createHash('sha256').update(process.env.OAUTH_COOKIE_SECRET || '').digest();
function encrypt(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value),'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
}
function decode(row) {
  if (!row || (row.expires && row.expires <= Math.floor(Date.now()/1000))) return undefined;
  const bytes = Buffer.from(row.payload,'base64');
  const decipher = createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));
  decipher.setAuthTag(bytes.subarray(12,28));
  const value = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)),decipher.final()]).toString());
  if (row.consumed) value.consumed = row.consumed;
  return value;
}
export class OAuthStore {
  constructor(model) { this.model = model; }
  async upsert(id, payload, expiresIn) {
    const expires = expiresIn ? Math.floor(Date.now()/1000)+expiresIn : null;
    db.prepare('INSERT OR REPLACE INTO oauth (model,id,payload,grant_id,uid,user_code,expires,consumed) VALUES (?,?,?,?,?,?,?,?)').run(this.model,id,encrypt(payload),payload.grantId || null,payload.uid || null,payload.userCode || null,expires,payload.consumed || null);
    db.prepare('DELETE FROM oauth WHERE expires IS NOT NULL AND expires < ?').run(Math.floor(Date.now()/1000));
  }
  async find(id) { return decode(db.prepare('SELECT * FROM oauth WHERE model=? AND id=?').get(this.model,id)); }
  async findByUid(uid) { return decode(db.prepare('SELECT * FROM oauth WHERE model=? AND uid=?').get(this.model,uid)); }
  async findByUserCode(code) { return decode(db.prepare('SELECT * FROM oauth WHERE model=? AND user_code=?').get(this.model,code)); }
  async consume(id) { db.prepare('UPDATE oauth SET consumed=? WHERE model=? AND id=?').run(Math.floor(Date.now()/1000),this.model,id); }
  async destroy(id) { db.prepare('DELETE FROM oauth WHERE model=? AND id=?').run(this.model,id); }
  async revokeByGrantId(grantId) { db.prepare('DELETE FROM oauth WHERE grant_id=?').run(grantId); }
}
