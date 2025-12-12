const { Pool } = require('pg');

function must(name){
  if(!process.env[name]) throw new Error('Missing env var: ' + name);
  return process.env[name];
}

const pool = new Pool({
  connectionString: must('DATABASE_URL'),
  max: 10,
  idleTimeoutMillis: 30000
});

async function query(text, params){
  return pool.query(text, params);
}

async function tx(fn){
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  }catch(e){
    await client.query('ROLLBACK');
    throw e;
  }finally{
    client.release();
  }
}

module.exports = { pool, query, tx };
