const { query } = require('../db');

function key(parts){ return parts.filter(Boolean).join(':').slice(0,200); }

async function hit(bucketKey, limit, windowSec){
  const now = new Date();
  const windowStart = new Date(Math.floor(now.getTime()/(windowSec*1000))*windowSec*1000);
  const r = await query(\
    INSERT INTO rate_limits(key, window_start, count)
    VALUES (,,1)
    ON CONFLICT(key) DO UPDATE SET
      window_start = CASE WHEN rate_limits.window_start= THEN rate_limits.window_start ELSE  END,
      count = CASE WHEN rate_limits.window_start= THEN rate_limits.count+1 ELSE 1 END
    RETURNING count
  \, [bucketKey, windowStart]);
  const count = r.rows[0].count;
  return { allowed: count <= limit, remaining: Math.max(0, limit-count) };
}

function rateLimit({name, limit, windowSec, keyFn}){
  return async (req,res,next)=>{
    try{
      const bucketKey = key([name, keyFn(req)]);
      const out = await hit(bucketKey, limit, windowSec);
      res.setHeader('X-RateLimit-Limit', String(limit));
      res.setHeader('X-RateLimit-Remaining', String(out.remaining));
      if(!out.allowed) return res.status(429).json({error:'Too many requests'});
      next();
    }catch(e){
      next(); // fail open
    }
  };
}

module.exports = { rateLimit };
