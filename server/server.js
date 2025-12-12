require('dotenv').config();

const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const pgSession = require('connect-pg-simple')(session);

const { pool, query, tx } = require('./db');
const { security } = require('./middleware/security');
const { requireAuth, optionalAuth } = require('./middleware/auth');
const { rateLimit } = require('./middleware/rateLimit');

const app = express();

const TRUST_PROXY = String(process.env.TRUST_PROXY || '0') === '1';
if (TRUST_PROXY) app.set('trust proxy', 1);

security(app);
app.use(express.json({ limit: process.env.JSON_LIMIT || '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  name: 'aurora.sid',
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
}));

app.use((req,_res,next)=>{
  if(!req.session.anonId) req.session.anonId = uuidv4();
  next();
});

app.use(express.static(path.join(__dirname,'public')));

const UPLOADS = path.join(__dirname,'uploads');
const VIDEOS = path.join(UPLOADS,'videos');
const THUMBS = path.join(UPLOADS,'thumbs');
for(const d of [UPLOADS, VIDEOS, THUMBS]) if(!fs.existsSync(d)) fs.mkdirSync(d,{recursive:true});

app.use('/uploads', express.static(UPLOADS, {
  setHeaders(res){ res.setHeader('Accept-Ranges','bytes'); }
}));

function safeUnlink(p){ try{ if(p) fs.unlinkSync(p); }catch{} }
function clampInt(x,min,max,def){ const n = parseInt(x,10); if(!Number.isFinite(n)) return def; return Math.max(min, Math.min(max,n)); }
function parseTags(s){
  if(!s) return [];
  return String(s).split(',').map(x=>x.trim().toLowerCase()).filter(Boolean).slice(0,12);
}
function validateHandle(h){
  h = String(h||'').trim().toLowerCase();
  if(!/^[a-z0-9_]{3,20}$/.test(h)) return null;
  return h;
}
function publicUser(u){
  return { id:u.id, email:u.email, displayName:u.display_name, handle:u.handle, bio:u.bio, avatarUrl:u.avatar_url, createdAt:u.created_at };
}

const allowedVideo = new Set(['video/mp4','video/webm','video/quicktime']);
const allowedThumb = new Set(['image/png','image/jpeg','image/webp']);

const upload = multer({
  storage: multer.diskStorage({
    destination(_req,file,cb){
      if(file.fieldname==='video') return cb(null, VIDEOS);
      if(file.fieldname==='thumbnail') return cb(null, THUMBS);
      cb(new Error('Unexpected field'));
    },
    filename(_req,file,cb){
      const ext = path.extname(file.originalname||'').slice(0,10);
      cb(null, Date.now() + '_' + uuidv4() + ext);
    }
  }),
  limits: { files: 2, fileSize: 100 * 1024 * 1024 },
  fileFilter(_req,file,cb){
    if(file.fieldname==='video'){
      if(!allowedVideo.has(file.mimetype)) return cb(new Error('Invalid video type'));
      return cb(null,true);
    }
    if(file.fieldname==='thumbnail'){
      if(!allowedThumb.has(file.mimetype)) return cb(new Error('Invalid thumbnail type'));
      return cb(null,true);
    }
    cb(new Error('Unexpected field'));
  }
});

const keyByUserOrIp = (req)=>{
  const uid = req.session?.user?.id;
  const ip = req.ip || req.headers['x-forwarded-for'] || 'ip';
  return uid ? ('u:' + uid) : ('ip:' + ip);
};
const limitLogin = rateLimit({ name:'login', limit:10, windowSec:600, keyFn:keyByUserOrIp });
const limitComments = rateLimit({ name:'comment', limit:12, windowSec:300, keyFn:keyByUserOrIp });
const limitUploadsGlobal = rateLimit({ name:'upload', limit:30, windowSec:3600, keyFn:keyByUserOrIp });
const limitUploadsUser = rateLimit({ name:'upload_user', limit:5, windowSec:3600, keyFn:(req)=>'u:'+req.session.user.id });

app.get('/api/health', (_req,res)=>res.json({ok:true}));

// ---------- AUTH ----------
app.post('/api/auth/signup', async (req,res)=>{
  try{
    const { email, password, displayName, handle } = req.body || {};
    const em = String(email||'').trim().toLowerCase();
    const pw = String(password||'');
    const dn = String(displayName||'').trim();
    const hd = validateHandle(handle);

    if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(em)) return res.status(400).json({error:'Invalid email'});
    if(pw.length < 8) return res.status(400).json({error:'Password must be 8+ chars'});
    if(!dn || dn.length<2 || dn.length>40) return res.status(400).json({error:'Display name must be 2-40 chars'});
    if(!hd) return res.status(400).json({error:'Handle must be 3-20: a-z 0-9 _'});

    const hash = await bcrypt.hash(pw,12);
    const r = await query(
      'INSERT INTO users(email,password_hash,display_name,handle) VALUES(,,,) RETURNING *',
      [em,hash,dn,hd]
    );
    const u = r.rows[0];
    req.session.user = { id:u.id, handle:u.handle, displayName:u.display_name };
    res.json({ user: publicUser(u) });
  }catch(e){
    if(String(e.message||'').toLowerCase().includes('duplicate')) return res.status(409).json({error:'Email or handle already used'});
    res.status(500).json({error:'Signup failed'});
  }
});

app.post('/api/auth/login', limitLogin, async (req,res)=>{
  try{
    const { email, password } = req.body || {};
    const em = String(email||'').trim().toLowerCase();
    const pw = String(password||'');
    const r = await query('SELECT * FROM users WHERE email=',[em]);
    const u = r.rows[0];
    if(!u) return res.status(401).json({error:'Invalid credentials'});
    const ok = await bcrypt.compare(pw, u.password_hash);
    if(!ok) return res.status(401).json({error:'Invalid credentials'});
    req.session.user = { id:u.id, handle:u.handle, displayName:u.display_name };
    res.json({ user: publicUser(u) });
  }catch{
    res.status(500).json({error:'Login failed'});
  }
});

app.post('/api/auth/logout', async (req,res)=>{
  req.session.destroy(()=>res.json({ok:true}));
});

app.get('/api/auth/me', optionalAuth, async (req,res)=>{
  if(!req.user) return res.json({user:null});
  const r = await query('SELECT * FROM users WHERE id=',[req.user.id]);
  res.json({ user: r.rows[0] ? publicUser(r.rows[0]) : null });
});

app.post('/api/auth/change-password', requireAuth, limitLogin, async (req,res)=>{
  try{
    const { currentPassword, newPassword } = req.body || {};
    const cur = String(currentPassword||'');
    const nw = String(newPassword||'');
    if(nw.length < 8) return res.status(400).json({error:'New password must be 8+ chars'});
    const r = await query('SELECT * FROM users WHERE id=',[req.session.user.id]);
    const u = r.rows[0];
    if(!u) return res.status(404).json({error:'Not found'});
    const ok = await bcrypt.compare(cur, u.password_hash);
    if(!ok) return res.status(401).json({error:'Current password wrong'});
    const hash = await bcrypt.hash(nw,12);
    await query('UPDATE users SET password_hash= WHERE id=',[hash,u.id]);
    res.json({ok:true});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

// ---------- EVENTS (for algorithm) ----------
app.post('/api/events/impression', optionalAuth, async (req,res)=>{
  try{
    const { videoIds, tab } = req.body || {};
    const ids = Array.isArray(videoIds) ? videoIds.slice(0,60) : [];
    if(!ids.length) return res.json({ok:true});
    const userId = req.session?.user?.id || null;
    const sessionId = req.session.anonId;
    await tx(async (c)=>{
      for(const vid of ids){
        await c.query(
          'INSERT INTO impressions(user_id,session_id,video_id,tab) VALUES(,,,)',
          [userId, sessionId, vid, String(tab||'for_you')]
        );
      }
    });
    res.json({ok:true});
  }catch{
    res.json({ok:true});
  }
});

app.post('/api/events/click', optionalAuth, async (req,res)=>{
  try{
    const { videoId, tab } = req.body || {};
    const userId = req.session?.user?.id || null;
    await query(
      'INSERT INTO engagement_events(user_id,session_id,video_id,type,meta) VALUES(,,,,)',
      [userId, req.session.anonId, videoId, 'click', { tab: String(tab||'for_you') }]
    );
    res.json({ok:true});
  }catch{
    res.json({ok:true});
  }
});

app.post('/api/events/watchtime', optionalAuth, async (req,res)=>{
  try{
    const { videoId, seconds, positionSec, durationSec, bounce } = req.body || {};
    const sec = Math.max(0, Math.min(600, Number(seconds||0)));
    const userId = req.session?.user?.id || null;

    await query(
      'INSERT INTO engagement_events(user_id,session_id,video_id,type,value_num,meta) VALUES(,,,,,)',
      [userId, req.session.anonId, videoId, 'watch_time', sec, { positionSec, durationSec, bounce: !!bounce }]
    );

    if(userId && videoId && sec>0){
      const completed = durationSec && positionSec ? (Number(positionSec) / Math.max(1,Number(durationSec)) >= 0.9) : false;
      await query(
        \
        INSERT INTO watch_history(user_id,video_id,watch_time_sec,last_position_sec,completed)
        VALUES(,,,,)
        ON CONFLICT(user_id,video_id) DO UPDATE SET
          watch_time_sec = watch_history.watch_time_sec + EXCLUDED.watch_time_sec,
          last_position_sec = GREATEST(watch_history.last_position_sec, EXCLUDED.last_position_sec),
          completed = watch_history.completed OR EXCLUDED.completed,
          updated_at = now()
        \,
        [userId, videoId, Math.floor(sec), Math.floor(Number(positionSec||0)), completed]
      );
      if(bounce){
        await query(
          'INSERT INTO engagement_events(user_id,session_id,video_id,type,value_num) VALUES(,,,,)',
          [userId, req.session.anonId, videoId, 'bounce', Math.floor(Number(positionSec||0))]
        );
      }
    }

    res.json({ok:true});
  }catch{
    res.json({ok:true});
  }
});

app.post('/api/events/satisfaction', optionalAuth, async (req,res)=>{
  try{
    const { videoId, kind, creatorId } = req.body || {};
    const userId = req.session?.user?.id || null;
    const type = ['like','follow','save','comment','unlike','unfollow'].includes(String(kind)) ? String(kind) : 'save';
    await query(
      'INSERT INTO engagement_events(user_id,session_id,video_id,type,meta) VALUES(,,,,)',
      [userId, req.session.anonId, videoId || null, type, { creatorId: creatorId || null }]
    );
    res.json({ok:true});
  }catch{
    res.json({ok:true});
  }
});

// ---------- VIDEO upload ----------
app.post('/api/videos',
  requireAuth,
  limitUploadsGlobal,
  limitUploadsUser,
  (req,res,next)=>{
    upload.fields([{name:'video',maxCount:1},{name:'thumbnail',maxCount:1}])(req,res,(err)=>{
      if(err) return res.status(400).json({error: err.message || 'Upload failed'});
      next();
    });
  },
  async (req,res)=>{
    const files = req.files || {};
    const vfile = (files.video||[])[0];
    const tfile = (files.thumbnail||[])[0];

    try{
      if(!vfile) return res.status(400).json({error:'Missing video file'});
      if(tfile && tfile.size > 10*1024*1024){ safeUnlink(tfile.path); safeUnlink(vfile.path); return res.status(400).json({error:'Thumbnail too large (10MB max)'}); }

      const title = String(req.body?.title||'').trim();
      if(title.length < 2 || title.length > 120){ safeUnlink(vfile.path); safeUnlink(tfile?.path); return res.status(400).json({error:'Title must be 2-120 chars'}); }

      const desc = String(req.body?.description||'').slice(0,5000);
      const tags = parseTags(req.body?.tags);
      const vis = ['public','unlisted','private'].includes(String(req.body?.visibility)) ? String(req.body?.visibility) : 'public';
      const dur = req.body?.durationSec ? clampInt(req.body.durationSec,1,86400,null) : null;

      const relVideo = path.relative(__dirname, vfile.path).replaceAll('\\\\','/');
      const relThumb = tfile ? path.relative(__dirname, tfile.path).replaceAll('\\\\','/') : null;

      const r = await query(
        \
        INSERT INTO videos(owner_id,title,description,tags,visibility,video_path,mime_type,size_bytes,duration_sec,thumbnail_path,thumb_mime)
        VALUES(,,,,,,,,,,)
        RETURNING *
        \,
        [req.session.user.id, title, desc, tags, vis, relVideo, vfile.mimetype, vfile.size, dur, relThumb, tfile? tfile.mimetype : null]
      );

      // Notify followers
      const vid = r.rows[0];
      const followers = await query('SELECT subscriber_id FROM follows WHERE creator_id=',[req.session.user.id]);
      for(const f of followers.rows){
        await query('INSERT INTO notifications(user_id,type,payload) VALUES(,,)', [f.subscriber_id, 'new_upload', { videoId: vid.id, title: vid.title, creatorId: req.session.user.id }]);
      }

      res.json({ video: vid });
    }catch(e){
      safeUnlink(vfile?.path);
      safeUnlink(tfile?.path);
      res.status(500).json({error:'Failed to save video'});
    }
  }
);

// ---------- FEEDS (For You/Fresh/Following) ----------
function smoothedRate(num, den, priorNum, priorDen){ return (num+priorNum)/(den+priorDen); }
function sigmoid(x){ return 1/(1+Math.exp(-x)); }
function timeDecayHours(ageH, halfLifeH){ return Math.pow(0.5, ageH/halfLifeH); }

async function userProfile(userId){
  const tags = await query(\
    SELECT unnest(v.tags) AS tag, COUNT(*)::int AS c
    FROM watch_history wh JOIN videos v ON v.id=wh.video_id
    WHERE wh.user_id=
    GROUP BY tag ORDER BY c DESC LIMIT 20\, [userId]);
  const creators = await query(\
    SELECT v.owner_id, COUNT(*)::int AS c
    FROM watch_history wh JOIN videos v ON v.id=wh.video_id
    WHERE wh.user_id=
    GROUP BY v.owner_id ORDER BY c DESC LIMIT 20\, [userId]);
  const tmap = new Map(tags.rows.map(r=>[String(r.tag), Number(r.c)]));
  const cmap = new Map(creators.rows.map(r=>[String(r.owner_id), Number(r.c)]));
  return { tmap, cmap };
}
function personalBoost(video, prof){
  if(!prof) return 0;
  let s = 0;
  for(const t of (video.tags||[])) s += (prof.tmap.get(String(t))||0);
  s += (prof.cmap.get(String(video.owner_id))||0) * 2;
  return sigmoid(s/8)-0.5;
}

async function statsMap(videoIds, userId){
  if(!videoIds.length) return new Map();
  const r = await query(\
    WITH imp AS (
      SELECT video_id, COUNT(*)::int AS impressions
      FROM impressions
      WHERE video_id = ANY(::uuid[]) AND shown_at > now() - interval '14 days'
      GROUP BY video_id
    ),
    clk AS (
      SELECT video_id, COUNT(*)::int AS clicks
      FROM engagement_events
      WHERE video_id = ANY(::uuid[]) AND type='click' AND created_at > now() - interval '14 days'
      GROUP BY video_id
    ),
    wt AS (
      SELECT video_id, COALESCE(SUM(value_num),0)::double precision AS watch_seconds
      FROM engagement_events
      WHERE video_id = ANY(::uuid[]) AND type='watch_time' AND created_at > now() - interval '14 days'
      GROUP BY video_id
    ),
    sat AS (
      SELECT video_id,
        COUNT(*) FILTER (WHERE type IN ('like','follow','save','comment'))::int AS sat_events,
        COUNT(*) FILTER (WHERE type IN ('bounce','not_interested','skip'))::int AS neg_events
      FROM engagement_events
      WHERE video_id = ANY(::uuid[]) AND created_at > now() - interval '14 days'
      GROUP BY video_id
    ),
    uimp AS (
      SELECT video_id, COUNT(*)::int AS user_impressions
      FROM impressions
      WHERE user_id= AND video_id = ANY(::uuid[]) AND shown_at > now() - interval '14 days'
      GROUP BY video_id
    ),
    uwh AS (
      SELECT video_id, 1::int AS watched_recently
      FROM watch_history
      WHERE user_id= AND video_id = ANY(::uuid[]) AND updated_at > now() - interval '30 days'
    )
    SELECT v.id AS video_id,
      COALESCE(imp.impressions,0) AS impressions,
      COALESCE(clk.clicks,0) AS clicks,
      COALESCE(wt.watch_seconds,0) AS watch_seconds,
      COALESCE(sat.sat_events,0) AS sat_events,
      COALESCE(sat.neg_events,0) AS neg_events,
      COALESCE(uimp.user_impressions,0) AS user_impressions,
      COALESCE(uwh.watched_recently,0) AS watched_recently
    FROM videos v
    LEFT JOIN imp ON imp.video_id=v.id
    LEFT JOIN clk ON clk.video_id=v.id
    LEFT JOIN wt ON wt.video_id=v.id
    LEFT JOIN sat ON sat.video_id=v.id
    LEFT JOIN uimp ON uimp.video_id=v.id
    LEFT JOIN uwh ON uwh.video_id=v.id
    WHERE v.id = ANY(::uuid[])
  \, [videoIds, userId || null]);

  const m = new Map();
  for(const row of r.rows) m.set(String(row.video_id), row);
  return m;
}

function score(video, st, prof){
  const impressions = Number(st?.impressions||0);
  const clicks = Number(st?.clicks||0);
  const ctr = smoothedRate(clicks, impressions, 2, 50); // prior

  const watchSeconds = Number(st?.watch_seconds||0);
  const avgWatch = watchSeconds / Math.max(1, clicks); // watch per click (rough)
  const duration = Math.max(10, Number(video.duration_sec||60));
  const watchScore = sigmoid((avgWatch / Math.max(20,duration))*3 - 1);

  const satEvents = Number(st?.sat_events||0);
  const satRate = smoothedRate(satEvents, Math.max(1, Number(video.views||0)), 1, 200);

  const negRate = smoothedRate(Number(st?.neg_events||0), Math.max(1, impressions), 1, 150);

  const ageH = (Date.now() - new Date(video.created_at).getTime()) / 36e5;
  const fresh = timeDecayHours(ageH, 48);

  const pb = personalBoost(video, prof);

  const watchedPenalty = Number(st?.watched_recently||0) ? 0.25 : 0;
  const impressedPenalty = Math.min(1, Number(st?.user_impressions||0)/6) * 0.15;

  return (ctr*0.38) + (watchScore*0.36) + (satRate*0.20) + (fresh*0.10) + (pb*0.18) - watchedPenalty - impressedPenalty - (negRate*0.25);
}

function diversify(list){
  const out=[];
  let last=null, streak=0;
  for(const v of list){
    const c = String(v.owner_id);
    if(c===last) streak++; else { last=c; streak=1; }
    if(streak>2){
      const altIdx = list.findIndex(x=>String(x.owner_id)!==c && !out.includes(x));
      if(altIdx!==-1){
        const alt = list[altIdx];
        out.push(alt);
        list.splice(altIdx,1);
        list.push(v);
        last = String(alt.owner_id);
        streak = 1;
        continue;
      }
    }
    out.push(v);
  }
  return out;
}

app.get('/api/videos', optionalAuth, async (req,res)=>{
  try{
    const tab = ['for_you','fresh','following'].includes(String(req.query.tab)) ? String(req.query.tab) : 'for_you';
    const limit = clampInt(req.query.limit, 1, 30, 18);
    const offset = clampInt(req.query.offset, 0, 10000, 0);
    const q = String(req.query.q||'').trim().toLowerCase();

    const userId = req.session?.user?.id || null;

    if(tab==='following'){
      if(!userId) return res.json({tab, limit, offset, videos:[]});
      const r = await query(\
        SELECT v.*, u.display_name, u.handle
        FROM videos v
        JOIN users u ON u.id=v.owner_id
        JOIN follows f ON f.creator_id=v.owner_id
        WHERE v.visibility='public' AND f.subscriber_id=
        AND (='' OR lower(v.title) LIKE '%'||||'%')
        ORDER BY v.created_at DESC
        LIMIT  OFFSET 
      \, [userId, q, limit, offset]);
      return res.json({ tab, limit, offset, videos: r.rows.map(rowToCard) });
    }

    if(tab==='fresh'){
      const r = await query(\
        SELECT v.*, u.display_name, u.handle
        FROM videos v JOIN users u ON u.id=v.owner_id
        WHERE v.visibility='public'
        AND (='' OR lower(v.title) LIKE '%'||||'%')
        ORDER BY v.created_at DESC
        LIMIT  OFFSET 
      \, [q, limit, offset]);
      return res.json({ tab, limit, offset, videos: r.rows.map(rowToCard) });
    }

    // for_you: pool then rank
    const poolSize = Math.max(60, limit*6);
    const poolR = await query(\
      SELECT v.*, u.display_name, u.handle
      FROM videos v JOIN users u ON u.id=v.owner_id
      WHERE v.visibility='public'
      AND (='' OR lower(v.title) LIKE '%'||||'%')
      ORDER BY v.created_at DESC
      LIMIT 
    \, [q, poolSize]);

    const list = poolR.rows;
    const ids = list.map(v=>v.id);
    const stMap = await statsMap(ids, userId);
    const prof = userId ? await userProfile(userId) : null;

    const scored = list.map(v=>({v, s: score(v, stMap.get(String(v.id)), prof)}))
      .sort((a,b)=>b.s-a.s);

    const top = scored.slice(0, limit*4).map(x=>x.v);

    const exploreRatio = 0.20;
    const exploreCount = Math.max(3, Math.round(limit*exploreRatio));
    const exploration = top
      .filter(v => (stMap.get(String(v.id))?.user_impressions || 0) === 0)
      .slice(0, exploreCount);

    const exploited = top.filter(v=>!exploration.includes(v)).slice(0, limit - exploration.length);

    const mixed = [];
    let ei=0, xi=0;
    while(mixed.length < limit && (ei<exploration.length || xi<exploited.length)){
      if(mixed.length%5===0 && ei<exploration.length) mixed.push(exploration[ei++]);
      else if(xi<exploited.length) mixed.push(exploited[xi++]);
      else if(ei<exploration.length) mixed.push(exploration[ei++]);
    }

    const finalList = diversify(mixed).map(rowToCard);
    res.json({ tab, limit, offset, videos: finalList });
  }catch(e){
    res.status(500).json({error:'Feed failed'});
  }
});

function rowToCard(v){
  return {
    id: v.id,
    title: v.title,
    description: v.description,
    tags: v.tags || [],
    visibility: v.visibility,
    views: Number(v.views||0),
    likeCount: Number(v.like_count||0),
    commentCount: Number(v.comment_count||0),
    durationSec: v.duration_sec,
    createdAt: v.created_at,
    owner: { id: v.owner_id, displayName: v.display_name, handle: v.handle },
    thumbnailUrl: v.thumbnail_path ? ('/' + v.thumbnail_path) : null
  };
}

app.get('/api/videos/:id', optionalAuth, async (req,res)=>{
  try{
    const r = await query(\
      SELECT v.*, u.display_name, u.handle
      FROM videos v JOIN users u ON u.id=v.owner_id
      WHERE v.id=
    \, [req.params.id]);
    const v = r.rows[0];
    if(!v) return res.status(404).json({error:'Not found'});
    const me = req.session?.user?.id;

    if(v.visibility==='private' && String(v.owner_id)!==String(me)) return res.status(403).json({error:'Private'});

    const subs = await query('SELECT COUNT(*)::bigint AS c FROM follows WHERE creator_id=',[v.owner_id]).then(x=>x.rows[0].c);
    const liked = me ? (await query('SELECT 1 FROM video_likes WHERE user_id= AND video_id=',[me,v.id])).rowCount>0 : false;

    res.json({ video: {
      id: v.id,
      title: v.title,
      description: v.description,
      tags: v.tags||[],
      visibility: v.visibility,
      views: Number(v.views||0),
      likeCount: Number(v.like_count||0),
      commentCount: Number(v.comment_count||0),
      durationSec: v.duration_sec,
      createdAt: v.created_at,
      updatedAt: v.updated_at,
      owner: { id: v.owner_id, displayName: v.display_name, handle: v.handle, subscriberCount: Number(subs||0) },
      liked,
      thumbnailUrl: v.thumbnail_path ? ('/' + v.thumbnail_path) : null,
      streamUrl: '/api/videos/' + v.id + '/stream'
    }});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

// Range streaming
app.get('/api/videos/:id/stream', optionalAuth, async (req,res)=>{
  try{
    const r = await query('SELECT * FROM videos WHERE id=',[req.params.id]);
    const v = r.rows[0];
    if(!v) return res.status(404).end();

    const fullPath = path.join(__dirname, v.video_path);
    const stat = fs.statSync(fullPath);
    const size = stat.size;
    const range = req.headers.range;

    res.setHeader('Content-Type', v.mime_type);
    res.setHeader('Accept-Ranges', 'bytes');

    if(!range){
      res.setHeader('Content-Length', size);
      fs.createReadStream(fullPath).pipe(res);
      return;
    }

    const m = /bytes=(\\d+)-(\\d+)?/.exec(range);
    if(!m) return res.status(416).end();

    const start = Math.max(0, parseInt(m[1],10));
    const end = m[2] ? Math.min(size-1, parseInt(m[2],10)) : Math.min(size-1, start + 1024*1024*2);
    if(start >= size) return res.status(416).end();

    res.status(206);
    res.setHeader('Content-Range', 'bytes ' + start + '-' + end + '/' + size);
    res.setHeader('Content-Length', (end-start+1));

    fs.createReadStream(fullPath, { start, end }).pipe(res);
  }catch{
    res.status(500).end();
  }
});

app.post('/api/videos/:id/view', optionalAuth, async (req,res)=>{
  try{
    const id = req.params.id;
    await query('UPDATE videos SET views=views+1 WHERE id=',[id]);
    res.json({ok:true});
  }catch{
    res.json({ok:true});
  }
});

app.post('/api/videos/:id/like', requireAuth, async (req,res)=>{
  try{
    const userId = req.session.user.id;
    const vid = req.params.id;

    const exists = await query('SELECT 1 FROM video_likes WHERE user_id= AND video_id=',[userId,vid]);
    let liked;
    if(exists.rowCount){
      await tx(async (c)=>{
        await c.query('DELETE FROM video_likes WHERE user_id= AND video_id=',[userId,vid]);
        await c.query('UPDATE videos SET like_count=GREATEST(0, like_count-1) WHERE id=',[vid]);
      });
      liked = false;
      await query('INSERT INTO engagement_events(user_id,session_id,video_id,type) VALUES(,,,)', [userId, req.session.anonId, vid, 'unlike']);
    }else{
      await tx(async (c)=>{
        await c.query('INSERT INTO video_likes(user_id,video_id) VALUES(,)',[userId,vid]);
        await c.query('UPDATE videos SET like_count=like_count+1 WHERE id=',[vid]);
      });
      liked = true;
      await query('INSERT INTO engagement_events(user_id,session_id,video_id,type) VALUES(,,,)', [userId, req.session.anonId, vid, 'like']);
    }

    const likeCount = await query('SELECT like_count FROM videos WHERE id=',[vid]).then(x=>Number(x.rows[0]?.like_count||0));
    res.json({ liked, likeCount });
  }catch(e){
    res.status(500).json({error:'Failed'});
  }
});

app.post('/api/videos/:id/not-interested', requireAuth, async (req,res)=>{
  try{
    const userId = req.session.user.id;
    const vid = req.params.id;
    await query('INSERT INTO engagement_events(user_id,session_id,video_id,type) VALUES(,,,)', [userId, req.session.anonId, vid, 'not_interested']);
    res.json({ok:true});
  }catch{
    res.json({ok:true});
  }
});

// PATCH/DELETE basic (owner only)
app.patch('/api/videos/:id', requireAuth, async (req,res)=>{
  try{
    const vid = req.params.id;
    const r = await query('SELECT * FROM videos WHERE id=',[vid]);
    const v = r.rows[0];
    if(!v) return res.status(404).json({error:'Not found'});
    if(String(v.owner_id)!==String(req.session.user.id)) return res.status(403).json({error:'Forbidden'});

    const title = req.body?.title ? String(req.body.title).trim().slice(0,120) : v.title;
    const description = req.body?.description ? String(req.body.description).slice(0,5000) : v.description;
    const tags = req.body?.tags ? parseTags(req.body.tags) : v.tags;
    const visibility = ['public','unlisted','private'].includes(String(req.body?.visibility)) ? String(req.body.visibility) : v.visibility;

    const up = await query(\
      UPDATE videos SET title=, description=, tags=, visibility=, updated_at=now()
      WHERE id= RETURNING *
    \, [title,description,tags,visibility,vid]);

    res.json({ video: up.rows[0] });
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.delete('/api/videos/:id', requireAuth, async (req,res)=>{
  try{
    const vid = req.params.id;
    const r = await query('SELECT * FROM videos WHERE id=',[vid]);
    const v = r.rows[0];
    if(!v) return res.status(404).json({error:'Not found'});
    if(String(v.owner_id)!==String(req.session.user.id)) return res.status(403).json({error:'Forbidden'});

    await query('DELETE FROM videos WHERE id=',[vid]);
    safeUnlink(path.join(__dirname, v.video_path));
    if(v.thumbnail_path) safeUnlink(path.join(__dirname, v.thumbnail_path));
    res.json({ok:true});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

// ---------- Creators / Subs ----------
app.get('/api/creators/:id', optionalAuth, async (req,res)=>{
  try{
    const id = req.params.id;
    const u = await query('SELECT id, display_name, handle, bio, avatar_url FROM users WHERE id=',[id]).then(x=>x.rows[0]);
    if(!u) return res.status(404).json({error:'Not found'});

    const subs = await query('SELECT COUNT(*)::bigint AS c FROM follows WHERE creator_id=',[id]).then(x=>Number(x.rows[0].c||0));
    const following = req.session?.user?.id
      ? (await query('SELECT 1 FROM follows WHERE subscriber_id= AND creator_id=',[req.session.user.id,id])).rowCount>0
      : false;

    const vids = await query(\
      SELECT v.*, u.display_name, u.handle
      FROM videos v JOIN users u ON u.id=v.owner_id
      WHERE v.owner_id= AND v.visibility IN ('public','unlisted')
      ORDER BY v.created_at DESC
      LIMIT 60
    \, [id]);

    res.json({ creator: {
      id: u.id,
      displayName: u.display_name,
      handle: u.handle,
      bio: u.bio,
      avatarUrl: u.avatar_url,
      subscriberCount: subs,
      following,
      videos: vids.rows.map(rowToCard)
    }});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.post('/api/creators/:id/follow', requireAuth, async (req,res)=>{
  try{
    const me = req.session.user.id;
    const creator = req.params.id;
    if(String(me)===String(creator)) return res.status(400).json({error:'Cannot follow yourself'});

    const exists = await query('SELECT 1 FROM follows WHERE subscriber_id= AND creator_id=',[me,creator]);
    let following;
    if(exists.rowCount){
      await query('DELETE FROM follows WHERE subscriber_id= AND creator_id=',[me,creator]);
      following = false;
      await query('INSERT INTO engagement_events(user_id,session_id,video_id,type,meta) VALUES(,,,,)', [me, req.session.anonId, null, 'unfollow', { creatorId: creator }]);
    }else{
      await query('INSERT INTO follows(subscriber_id,creator_id) VALUES(,)',[me,creator]);
      following = true;
      await query('INSERT INTO engagement_events(user_id,session_id,video_id,type,meta) VALUES(,,,,)', [me, req.session.anonId, null, 'follow', { creatorId: creator }]);
      await query('INSERT INTO notifications(user_id,type,payload) VALUES(,,)', [creator, 'new_follower', { followerId: me }]);
    }

    const count = await query('SELECT COUNT(*)::bigint AS c FROM follows WHERE creator_id=',[creator]).then(x=>Number(x.rows[0].c||0));
    res.json({ following, subscriberCount: count });
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

// ---------- Comments ----------
app.get('/api/videos/:id/comments', optionalAuth, async (req,res)=>{
  try{
    const vid = req.params.id;
    const r = await query(\
      SELECT c.*, u.display_name, u.handle
      FROM comments c JOIN users u ON u.id=c.user_id
      WHERE c.video_id= AND c.deleted_at IS NULL
      ORDER BY c.created_at DESC
      LIMIT 200
    \, [vid]);

    res.json({ comments: r.rows.map(x=>({
      id:x.id,
      body:x.body,
      likeCount:Number(x.like_count||0),
      createdAt:x.created_at,
      user:{ id:x.user_id, displayName:x.display_name, handle:x.handle }
    }))});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.post('/api/videos/:id/comments', requireAuth, limitComments, async (req,res)=>{
  try{
    const vid = req.params.id;
    const body = String(req.body?.body||'').trim();
    if(body.length<1 || body.length>1500) return res.status(400).json({error:'Comment must be 1-1500 chars'});

    const out = await tx(async (c)=>{
      const ins = await c.query('INSERT INTO comments(video_id,user_id,body) VALUES(,,) RETURNING *', [vid, req.session.user.id, body]);
      await c.query('UPDATE videos SET comment_count=comment_count+1 WHERE id=', [vid]);
      return ins.rows[0];
    });

    await query('INSERT INTO engagement_events(user_id,session_id,video_id,type) VALUES(,,,)', [req.session.user.id, req.session.anonId, vid, 'comment']);

    res.json({ comment: { id: out.id } });
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.delete('/api/comments/:id', requireAuth, async (req,res)=>{
  try{
    const cid = req.params.id;
    const r = await query('SELECT * FROM comments WHERE id=',[cid]);
    const c = r.rows[0];
    if(!c) return res.status(404).json({error:'Not found'});
    if(String(c.user_id)!==String(req.session.user.id)) return res.status(403).json({error:'Forbidden'});

    await tx(async (cl)=>{
      await cl.query('UPDATE comments SET deleted_at=now() WHERE id=',[cid]);
      await cl.query('UPDATE videos SET comment_count=GREATEST(0, comment_count-1) WHERE id=',[c.video_id]);
    });

    res.json({ok:true});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.post('/api/comments/:id/like', requireAuth, async (req,res)=>{
  try{
    const userId = req.session.user.id;
    const cid = req.params.id;

    const exists = await query('SELECT 1 FROM comment_likes WHERE user_id= AND comment_id=',[userId,cid]);
    let liked;
    if(exists.rowCount){
      await tx(async (c)=>{
        await c.query('DELETE FROM comment_likes WHERE user_id= AND comment_id=',[userId,cid]);
        await c.query('UPDATE comments SET like_count=GREATEST(0, like_count-1) WHERE id=',[cid]);
      });
      liked = false;
    }else{
      await tx(async (c)=>{
        await c.query('INSERT INTO comment_likes(user_id,comment_id) VALUES(,)',[userId,cid]);
        await c.query('UPDATE comments SET like_count=like_count+1 WHERE id=',[cid]);
      });
      liked = true;
    }
    const likeCount = await query('SELECT like_count FROM comments WHERE id=',[cid]).then(x=>Number(x.rows[0]?.like_count||0));
    res.json({ liked, likeCount });
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

// ---------- Playlists ----------
app.get('/api/playlists', requireAuth, async (req,res)=>{
  try{
    const uid = req.session.user.id;
    const pls = await query('SELECT * FROM playlists WHERE owner_id= ORDER BY created_at DESC',[uid]);
    const out = [];
    for(const p of pls.rows){
      const items = await query(\
        SELECT pi.id AS item_id, v.*
        FROM playlist_items pi
        JOIN videos v ON v.id=pi.video_id
        WHERE pi.playlist_id=
        ORDER BY pi.position ASC, pi.created_at ASC
      \, [p.id]);
      out.push({
        id: p.id,
        title: p.title,
        visibility: p.visibility,
        items: items.rows.map(v=>({
          itemId: v.item_id,
          videoId: v.id,
          title: v.title,
          views: Number(v.views||0),
          thumbnailUrl: v.thumbnail_path ? ('/' + v.thumbnail_path) : null
        }))
      });
    }
    res.json({ playlists: out });
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.post('/api/playlists', requireAuth, async (req,res)=>{
  try{
    const title = String(req.body?.title||'').trim();
    if(title.length<1 || title.length>80) return res.status(400).json({error:'Title must be 1-80 chars'});
    const visibility = ['public','unlisted','private'].includes(String(req.body?.visibility)) ? String(req.body.visibility) : 'private';
    const r = await query('INSERT INTO playlists(owner_id,title,visibility) VALUES(,,) RETURNING *',[req.session.user.id,title,visibility]);
    res.json({ playlist: r.rows[0] });
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.delete('/api/playlists/:id', requireAuth, async (req,res)=>{
  try{
    const pid = req.params.id;
    const r = await query('SELECT * FROM playlists WHERE id=',[pid]);
    const p = r.rows[0];
    if(!p) return res.status(404).json({error:'Not found'});
    if(String(p.owner_id)!==String(req.session.user.id)) return res.status(403).json({error:'Forbidden'});
    await query('DELETE FROM playlists WHERE id=',[pid]);
    res.json({ok:true});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.post('/api/playlists/:id/items', requireAuth, async (req,res)=>{
  try{
    const pid = req.params.id;
    const vid = String(req.body?.videoId||'');
    const r = await query('SELECT * FROM playlists WHERE id=',[pid]);
    if(!r.rows[0]) return res.status(404).json({error:'Playlist not found'});
    if(String(r.rows[0].owner_id)!==String(req.session.user.id)) return res.status(403).json({error:'Forbidden'});

    const pos = await query('SELECT COALESCE(MAX(position),0)+1 AS p FROM playlist_items WHERE playlist_id=',[pid]).then(x=>Number(x.rows[0].p||1));
    await query('INSERT INTO playlist_items(playlist_id,video_id,position) VALUES(,,) ON CONFLICT DO NOTHING',[pid,vid,pos]);

    await query('INSERT INTO engagement_events(user_id,session_id,video_id,type) VALUES(,,,)', [req.session.user.id, req.session.anonId, vid, 'save']);

    res.json({ok:true});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.delete('/api/playlists/:id/items/:itemId', requireAuth, async (req,res)=>{
  try{
    const pid = req.params.id;
    const itemId = req.params.itemId;
    const pr = await query('SELECT * FROM playlists WHERE id=',[pid]);
    if(!pr.rows[0]) return res.status(404).json({error:'Not found'});
    if(String(pr.rows[0].owner_id)!==String(req.session.user.id)) return res.status(403).json({error:'Forbidden'});
    await query('DELETE FROM playlist_items WHERE id= AND playlist_id=',[itemId,pid]);
    res.json({ok:true});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.post('/api/playlists/:id/reorder', requireAuth, async (req,res)=>{
  try{
    const pid = req.params.id;
    const order = Array.isArray(req.body?.order) ? req.body.order : [];
    const pr = await query('SELECT * FROM playlists WHERE id=',[pid]);
    if(!pr.rows[0]) return res.status(404).json({error:'Not found'});
    if(String(pr.rows[0].owner_id)!==String(req.session.user.id)) return res.status(403).json({error:'Forbidden'});

    await tx(async (c)=>{
      for(let i=0;i<order.length;i++){
        await c.query('UPDATE playlist_items SET position= WHERE id= AND playlist_id=',[i, order[i], pid]);
      }
    });
    res.json({ok:true});
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

// ---------- Notifications ----------
app.get('/api/notifications', requireAuth, async (req,res)=>{
  try{
    const r = await query('SELECT * FROM notifications WHERE user_id= ORDER BY created_at DESC LIMIT 60',[req.session.user.id]);
    res.json({ notifications: r.rows.map(n=>({ id:n.id, type:n.type, payload:n.payload, createdAt:n.created_at, readAt:n.read_at })) });
  }catch{
    res.status(500).json({error:'Failed'});
  }
});

app.post('/api/notifications/mark-read', requireAuth, async (req,res)=>{
  try{
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.slice(0,80) : [];
    if(!ids.length) return res.json({ok:true});
    await query('UPDATE notifications SET read_at=now() WHERE user_id= AND id = ANY(::uuid[])',[req.session.user.id, ids]);
    res.json({ok:true});
  }catch{
    res.json({ok:true});
  }
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, ()=>console.log('AuroraReel on http://localhost:' + PORT));
