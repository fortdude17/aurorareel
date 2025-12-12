function requireAuth(req,res,next){
  if(!req.session || !req.session.user) return res.status(401).json({error:'Unauthorized'});
  next();
}
function optionalAuth(req,_res,next){
  req.user = req.session?.user || null;
  next();
}
module.exports = { requireAuth, optionalAuth };
