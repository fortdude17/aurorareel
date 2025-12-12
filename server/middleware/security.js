const helmet = require('helmet');

function security(app){
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'img-src': [\"'self'\", 'data:', 'blob:'],
        'media-src': [\"'self'\", 'blob:'],
        'connect-src': [\"'self'\"],
        'script-src': [\"'self'\"],
        'style-src': [\"'self'\", \"'unsafe-inline'\"]
      }
    }
  }));
  app.use((req,res,next)=>{
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
    next();
  });
}
module.exports = { security };
