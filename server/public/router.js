const router = {
  go(path){ history.pushState({},'',path); router.render(); },
  match(){
    const p = location.pathname;
    if(p === '/' ) return {name:'home'};
    if(p.startsWith('/watch/')) return {name:'watch', id: p.split('/')[2]};
    if(p.startsWith('/channel/')) return {name:'channel', id: p.split('/')[2]};
    if(p === '/playlists') return {name:'playlists'};
    if(p === '/settings') return {name:'settings'};
    return {name:'home'};
  },
  async render(){
    const m = router.match();
    if(m.name==='home') return renderHome();
    if(m.name==='watch') return renderWatch(m.id);
    if(m.name==='channel') return renderChannel(m.id);
    if(m.name==='playlists') return renderPlaylists();
    if(m.name==='settings') return renderSettings();
  }
};
window.addEventListener('popstate', ()=>router.render());
