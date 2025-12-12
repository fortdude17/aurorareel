async function api(path, opts={}){
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(opts.headers||{}) },
    ...opts
  });
  const text = await res.text();
  let data = null;
  try{ data = text ? JSON.parse(text) : null; }catch{ data = { raw: text }; }
  if(!res.ok) throw new Error(data?.error || 'Request failed');
  return data;
}

const API = {
  me: () => api('/api/auth/me'),
  signup: (b)=> api('/api/auth/signup',{method:'POST',body:JSON.stringify(b)}),
  login: (b)=> api('/api/auth/login',{method:'POST',body:JSON.stringify(b)}),
  logout: ()=> api('/api/auth/logout',{method:'POST'}),
  changePassword: (b)=> api('/api/auth/change-password',{method:'POST',body:JSON.stringify(b)}),

  feed: (tab, limit, offset, q) => {
    const u = new URL('/api/videos', location.origin);
    u.searchParams.set('tab', tab);
    u.searchParams.set('limit', limit);
    u.searchParams.set('offset', offset);
    if(q) u.searchParams.set('q', q);
    return api(u.pathname + u.search);
  },
  video: (id)=> api('/api/videos/'+id),
  likeVideo: (id)=> api('/api/videos/'+id+'/like',{method:'POST'}),
  viewVideo: (id)=> api('/api/videos/'+id+'/view',{method:'POST'}),
  notInterested: (id)=> api('/api/videos/'+id+'/not-interested',{method:'POST'}),

  impression: (body)=> api('/api/events/impression',{method:'POST',body:JSON.stringify(body)}),
  click: (body)=> api('/api/events/click',{method:'POST',body:JSON.stringify(body)}),
  watchtime: (body)=> api('/api/events/watchtime',{method:'POST',body:JSON.stringify(body)}),
  satisfaction: (body)=> api('/api/events/satisfaction',{method:'POST',body:JSON.stringify(body)}),

  creator: (id)=> api('/api/creators/'+id),
  follow: (id)=> api('/api/creators/'+id+'/follow',{method:'POST'}),

  comments: (vid)=> api('/api/videos/'+vid+'/comments'),
  addComment: (vid, body)=> api('/api/videos/'+vid+'/comments',{method:'POST',body:JSON.stringify({body})}),
  delComment: (id)=> api('/api/comments/'+id,{method:'DELETE'}),
  likeComment: (id)=> api('/api/comments/'+id+'/like',{method:'POST'}),

  playlists: ()=> api('/api/playlists'),
  createPlaylist: (b)=> api('/api/playlists',{method:'POST',body:JSON.stringify(b)}),
  deletePlaylist: (id)=> api('/api/playlists/'+id,{method:'DELETE'}),
  addToPlaylist: (id, videoId)=> api('/api/playlists/'+id+'/items',{method:'POST',body:JSON.stringify({videoId})}),
  removePlaylistItem: (id, itemId)=> api('/api/playlists/'+id+'/items/'+itemId,{method:'DELETE'}),
  reorderPlaylist: (id, order)=> api('/api/playlists/'+id+'/reorder',{method:'POST',body:JSON.stringify({order})}),

  notifications: ()=> api('/api/notifications'),
  markRead: (ids)=> api('/api/notifications/mark-read',{method:'POST',body:JSON.stringify({ids})})
};
