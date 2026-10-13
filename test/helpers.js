import http from 'node:http';

/** Local test site. Routes set various cookies; /redirect chains through hops. */
export function startServer() {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const cookieHdr = req.headers.cookie || '';
    switch (u.pathname) {
      case '/':
        res.setHeader('Set-Cookie', ['theme=dark; Path=/; SameSite=Lax']);
        return res.end('home');
      case '/login':
        res.setHeader('Set-Cookie', ['sessionid=abc; Path=/', 'csrftoken=xyz; Path=/; SameSite=Strict']);
        return res.end('login');
      case '/redirect':
        res.statusCode = 302; res.setHeader('Location', '/redirect2');
        res.setHeader('Set-Cookie', ['hop1=1; Path=/; SameSite=Lax']);
        return res.end();
      case '/redirect2':
        res.statusCode = 301; res.setHeader('Location', `/final?jar=${encodeURIComponent(cookieHdr)}`);
        res.setHeader('Set-Cookie', ['auth_token=t; HttpOnly; SameSite=Lax; Path=/']);
        return res.end();
      case '/final':
        res.setHeader('Set-Cookie', [`jarseen=${u.searchParams.get('jar').includes('hop1=1') ? 'yes' : 'no'}; SameSite=Lax`]);
        return res.end('final');
      case '/loop':
        res.statusCode = 302; res.setHeader('Location', '/loop'); return res.end();
      case '/account':
        if (req.headers.authorization !== 'Bearer s3cret' && !cookieHdr.includes('sid=good')) { res.statusCode = 401; return res.end(); }
        res.setHeader('Set-Cookie', ['user_email=alice%40example.com; Path=/; SameSite=Lax', 'remember_me=1; Max-Age=31536000; HttpOnly; SameSite=Lax']);
        return res.end('account');
      case '/dupes':
        res.setHeader('Set-Cookie', ['a=1; SameSite=Lax', 'a=2; SameSite=Lax']);
        return res.end();
      case '/big':
        res.setHeader('Set-Cookie', [`big=${'x'.repeat(5000)}; SameSite=Lax`]);
        return res.end();
      case '/clean':
        return res.end('nothing');
      default:
        res.statusCode = 404; return res.end();
    }
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}` })));
}
