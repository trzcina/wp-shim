/**
 * WP-shim dla siechnice.com.pl (Bolt 3).
 *
 * Udaje REST API WordPressa (wp/v2 + hasła aplikacji / Basic Auth) na tyle,
 * żeby Linkhouse i WhitePress mogły się podłączyć. Każde żądanie loguje do KV,
 * wpisy i media zapisuje w KV.
 *
 * ETAP 2 (ACCEPT_PUBLISH=true + sekret SITE_MCP_TOKEN): wpis ze statusem „publish”/„future” od razu
 * staje się opublikowaną aktualnością w Bolcie (create_news przez MCP strony, kategoria BOLT_CATEGORY,
 * zdjęcie wyróżnione przez prepare_upload), platforma dostaje prawdziwy adres artykułu, a do skrzynki
 * idzie karta (link do artykułu i do panelu, gdzie można go wycofać). Późniejsze zmiany i usunięcie
 * wpisu przez platformę NIE ruszają Bolta — tylko karta w skrzynce. Szkice zostają w KV.
 *
 * Panel podglądu (wymaga ?token=ADMIN_TOKEN):
 *   /wp-json/__shim/logs            ostatnie żądania (skrót)
 *   /wp-json/__shim/logs?full=1     pełne żądania z nagłówkami i treścią
 *   /wp-json/__shim/posts           odebrane wpisy
 *   /wp-json/__shim/posts/ID?html=1 podgląd wpisu do skopiowania do Bolta
 */

const LOG_TTL = 30 * 86400;
const TAX = { categories: 'category', tags: 'post_tag' };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const isRest = url.pathname === '/wp-json' || url.pathname.startsWith('/wp-json/') || url.searchParams.has('rest_route');

    // Wszystko poza API idzie bez zmian do Bolta. Na stronie głównej dokładamy
    // nagłówek, po którym klienci WordPressa wykrywają adres API.
    if (!isRest) {
      const res = await fetch(request);
      if (request.method === 'GET' && url.pathname === '/') {
        const out = new Response(res.body, res);
        out.headers.append('Link', `<${siteOf(env, url)}/wp-json/>; rel="https://api.w.org/"`);
        return out;
      }
      return res;
    }

    try {
      return await handleApi(request, env, ctx, url);
    } catch (err) {
      console.error('shim error', err && err.stack ? err.stack : err);
      return wpError('shim_internal_error', 'Błąd wewnętrzny: ' + (err && err.message), 500);
    }
  },
};

/* ------------------------------------------------------------------ */
/* Wejście API                                                          */
/* ------------------------------------------------------------------ */

async function handleApi(request, env, ctx, url) {
  const site = siteOf(env, url);
  let route = url.pathname.startsWith('/wp-json') ? url.pathname.slice(8) : url.searchParams.get('rest_route') || '/';
  route = '/' + route.replace(/^\/+|\/+$/g, '');

  if (route === '/__shim' || route.startsWith('/__shim/')) return handleAdmin(request, env, url, site, route);

  const method = (request.headers.get('x-http-method-override') || url.searchParams.get('_method') || request.method).toUpperCase();
  const ct = request.headers.get('content-type') || '';
  const buf = ['GET', 'HEAD', 'OPTIONS'].includes(request.method) ? null : await request.arrayBuffer();
  const auth = checkAuth(request, env);
  const body = await parseBody(buf, ct);

  const c = { request, env, ctx, url, site, route, method, ct, buf, auth, file: body.file, params: { ...queryObj(url), ...body.fields } };
  const response = await routeRest(c);

  if (env.LOG_MODE !== 'auth' || auth.present) {
    ctx.waitUntil(logRequest(c, response.clone()).catch((e) => console.error('log error', e)));
  }
  return response;
}

async function routeRest(c) {
  const { route, method, auth } = c;
  let m;

  if (auth.present && !auth.ok) {
    return auth.userOk
      ? wpError('incorrect_password', 'Podane hasło aplikacji jest nieprawidłowe.', 401)
      : wpError('invalid_username', 'Nieznana nazwa użytkownika.', 401);
  }
  if (method === 'OPTIONS') return new Response(null, { status: 200, headers: { Allow: 'GET, POST, PUT, PATCH, DELETE' } });

  if (route === '/') return json(indexDoc(c));
  if (route === '/wp/v2') return json({ namespace: 'wp/v2', routes: routesDoc(c) });
  if (route === '/wp/v2/users/me') return needAuth(c) || json(userObj(c));
  if (route === '/wp/v2/users') return needAuth(c) || paginate(c, [userObj(c)]);
  if ((m = route.match(/^\/wp\/v2\/users\/(\d+)$/))) return needAuth(c) || (m[1] === '1' ? json(userObj(c)) : wpError('rest_user_invalid_id', 'Nieprawidłowy identyfikator użytkownika.', 404));
  if (route === '/wp/v2/settings') return needAuth(c) || json(settingsObj(c));
  if (route === '/wp/v2/types') return json(typesObj(c));
  if ((m = route.match(/^\/wp\/v2\/types\/([\w-]+)$/))) return typesObj(c)[m[1]] ? json(typesObj(c)[m[1]]) : wpError('rest_type_invalid', 'Nieprawidłowy typ treści.', 404);
  if (route === '/wp/v2/statuses') return json(statusesObj());
  if (route === '/wp/v2/taxonomies') return json(taxonomiesObj());
  if (route === '/wp/v2/plugins') return needAuth(c) || json([]);

  if ((m = route.match(/^\/wp\/v2\/(categories|tags)$/))) return termsCollection(c, TAX[m[1]]);
  if ((m = route.match(/^\/wp\/v2\/(categories|tags)\/(\d+)$/))) return termItem(c, TAX[m[1]], +m[2]);
  if (route === '/wp/v2/posts') return postsCollection(c);
  if ((m = route.match(/^\/wp\/v2\/posts\/(\d+)$/))) return postItem(c, +m[1]);
  if (route === '/wp/v2/media') return mediaCollection(c);
  if ((m = route.match(/^\/wp\/v2\/media\/(\d+)$/))) return mediaItem(c, +m[1]);

  return wpError('rest_no_route', 'Nie znaleziono ścieżki pasującej do adresu URL i metody żądania.', 404);
}

/* ------------------------------------------------------------------ */
/* Uwierzytelnianie (Basic Auth z hasłem aplikacji)                     */
/* ------------------------------------------------------------------ */

function checkAuth(request, env) {
  const h = request.headers.get('authorization') || '';
  if (!/^basic\s+/i.test(h)) return { present: false, ok: false, user: null };
  let decoded = '';
  try { decoded = atob(h.replace(/^basic\s+/i, '').trim()); } catch { /* zły base64 */ }
  const i = decoded.indexOf(':');
  const user = i >= 0 ? decoded.slice(0, i) : decoded;
  const pass = i >= 0 ? decoded.slice(i + 1) : '';
  const norm = (s) => String(s || '').replace(/\s+/g, ''); // WP ignoruje spacje w haśle aplikacji
  const userOk = !!env.WP_USER && user === env.WP_USER;
  const ok = userOk && !!env.WP_APP_PASSWORD && safeEqual(norm(pass), norm(env.WP_APP_PASSWORD));
  return { present: true, ok, userOk, user };
}

function needAuth(c) {
  return c.auth.ok ? null : wpError('rest_not_logged_in', 'Nie jesteś obecnie zalogowany.', 401);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ------------------------------------------------------------------ */
/* Dokumenty opisowe API                                                */
/* ------------------------------------------------------------------ */

function indexDoc(c) {
  const { site, env } = c;
  return {
    name: env.SITE_TITLE || 'Siechnice.com.pl',
    description: env.SITE_DESCRIPTION || '',
    url: site,
    home: site,
    gmt_offset: tzOffsetHours(new Date()),
    timezone_string: 'Europe/Warsaw',
    page_for_posts: 0,
    page_on_front: 0,
    show_on_front: 'posts',
    namespaces: ['oembed/1.0', 'wp/v2'],
    authentication: {
      'application-passwords': { endpoints: { authorization: `${site}/wp-admin/authorize-application.php` } },
    },
    routes: routesDoc(c),
    site_logo: 0,
    site_icon: 0,
    site_icon_url: '',
  };
}

function routesDoc(c) {
  const r = (path, methods) => [path, { namespace: 'wp/v2', methods, endpoints: [{ methods, args: {} }], _links: { self: [{ href: `${c.site}/wp-json${path}` }] } }];
  return Object.fromEntries([
    r('/wp/v2', ['GET']),
    r('/wp/v2/posts', ['GET', 'POST']),
    r('/wp/v2/posts/(?P<id>[\\d]+)', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
    r('/wp/v2/media', ['GET', 'POST']),
    r('/wp/v2/media/(?P<id>[\\d]+)', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']),
    r('/wp/v2/categories', ['GET', 'POST']),
    r('/wp/v2/categories/(?P<id>[\\d]+)', ['GET']),
    r('/wp/v2/tags', ['GET', 'POST']),
    r('/wp/v2/tags/(?P<id>[\\d]+)', ['GET']),
    r('/wp/v2/users', ['GET']),
    r('/wp/v2/users/me', ['GET']),
    r('/wp/v2/settings', ['GET']),
    r('/wp/v2/types', ['GET']),
    r('/wp/v2/statuses', ['GET']),
    r('/wp/v2/taxonomies', ['GET']),
  ]);
}

function userObj(c) {
  const { env, site } = c;
  const login = env.WP_USER || 'linkhouse';
  const slug = slugify(login);
  return {
    id: 1,
    username: login,
    name: env.WP_DISPLAY_NAME || login,
    first_name: '',
    last_name: '',
    email: env.WP_EMAIL || '',
    url: site,
    description: '',
    link: `${site}/author/${slug}/`,
    locale: 'pl_PL',
    nickname: login,
    slug,
    roles: ['administrator'],
    registered_date: '2018-03-05T12:18:01+00:00',
    capabilities: Object.fromEntries([
      'read', 'edit_posts', 'edit_others_posts', 'edit_published_posts', 'publish_posts', 'delete_posts',
      'delete_published_posts', 'upload_files', 'manage_categories', 'edit_pages', 'publish_pages',
      'unfiltered_html', 'administrator',
    ].map((k) => [k, true])),
    extra_capabilities: { administrator: true },
    avatar_urls: { 24: '', 48: '', 96: '' },
    meta: [],
  };
}

function settingsObj(c) {
  const { env, site } = c;
  return {
    title: env.SITE_TITLE || 'Siechnice.com.pl',
    description: env.SITE_DESCRIPTION || '',
    url: site,
    email: env.WP_EMAIL || '',
    timezone: 'Europe/Warsaw',
    date_format: 'j F Y',
    time_format: 'H:i',
    start_of_week: 1,
    language: 'pl_PL',
    use_smilies: false,
    default_category: firstCategoryId(env),
    default_post_format: '0',
    posts_per_page: 10,
    show_on_front: 'posts',
    page_on_front: 0,
    page_for_posts: 0,
    default_ping_status: 'closed',
    default_comment_status: 'closed',
    site_logo: null,
    site_icon: 0,
  };
}

function typesObj(c) {
  const t = (slug, name, rest_base, taxonomies) => ({
    description: '', hierarchical: slug === 'page', has_archive: false, name, slug, icon: null,
    taxonomies, rest_base, rest_namespace: 'wp/v2', _links: { 'wp:items': [{ href: `${c.site}/wp-json/wp/v2/${rest_base}` }] },
  });
  return {
    post: t('post', 'Wpisy', 'posts', ['category', 'post_tag']),
    page: t('page', 'Strony', 'pages', []),
    attachment: t('attachment', 'Media', 'media', []),
  };
}

function statusesObj() {
  const s = (slug, name, isPublic) => ({ name, private: slug === 'private', protected: ['draft', 'pending', 'future'].includes(slug), public: isPublic, queryable: isPublic, show_in_list: true, slug, date_floating: slug === 'draft' || slug === 'pending' });
  return {
    publish: s('publish', 'Opublikowano', true),
    future: s('future', 'Zaplanowano', false),
    draft: s('draft', 'Szkic', false),
    pending: s('pending', 'Oczekuje na przegląd', false),
    private: s('private', 'Prywatny', false),
  };
}

function taxonomiesObj() {
  return {
    category: { name: 'Kategorie', slug: 'category', description: '', types: ['post'], hierarchical: true, rest_base: 'categories', rest_namespace: 'wp/v2' },
    post_tag: { name: 'Tagi', slug: 'post_tag', description: '', types: ['post'], hierarchical: false, rest_base: 'tags', rest_namespace: 'wp/v2' },
  };
}

/* ------------------------------------------------------------------ */
/* Kategorie i tagi                                                     */
/* ------------------------------------------------------------------ */

function configuredCategories(env) {
  const fallback = [{ id: 1, name: 'Bez kategorii', slug: 'bez-kategorii' }];
  try {
    const parsed = env.CATEGORIES ? JSON.parse(env.CATEGORIES) : fallback;
    return Array.isArray(parsed) && parsed.length ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function firstCategoryId(env) {
  return configuredCategories(env)[0].id;
}

async function getTerms(env, tax) {
  const base = tax === 'category' ? configuredCategories(env) : [];
  const created = (await env.SHIM.get(`terms:${tax}`, 'json')) || [];
  return [...base, ...created];
}

function termView(t, tax, site) {
  const v = {
    id: t.id, count: 0, description: t.description || '', link: `${site}/${tax === 'category' ? 'kategoria' : 'tag'}/${t.slug}/`,
    name: t.name, slug: t.slug, taxonomy: tax, meta: [],
  };
  if (tax === 'category') v.parent = t.parent || 0;
  return v;
}

async function termsCollection(c, tax) {
  const { env, site, method, params } = c;
  if (method === 'GET') {
    let items = await getTerms(env, tax);
    items = filterItems(items, params, (t) => t.name);
    return paginate(c, items.map((t) => termView(t, tax, site)));
  }
  if (method === 'POST') {
    const denied = needAuth(c);
    if (denied) return denied;
    const name = String(params.name || '').trim();
    if (!name) return wpError('rest_missing_callback_param', 'Brakujący parametr: name', 400);
    const slug = slugify(params.slug || name);
    const all = await getTerms(env, tax);
    const existing = all.find((t) => t.slug === slug);
    if (existing) return wpError('term_exists', 'Element o podanej nazwie już istnieje.', 400, { term_id: existing.id });
    const term = { id: await nextId(env, 'term', 100), name, slug, description: String(params.description || ''), parent: +params.parent || 0 };
    const created = (await env.SHIM.get(`terms:${tax}`, 'json')) || [];
    created.push(term);
    await env.SHIM.put(`terms:${tax}`, JSON.stringify(created));
    return json(termView(term, tax, site), 201);
  }
  return methodNotAllowed();
}

async function termItem(c, tax, id) {
  if (c.method !== 'GET') return methodNotAllowed();
  const t = (await getTerms(c.env, tax)).find((x) => x.id === id);
  return t ? json(termView(t, tax, c.site)) : wpError('rest_term_invalid', 'Element nie istnieje.', 404);
}

/* ------------------------------------------------------------------ */
/* Wpisy                                                                */
/* ------------------------------------------------------------------ */

async function postsCollection(c) {
  const { env, method, params, auth } = c;
  if (method === 'GET') {
    let posts = await listJson(env, 'post:');
    const wanted = String(params.status || 'publish').split(',');
    posts = posts.filter((p) => (auth.ok ? (wanted.includes('any') ? p.status !== 'trash' : wanted.includes(p.status)) : p.status === 'publish'));
    posts = filterItems(posts, params, (p) => p.title);
    posts.sort((a, b) => b.id - a.id);
    return paginate(c, posts.map((p) => postView(p, c)));
  }
  if (method === 'POST') {
    const denied = needAuth(c);
    if (denied) return denied;
    const id = await nextId(env, 'obj', 1000);
    const now = new Date();
    const nowWp = wpDate(now);
    const rec = {
      id,
      date: params.date ? String(params.date).slice(0, 19) : nowWp.date,
      date_gmt: params.date_gmt ? String(params.date_gmt).slice(0, 19) : nowWp.date_gmt,
      modified: nowWp.date,
      modified_gmt: nowWp.date_gmt,
      received: { at: now.toISOString(), ip: c.request.headers.get('cf-connecting-ip'), ua: c.request.headers.get('user-agent') },
    };
    applyPostFields(rec, params);
    rec.slug = await uniqueSlug(env, rec.slug || slugify(rec.title), id);
    return savePostAndRespond(c, rec, 201);
  }
  return methodNotAllowed();
}

async function postItem(c, id) {
  const { env, method, params, auth } = c;
  const rec = await env.SHIM.get(`post:${id}`, 'json');
  if (!rec) return wpError('rest_post_invalid_id', 'Nieprawidłowy identyfikator wpisu.', 404);

  if (method === 'GET') {
    if (rec.status !== 'publish' && !auth.ok) return wpError('rest_forbidden', 'Brak uprawnień.', 401);
    return json(postView(rec, c));
  }
  const denied = needAuth(c);
  if (denied) return denied;

  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    if (rec.bolt) {
      // Już w Bolcie: zmian z platformy nie przenosimy automatycznie (opublikowany tekst zmienia człowiek).
      rec.edits_ignored = (rec.edits_ignored || 0) + 1;
      rec.last_edit = { at: new Date().toISOString(), fields: Object.keys(params) };
      await env.SHIM.put(`post:${id}`, JSON.stringify(rec));
      if (rec.edits_ignored === 1) c.ctx.waitUntil(zglosDoSkrzynki(c, rec, 'edycja').catch((e) => console.error('skrzynka', e)));
      return json(postView(rec, c));
    }
    const oldSlug = rec.slug;
    applyPostFields(rec, params);
    if (params.slug !== undefined) rec.slug = await uniqueSlug(env, slugify(params.slug), id);
    else rec.slug = oldSlug;
    const nowWp = wpDate(new Date());
    rec.modified = nowWp.date;
    rec.modified_gmt = nowWp.date_gmt;
    return savePostAndRespond(c, rec, 200);
  }
  if (method === 'DELETE') {
    const view = postView(rec, c);
    if (rec.bolt) {
      // Artykuł w Bolcie zostaje — o usunięciu decyduje człowiek (karta w skrzynce).
      rec.status = 'trash';
      await env.SHIM.put(`post:${id}`, JSON.stringify(rec));
      c.ctx.waitUntil(zglosDoSkrzynki(c, rec, 'usuniecie').catch((e) => console.error('skrzynka', e)));
      return json(String(params.force) === 'true' || params.force === true ? { deleted: true, previous: view } : postView(rec, c));
    }
    if (String(params.force) === 'true' || params.force === true) {
      await env.SHIM.delete(`post:${id}`);
      await env.SHIM.delete(`slug:${rec.slug}`);
      return json({ deleted: true, previous: view });
    }
    rec.status = 'trash';
    await env.SHIM.put(`post:${id}`, JSON.stringify(rec));
    return json(postView(rec, c));
  }
  return methodNotAllowed();
}

function applyPostFields(rec, p) {
  if (p.title !== undefined) rec.title = rawText(p.title);
  if (p.content !== undefined) rec.content = rawText(p.content);
  if (p.excerpt !== undefined) rec.excerpt = rawText(p.excerpt);
  if (p.status !== undefined || rec.status === undefined) rec.status = normStatus(p.status);
  if (p.categories !== undefined) rec.categories = idList(p.categories);
  if (p.tags !== undefined) rec.tags = idList(p.tags);
  if (p.featured_media !== undefined) rec.featured_media = +p.featured_media || 0;
  if (p.meta !== undefined) rec.meta = p.meta;
  if (p.slug !== undefined && !rec.slug) rec.slug = slugify(p.slug);
  rec.title ??= '';
  rec.content ??= '';
  rec.excerpt ??= '';
  rec.categories ??= [];
  rec.tags ??= [];
  rec.featured_media ??= 0;
  rec.meta ??= {};
  // Zachowujemy wszystkie pozostałe pola, żeby zobaczyć, co jeszcze wysyłają (np. meta Yoast).
  const known = ['title', 'content', 'excerpt', 'status', 'categories', 'tags', 'featured_media', 'meta', 'slug', 'date', 'date_gmt', 'rest_route', '_method'];
  const extra = Object.fromEntries(Object.entries(p).filter(([k]) => !known.includes(k)));
  if (Object.keys(extra).length) rec.extra_fields = { ...(rec.extra_fields || {}), ...extra };
}

async function savePostAndRespond(c, rec, okStatus) {
  const { env } = c;
  const wantsPublic = ['publish', 'future'].includes(rec.status);
  if (wantsPublic && env.ACCEPT_PUBLISH === 'true' && env.SITE_MCP_TOKEN) {
    // Etap 2: od razu artykuł w Bolcie (kategoria sponsorowana), potem karta w skrzynce.
    // „future” (zaplanowane) też publikujemy od razu — Bolt przez MCP nie planuje publikacji.
    try {
      rec.bolt = await publikujWBolcie(c, rec);
    } catch (e) {
      rec.requested_status = rec.status;
      rec.status = 'pending';
      rec.bolt_error = String(e && e.message ? e.message : e).slice(0, 500);
      await storePost(env, rec);
      c.ctx.waitUntil(zglosDoSkrzynki(c, rec, 'blad').catch((err) => console.error('skrzynka', err)));
      return wpError('shim_publish_failed', `Nie udało się opublikować (ID ${rec.id}): ${rec.bolt_error}`, 502, { post_id: rec.id });
    }
    rec.requested_status = rec.status;
    rec.status = 'publish';
    delete rec.bolt_error;
    await storePost(env, rec);
    c.ctx.waitUntil(zglosDoSkrzynki(c, rec, 'publikacja').catch((e) => console.error('skrzynka', e)));
    const view = postView(rec, c);
    return json(view, okStatus, okStatus === 201 ? { Location: `${c.site}/wp-json/wp/v2/posts/${rec.id}` } : {});
  }
  if (wantsPublic && rec.bolt) return json(postView(rec, c), okStatus);
  if (wantsPublic) {
    // Etap rozpoznania: treść zapisujemy, ale nie udajemy publikacji,
    // żeby platforma nie zgłosiła adresu, pod którym jeszcze nic nie ma.
    rec.requested_status = rec.status;
    rec.status = 'pending';
    await storePost(env, rec);
    return wpError(
      'shim_capture_only',
      `Wpis zapisany jako ID ${rec.id}, ale automatyczna publikacja jest jeszcze wyłączona. Opublikuj go ręcznie.`,
      503,
      { post_id: rec.id },
    );
  }
  await storePost(env, rec);
  const view = postView(rec, c);
  return json(view, okStatus, okStatus === 201 ? { Location: `${c.site}/wp-json/wp/v2/posts/${rec.id}` } : {});
}

async function storePost(env, rec) {
  await env.SHIM.put(`post:${rec.id}`, JSON.stringify(rec));
  await env.SHIM.put(`slug:${rec.slug}`, String(rec.id));
}

function postLink(slug, id, c) {
  const tpl = c.env.POST_URL_TEMPLATE || `${c.site}/entry/{slug}`;
  return tpl.replace('{slug}', slug).replace('{id}', String(id));
}

function postView(r, c) {
  const isPublic = ['publish', 'future', 'private'].includes(r.status);
  const link = r.bolt && r.bolt.url ? r.bolt.url : isPublic ? postLink(r.slug, r.id, c) : `${c.site}/?p=${r.id}`;
  return {
    id: r.id,
    date: r.date,
    date_gmt: r.date_gmt,
    guid: { rendered: `${c.site}/?p=${r.id}`, raw: `${c.site}/?p=${r.id}` },
    modified: r.modified,
    modified_gmt: r.modified_gmt,
    password: '',
    slug: r.slug,
    status: r.status,
    type: 'post',
    link,
    title: { raw: r.title, rendered: escapeHtml(r.title) },
    content: { raw: r.content, rendered: r.content, protected: false, block_version: 0 },
    excerpt: { raw: r.excerpt, rendered: r.excerpt, protected: false },
    author: 1,
    featured_media: r.featured_media,
    comment_status: 'closed',
    ping_status: 'closed',
    sticky: false,
    template: '',
    format: 'standard',
    meta: r.meta,
    categories: r.categories,
    tags: r.tags,
    permalink_template: postLink('%postname%', r.id, c),
    generated_slug: r.slug,
    _links: { self: [{ href: `${c.site}/wp-json/wp/v2/posts/${r.id}` }] },
  };
}

async function uniqueSlug(env, slug, id) {
  let candidate = slug || 'wpis';
  for (let n = 2; n < 100; n++) {
    const owner = await env.SHIM.get(`slug:${candidate}`);
    if (!owner || owner === String(id)) return candidate;
    candidate = `${slug}-${n}`;
  }
  return `${slug}-${id}`;
}

function normStatus(s) {
  const v = String(s || 'draft').toLowerCase();
  return ['publish', 'future', 'draft', 'pending', 'private'].includes(v) ? v : 'draft';
}

/* ------------------------------------------------------------------ */
/* Etap 2: publikacja w Bolcie (MCP strony) i karta w skrzynce           */
/* ------------------------------------------------------------------ */

/** Narzędzie MCP strony (token usługi z mcp_tokens: create_news, prepare_upload). */
async function siteTool(env, name, args) {
  const res = await fetch(env.SITE_MCP_URL || 'https://siechnice.com.pl/mcp', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.SITE_MCP_TOKEN}`, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
    signal: AbortSignal.timeout(25000),
  });
  if (res.status === 401) throw new Error('strona odrzuciła token MCP (401)');
  if (!res.ok) throw new Error(`strona: HTTP ${res.status} przy ${name}`);
  const body = await res.json();
  if (body.error) throw new Error(`strona: ${body.error.message || 'błąd wywołania'}`);
  const data = (body.result && body.result.structuredContent) || {};
  if (body.result && body.result.isError) throw new Error(`strona: ${data.error || (body.result.content && body.result.content[0] && body.result.content[0].text) || 'błąd narzędzia'}`);
  return data;
}

/** Usuwa śmieci edytorów (dir, data-*, class) — reszta HTML idzie do sanitizera Bolta. */
function oczyscHtml(html) {
  return String(html || '')
    .replace(/\s(?:dir|class|data-[\w-]+)=("[^"]*"|'[^']*')/gi, '')
    .replace(/<p>\s*(?:&nbsp;|\s)*<\/p>/gi, '')
    .trim();
}

/** Wstęp = excerpt albo pierwszy akapit treści (wtedy wycięty z treści, żeby się nie powtarzał). */
function wstepITresc(rec) {
  const tresc = oczyscHtml(rec.content);
  const excerpt = oczyscHtml(rec.excerpt);
  if (excerpt.replace(/<[^>]+>/g, '').trim()) return { teaser: excerpt.startsWith('<') ? excerpt : `<p>${excerpt}</p>`, body: tresc };
  const m = tresc.match(/^\s*(<p>[\s\S]*?<\/p>)/i);
  if (m) {
    const reszta = tresc.slice(m[0].length).trim();
    return { teaser: m[1], body: reszta || m[1] };
  }
  return { teaser: `<p>${escapeHtml(rec.title)}</p>`, body: tresc || `<p>${escapeHtml(rec.title)}</p>` };
}

const ROZSZERZENIA = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };

/** Zdjęcie wyróżnione z KV → pliki strony (podpisany link z prepare_upload). Zwraca ścieżkę albo null. */
async function wgrajZdjecie(env, mediaId) {
  if (!mediaId) return null;
  const meta = await env.SHIM.get(`media:${mediaId}`, 'json');
  const bytes = await env.SHIM.get(`mediafile:${mediaId}`, 'arrayBuffer');
  if (!meta || !bytes) return null;
  let mime = String(meta.mime || '').toLowerCase();
  if (mime === 'image/jpg' || mime === 'image/pjpeg') mime = 'image/jpeg';
  const ext = ROZSZERZENIA[mime];
  if (!ext) return null;
  const link = await siteTool(env, 'prepare_upload', {});
  const uploadUrl = String(link.upload_url || '');
  if (!/^https?:\/\//.test(uploadUrl)) throw new Error('strona nie dała linku do wgrania zdjęcia');
  const nazwa = (meta.filename || 'zdjecie').replace(/\.[^.]+$/, '').slice(0, 80) + '.' + ext;
  const form = new FormData();
  form.append('file', new Blob([bytes], { type: mime }), nazwa);
  const res = await fetch(uploadUrl, { method: 'POST', body: form, signal: AbortSignal.timeout(30000) });
  const odp = await res.json().catch(() => ({}));
  const sciezka = odp.files && odp.files[0] && odp.files[0].path;
  if (!res.ok || !sciezka) throw new Error(`strona nie przyjęła zdjęcia: ${odp.error || (odp.errors || []).join('; ') || 'HTTP ' + res.status}`);
  return { path: sciezka, alt: meta.alt_text || '', podpis: meta.caption ? rawText(meta.caption).replace(/<[^>]+>/g, '').trim() : '' };
}

/**
 * Tworzy opublikowaną aktualność. Blokada na tytuł (10 min) chroni przed podwójną publikacją, gdy platforma
 * ponowi żądanie po przekroczeniu czasu; ten sam tytuł w ciągu doby zwraca już opublikowany artykuł.
 */
async function publikujWBolcie(c, rec) {
  const { env } = c;
  const klucz = `pub:${slugify(rec.title).slice(0, 120)}`;
  const byl = await env.SHIM.get(klucz, 'json');
  if (byl && byl.url) return { ...byl, powtorka: true };
  if (byl && byl.trwa) throw new Error('ten artykuł właśnie się publikuje — spróbuj za kilka minut');
  await env.SHIM.put(klucz, JSON.stringify({ trwa: true }), { expirationTtl: 600 });
  try {
    const { teaser, body } = wstepITresc(rec);
    const zdj = await wgrajZdjecie(env, rec.featured_media);
    const podpis = (zdj && zdj.podpis) || env.IMAGE_CREDIT || '';
    const r = await siteTool(env, 'create_news', {
      title: String(rec.title).slice(0, 250),
      teaser,
      body,
      categories: [env.BOLT_CATEGORY || 'artykul-sponsorowany'],
      ...(zdj ? { image: { file: zdj.path, title: zdj.alt || rec.title } } : {}),
      ...(podpis ? { imagecredentials: podpis } : {}),
      publish: true,
    });
    const bolt = { id: r.id ?? null, url: typeof r.url === 'string' ? r.url : null, admin_url: typeof r.admin_url === 'string' ? r.admin_url : null, at: new Date().toISOString(), zdjecie: !!zdj };
    if (!bolt.url) throw new Error('strona nie zwróciła adresu artykułu');
    await env.SHIM.put(klucz, JSON.stringify(bolt), { expirationTtl: 86400 });
    return bolt;
  } catch (e) {
    await env.SHIM.delete(klucz);
    throw e;
  }
}

/** Karta w skrzynce (wtyczka „przypomnienia”, nadawca wp-shim): link do artykułu i do panelu, przycisk „OK”. */
async function zglosDoSkrzynki(c, rec, rodzaj) {
  const { env } = c;
  if (!env.SKRZYNKA_TOKEN) return;
  const platforma = env.PLATFORM_NAME || 'Linkhouse';
  const tytuly = {
    publikacja: `${platforma}: opublikowano „${rec.title}”`,
    blad: `${platforma}: NIE udało się opublikować „${rec.title}”`,
    edycja: `${platforma} zmienia opublikowany artykuł „${rec.title}”`,
    usuniecie: `${platforma} usunął wpis „${rec.title}”`,
  };
  const opisy = {
    publikacja: `Artykuł sponsorowany jest już na stronie${rec.bolt && rec.bolt.zdjecie ? ' (ze zdjęciem)' : ' (bez zdjęcia — dodaj w panelu)'}. Sprawdź go; żeby wycofać, zmień status w panelu na „wstrzymany” albo „szkic”.`,
    blad: `Platforma dostała błąd, więc może ponowić albo pokazać go klientowi. Powód: ${rec.bolt_error || '?'}. Treść jest w shimie (ID ${rec.id}).`,
    edycja: 'Platforma przysłała zmiany do opublikowanego wpisu. Nie przeniesiono ich automatycznie — jeśli trzeba, popraw artykuł w panelu.',
    usuniecie: 'Platforma usunęła wpis u siebie. Artykuł na stronie został — zdecyduj w panelu, czy go wycofać.',
  };
  const akcje = [];
  if (rec.bolt && /^https:/.test(rec.bolt.url || '')) akcje.push({ type: 'Action.OpenUrl', title: 'Zobacz na stronie', url: rec.bolt.url });
  if (rec.bolt && /^https:/.test(rec.bolt.admin_url || '')) akcje.push({ type: 'Action.OpenUrl', title: 'Edytuj / wycofaj w panelu', url: rec.bolt.admin_url });
  akcje.push({ type: 'Action.Execute', verb: 'zrobione', title: 'OK', style: 'positive' });
  const karta = {
    type: 'AdaptiveCard',
    version: '1.5',
    body: [
      { type: 'TextBlock', text: tytuly[rodzaj].slice(0, 200), weight: 'bolder', size: 'large', wrap: true },
      { type: 'TextBlock', text: opisy[rodzaj], wrap: true },
      { type: 'FactSet', facts: [
        { title: 'Kategoria', value: env.BOLT_CATEGORY || 'artykul-sponsorowany' },
        { title: 'Wpis w shimie', value: `ID ${rec.id}` },
        ...(rec.bolt && rec.bolt.id ? [{ title: 'Aktualność', value: `#${rec.bolt.id}` }] : []),
      ] },
    ],
    actions: akcje,
  };
  const res = await fetch((env.SKRZYNKA_URL || 'https://skrzynka.siechnice.com.pl') + '/api/zadania', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.SKRZYNKA_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ wtyczka: 'przypomnienia', klucz: `${rodzaj}:${rec.id}`, karta, tagi: ['sponsorowane'] }),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) console.error('skrzynka HTTP', res.status, (await res.text()).slice(0, 300));
}

/* ------------------------------------------------------------------ */
/* Media                                                                */
/* ------------------------------------------------------------------ */

async function mediaCollection(c) {
  const { env, method, params, request, buf, ct, file } = c;
  if (method === 'GET') {
    let items = await listJson(env, 'media:');
    items = filterItems(items, params, (m) => m.title);
    items.sort((a, b) => b.id - a.id);
    return paginate(c, items.map((m) => mediaView(m, c)));
  }
  if (method !== 'POST') return methodNotAllowed();
  const denied = needAuth(c);
  if (denied) return denied;

  let bytes, mime, filename;
  if (file) {
    bytes = await file.arrayBuffer();
    mime = file.type || 'application/octet-stream';
    filename = file.name || 'plik';
  } else if (buf && buf.byteLength) {
    bytes = buf;
    mime = ct.split(';')[0].trim() || 'application/octet-stream';
    filename = filenameFromDisposition(request.headers.get('content-disposition')) || 'plik';
  } else {
    return wpError('rest_upload_no_data', 'Nie przesłano danych.', 400);
  }

  const id = await nextId(env, 'obj', 1000);
  const nowWp = wpDate(new Date());
  const rec = {
    id,
    filename: safeFilename(filename),
    mime,
    size: bytes.byteLength,
    title: rawText(params.title) || filename.replace(/\.[^.]+$/, ''),
    alt_text: String(params.alt_text || ''),
    caption: rawText(params.caption),
    description: rawText(params.description),
    post: +params.post || null,
    date: nowWp.date,
    date_gmt: nowWp.date_gmt,
  };
  await env.SHIM.put(`mediafile:${id}`, bytes, { metadata: { mime, filename: rec.filename } });
  await env.SHIM.put(`media:${id}`, JSON.stringify(rec));
  return json(mediaView(rec, c), 201, { Location: `${c.site}/wp-json/wp/v2/media/${id}` });
}

async function mediaItem(c, id) {
  const { env, method, params } = c;
  const rec = await env.SHIM.get(`media:${id}`, 'json');
  if (!rec) return wpError('rest_post_invalid_id', 'Nieprawidłowy identyfikator załącznika.', 404);
  if (method === 'GET') return json(mediaView(rec, c));
  const denied = needAuth(c);
  if (denied) return denied;
  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    if (params.title !== undefined) rec.title = rawText(params.title);
    if (params.alt_text !== undefined) rec.alt_text = String(params.alt_text);
    if (params.caption !== undefined) rec.caption = rawText(params.caption);
    if (params.description !== undefined) rec.description = rawText(params.description);
    if (params.post !== undefined) rec.post = +params.post || null;
    await env.SHIM.put(`media:${id}`, JSON.stringify(rec));
    return json(mediaView(rec, c));
  }
  if (method === 'DELETE') {
    const view = mediaView(rec, c);
    await env.SHIM.delete(`media:${id}`);
    await env.SHIM.delete(`mediafile:${id}`);
    return json({ deleted: true, previous: view });
  }
  return methodNotAllowed();
}

function mediaView(r, c) {
  const src = `${c.site}/wp-json/__shim/media/${r.id}/${encodeURIComponent(r.filename)}`;
  return {
    id: r.id,
    date: r.date,
    date_gmt: r.date_gmt,
    guid: { rendered: src, raw: src },
    modified: r.date,
    modified_gmt: r.date_gmt,
    slug: slugify(r.title),
    status: 'inherit',
    type: 'attachment',
    link: src,
    title: { raw: r.title, rendered: escapeHtml(r.title) },
    author: 1,
    comment_status: 'closed',
    ping_status: 'closed',
    template: '',
    meta: [],
    description: { raw: r.description || '', rendered: r.description || '' },
    caption: { raw: r.caption || '', rendered: r.caption || '' },
    alt_text: r.alt_text,
    media_type: r.mime.startsWith('image/') ? 'image' : 'file',
    mime_type: r.mime,
    media_details: { filesize: r.size, width: 0, height: 0, file: r.filename, sizes: {} },
    post: r.post,
    source_url: src,
  };
}

/* ------------------------------------------------------------------ */
/* Panel podglądu                                                       */
/* ------------------------------------------------------------------ */

async function handleAdmin(request, env, url, site, route) {
  let m = route.match(/^\/__shim\/media\/(\d+)(?:\/.*)?$/);
  if (m) {
    // Obrazki są publiczne, bo trafiają do treści artykułów.
    const { value, metadata } = await env.SHIM.getWithMetadata(`mediafile:${m[1]}`, 'arrayBuffer');
    if (!value) return new Response('Nie znaleziono', { status: 404 });
    return new Response(value, { headers: { 'content-type': metadata?.mime || 'application/octet-stream', 'cache-control': 'public, max-age=86400' } });
  }

  const token = url.searchParams.get('token') || request.headers.get('x-shim-token') || '';
  if (!env.ADMIN_TOKEN || !safeEqual(token, env.ADMIN_TOKEN)) return new Response('Brak dostępu', { status: 403 });

  if (route === '/__shim') {
    return pretty({ endpoints: ['/wp-json/__shim/logs', '/wp-json/__shim/logs?full=1&limit=20', '/wp-json/__shim/posts', '/wp-json/__shim/posts/ID', '/wp-json/__shim/posts/ID?html=1'] });
  }

  if (route === '/__shim/logs') {
    const limit = Math.min(+url.searchParams.get('limit') || 50, 100);
    const list = await env.SHIM.list({ prefix: 'log:', limit });
    const entries = (await Promise.all(list.keys.map((k) => env.SHIM.get(k.name, 'json')))).filter(Boolean);
    if (url.searchParams.get('full')) return pretty(entries);
    return pretty(entries.map((e) => ({
      time: e.time,
      req: `${e.method} ${e.path}${e.query}`,
      status: e.response.status,
      auth: e.auth ? `${e.auth.user} ${e.auth.ok ? 'OK' : 'ZŁE'}` : '-',
      ua: e.headers['user-agent'] || '',
      ip: `${e.ip} ${e.asOrg || ''}`.trim(),
    })));
  }

  if (route === '/__shim/posts') {
    const posts = (await listJson(env, 'post:')).sort((a, b) => b.id - a.id);
    return pretty(posts.map((p) => ({ id: p.id, title: p.title, status: p.status, requested_status: p.requested_status, slug: p.slug, received: p.received?.at, ua: p.received?.ua })));
  }

  m = route.match(/^\/__shim\/posts\/(\d+)$/);
  if (m) {
    const p = await env.SHIM.get(`post:${m[1]}`, 'json');
    if (!p) return new Response('Nie znaleziono', { status: 404 });
    if (!url.searchParams.get('html')) return pretty(p);
    const html = `<!doctype html><html lang="pl"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(p.title)}</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem}img{max-width:100%}
.meta{color:#666;font-size:.9em;border-bottom:1px solid #ddd;padding-bottom:1rem}</style></head><body>
<p class="meta">ID ${p.id} · status: ${escapeHtml(p.status)} · slug: ${escapeHtml(p.slug)} · kategorie: ${escapeHtml(JSON.stringify(p.categories))}</p>
<h1>${escapeHtml(p.title)}</h1>${p.content}</body></html>`;
    return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
  }

  return new Response('Nie znaleziono', { status: 404 });
}

/* ------------------------------------------------------------------ */
/* Logowanie                                                            */
/* ------------------------------------------------------------------ */

async function logRequest(c, response) {
  const { request, url, method, buf, ct, auth, env } = c;
  const now = new Date();
  const headers = {};
  for (const [k, v] of request.headers) if (k !== 'authorization' && k !== 'cookie') headers[k] = v;
  let resBody = '';
  try { resBody = (await response.text()).slice(0, 4000); } catch { /* brak treści */ }
  const entry = {
    time: now.toISOString(),
    ip: request.headers.get('cf-connecting-ip'),
    country: request.cf?.country,
    asn: request.cf?.asn,
    asOrg: request.cf?.asOrganization,
    method,
    originalMethod: request.method,
    path: url.pathname,
    query: url.search,
    auth: auth.present ? { user: auth.user, ok: auth.ok } : null,
    headers,
    body: describeBody(buf, ct),
    response: { status: response.status, body: resBody },
  };
  console.log(JSON.stringify({ time: entry.time, req: `${method} ${url.pathname}${url.search}`, status: response.status, ua: headers['user-agent'], auth: entry.auth }));
  const key = `log:${String(9e15 - now.getTime()).padStart(16, '0')}:${crypto.randomUUID().slice(0, 8)}`;
  await env.SHIM.put(key, JSON.stringify(entry), { expirationTtl: LOG_TTL });
}

function describeBody(buf, ct) {
  if (!buf || !buf.byteLength) return null;
  const t = (ct || '').toLowerCase();
  if (!t || /json|text|xml|x-www-form-urlencoded/.test(t)) {
    const s = new TextDecoder().decode(buf);
    return s.length > 20000 ? `${s.slice(0, 20000)}… [ucięto, razem ${s.length} znaków]` : s;
  }
  return `<binarne: ${t}, ${buf.byteLength} B>`;
}

/* ------------------------------------------------------------------ */
/* Narzędzia                                                            */
/* ------------------------------------------------------------------ */

function siteOf(env, url) {
  return (env.SITE_URL || url.origin).replace(/\/+$/, '');
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=UTF-8', 'x-robots-tag': 'noindex', 'cache-control': 'no-store', ...extra },
  });
}

function pretty(data) {
  return new Response(JSON.stringify(data, null, 2), { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
}

function wpError(code, message, status, extraData = {}) {
  return json({ code, message, data: { status, ...extraData } }, status);
}

function methodNotAllowed() {
  return wpError('rest_no_route', 'Nie znaleziono ścieżki pasującej do adresu URL i metody żądania.', 404);
}

function paginate(c, items) {
  const per = Math.min(Math.max(parseInt(c.params.per_page, 10) || 10, 1), 100);
  const page = Math.max(parseInt(c.params.page, 10) || 1, 1);
  const total = items.length;
  const pages = Math.max(1, Math.ceil(total / per));
  if (page > pages && total > 0) return wpError('rest_post_invalid_page_number', 'Żądany numer strony jest większy niż liczba dostępnych stron.', 400);
  return json(items.slice((page - 1) * per, page * per), 200, { 'X-WP-Total': String(total), 'X-WP-TotalPages': String(pages) });
}

function filterItems(items, params, nameOf) {
  let out = items;
  if (params.search) {
    const q = String(params.search).toLowerCase();
    out = out.filter((x) => String(nameOf(x) || '').toLowerCase().includes(q));
  }
  if (params.slug) {
    const slugs = String(params.slug).split(',');
    out = out.filter((x) => slugs.includes(x.slug));
  }
  if (params.include) {
    const ids = idList(params.include);
    out = out.filter((x) => ids.includes(x.id));
  }
  if (params.exclude) {
    const ids = idList(params.exclude);
    out = out.filter((x) => !ids.includes(x.id));
  }
  return out;
}

async function listJson(env, prefix) {
  const keys = [];
  let cursor;
  do {
    const page = await env.SHIM.list({ prefix, cursor });
    keys.push(...page.keys.map((k) => k.name));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && keys.length < 1000);
  return (await Promise.all(keys.map((k) => env.SHIM.get(k, 'json')))).filter(Boolean);
}

async function nextId(env, name, start) {
  const key = `seq:${name}`;
  const next = (parseInt(await env.SHIM.get(key), 10) || start) + 1;
  await env.SHIM.put(key, String(next));
  return next;
}

async function parseBody(buf, ct) {
  if (!buf || !buf.byteLength) return { fields: {} };
  const t = (ct || '').toLowerCase();
  const text = () => new TextDecoder().decode(buf);
  if (t.includes('multipart/form-data')) {
    const fd = await new Response(buf, { headers: { 'content-type': ct } }).formData();
    const fields = {};
    let file = null;
    for (const [k, v] of fd) {
      if (typeof v === 'object' && v !== null && 'arrayBuffer' in v) file = file || v;
      else addField(fields, k, v);
    }
    return { fields, file };
  }
  if (t.includes('application/x-www-form-urlencoded')) {
    const fields = {};
    for (const [k, v] of new URLSearchParams(text())) addField(fields, k, v);
    return { fields };
  }
  if (t.includes('json') || !t) {
    try {
      const v = JSON.parse(text());
      return { fields: v && typeof v === 'object' && !Array.isArray(v) ? v : {} };
    } catch {
      return { fields: {} };
    }
  }
  return { fields: {} }; // surowy plik (np. image/jpeg przy /media)
}

function queryObj(url) {
  const out = {};
  for (const [k, v] of url.searchParams) if (k !== 'rest_route' && k !== '_method') addField(out, k, v);
  return out;
}

// Obsługa form: categories[]=1&categories[]=2 oraz title[raw]=...
function addField(obj, key, value) {
  const arr = key.match(/^(.+)\[\]$/);
  if (arr) {
    (obj[arr[1]] = Array.isArray(obj[arr[1]]) ? obj[arr[1]] : []).push(value);
    return;
  }
  const nested = key.match(/^(.+)\[([^\]]+)\]$/);
  if (nested) {
    obj[nested[1]] = typeof obj[nested[1]] === 'object' && obj[nested[1]] ? obj[nested[1]] : {};
    obj[nested[1]][nested[2]] = value;
    return;
  }
  obj[key] = value;
}

function rawText(v) {
  if (v === undefined || v === null) return '';
  if (typeof v === 'object') return String(v.raw ?? v.rendered ?? '');
  return String(v);
}

function idList(v) {
  if (v === undefined || v === null || v === '') return [];
  const arr = Array.isArray(v) ? v : String(v).split(',');
  return arr.map((x) => parseInt(x, 10)).filter((x) => Number.isFinite(x));
}

function slugify(s) {
  const map = { ą: 'a', ć: 'c', ę: 'e', ł: 'l', ń: 'n', ó: 'o', ś: 's', ź: 'z', ż: 'z' };
  return String(s || '')
    .toLowerCase()
    .replace(/[ąćęłńóśźż]/g, (ch) => map[ch])
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 190);
}

function safeFilename(name) {
  const dot = name.lastIndexOf('.');
  const base = slugify(dot > 0 ? name.slice(0, dot) : name) || 'plik';
  const ext = dot > 0 ? name.slice(dot + 1).toLowerCase().replace(/[^a-z0-9]/g, '') : '';
  return ext ? `${base}.${ext}` : base;
}

function filenameFromDisposition(h) {
  if (!h) return null;
  const star = h.match(/filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i);
  if (star) {
    try { return decodeURIComponent(star[1].trim().replace(/^"|"$/g, '')); } catch { /* dalej */ }
  }
  const plain = h.match(/filename\s*=\s*"?([^";]+)"?/i);
  return plain ? plain[1].trim() : null;
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

// Data w formacie WordPressa: lokalna (Europe/Warsaw) i GMT, bez strefy.
function wpDate(d) {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Europe/Warsaw', year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }).formatToParts(d).map((p) => [p.type, p.value]),
  );
  const hour = parts.hour === '24' ? '00' : parts.hour;
  return { date: `${parts.year}-${parts.month}-${parts.day}T${hour}:${parts.minute}:${parts.second}`, date_gmt: d.toISOString().slice(0, 19) };
}

function tzOffsetHours(d) {
  const local = new Date(wpDate(d).date + 'Z');
  return Math.round((local.getTime() - Math.floor(d.getTime() / 1000) * 1000) / 3600000);
}
