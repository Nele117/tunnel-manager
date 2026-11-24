"""Tunnel Manager: single-process LAN administration service, Python standard library."""
import os, json, re, secrets, hmac, time, threading, subprocess, signal, ipaddress, socket, ssl, copy, sys
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler, HTTPSHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from http.cookies import SimpleCookie
from collections import deque
from concurrent.futures import ThreadPoolExecutor

DATA=Path(os.environ.get('DATA_DIR','/data')); STATIC=Path(__file__).parent/'static'
LOCK=threading.RLock(); SESSIONS={}; ATTEMPTS={}; LOG=deque(maxlen=150); STOP=threading.Event(); CHILD=None
PASSWORD=os.environ.get('ADMIN_PASSWORD',''); SECURE=os.environ.get('SECURE_COOKIE','0')=='1'
class Error(Exception): pass
class Pending(Error): pass
class Conflict(Error): pass
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None
OPENER=build_opener(ProxyHandler({}),NoRedirect())

def load():
    try: return json.loads((DATA/'state.json').read_text())
    except FileNotFoundError: return {}
def write_json(name,s):
    DATA.mkdir(parents=True,exist_ok=True); p=DATA/(name+'.tmp')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f: json.dump(s,f,indent=2); f.flush(); os.fsync(f.fileno())
    os.replace(p,DATA/name)
    fd=os.open(DATA,os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)
def save(s): write_json('state.json',s)
def event(msg): LOG.append(f'{time.strftime("%H:%M:%S")}  {msg}')
def cf(token,method,path,body=None,query=None,full=False):
    url='https://api.cloudflare.com/client/v4'+path+('?' + urlencode(query) if query else '')
    req=Request(url,data=json.dumps(body).encode() if body is not None else None,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','User-Agent':'TunnelManager/1.4.1'})
    try:
        with OPENER.open(req,timeout=18) as r: data=json.load(r)
    except HTTPError as e:
        try: errors=json.load(e).get('errors',[]); msg='; '.join(str(x.get('message','')) for x in errors)
        except Exception: msg=''
        raise Error(f'Cloudflare HTTP {e.code}: {msg or e.reason}') from None
    except (URLError,TimeoutError) as e: raise Error('Cloudflare API unreachable: '+str(e.reason if isinstance(e,URLError) else e)) from None
    if not data.get('success'): raise Error('Cloudflare: '+ '; '.join(x.get('message','') for x in data.get('errors',[])))
    return data if full else data.get('result')
def pages(token,path,query=None):
    out=[]
    for page in range(1,101):
        d=cf(token,'GET',path,query={**(query or {}),'page':page,'per_page':50},full=True); rows=d.get('result') or []; out.extend(rows)
        info=d.get('result_info') or {}
        if page>=info.get('total_pages',page+1) or len(rows)<50: return out
    raise Error('Too many API results; narrow the token scope.')
def account(s): return '/accounts/'+s['account']
def tunnel(s): return account(s)+'/cfd_tunnel/'+s['tunnel']
def call(s,m,p,b=None,q=None): return cf(s['token'],m,p,b,q)
def config(s): return (call(s,'GET',tunnel(s)+'/configurations') or {}).get('config') or {}
def put(s,c): return call(s,'PUT',tunnel(s)+'/configurations',{'config':c})
def rules(c): return c.get('ingress') or []
def set_rule(c,host,new):
    c=copy.deepcopy(c); rr=rules(c); rr=[r for r in rr if r.get('hostname')!=host or r.get('path')]
    if not rr or rr[-1].get('hostname') or rr[-1].get('path'): rr.append({'service':'http_status:404'})
    if new: rr.insert(0,new)
    c['ingress']=rr; return c

def valid_id(v):
    if not isinstance(v,str) or not re.fullmatch(r'[a-fA-F0-9-]{32,36}',v): raise Error('Invalid Cloudflare identifier.')
    return v

def origin(v):
    try:
        u=urlsplit(v); ip=ipaddress.ip_address(u.hostname or ''); port=u.port
        allowed=any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
        if u.scheme not in ('http','https') or not allowed or ip.version!=4 or not port or u.username or u.password or u.path not in ('','/') or u.query or u.fragment: raise ValueError()
        if str(ip)==os.environ.get('MANAGER_HOST_IP','') and port in (int(os.environ.get('MANAGER_PORT','8080')),8080,8081,20241): raise ValueError()
        return f'{u.scheme}://{ip}:{port}'
    except (ValueError,TypeError): raise Error('Use HTTP(S), a private IPv4 address and an explicit port (e.g. http://192.168.1.123:8096).') from None

def zones(token):
    return [{'id':z['id'],'name':z['name'],'account':z['account']['id'],'status':z.get('status')} for z in pages(token,'/zones')]
def route_zone(s,host):
    zz=[z for z in zones(s['token']) if z['account']==s['account'] and z['status']=='active' and host.endswith('.'+z['name'])]
    if not zz: raise Error('Hostname must be a subdomain of an active domain in the selected account.')
    z=max(zz,key=lambda x:len(x['name']))
    if '.' in host[:-(len(z['name'])+1)]: raise Error('Use a single-level subdomain for standard Cloudflare TLS coverage.')
    return z

def lookup_dns(s,z,host): return call(s,'GET','/zones/'+z+'/dns_records',q={'name':host,'per_page':100}) or []
def dns_path(z,id=None): return '/zones/'+z+'/dns_records'+('/'+id if id else '')
def access_path(s,id=None): return account(s)+'/access/apps'+('/'+id if id else '')
def make_access(s,host,emails):
    return call(s,'POST',access_path(s),{'name':'Tunnel Manager · '+host,'type':'self_hosted','domain':host,'session_duration':'24h','auto_redirect_to_identity':False})
def verify_policy(s,r):
    pol=call(s,'GET',access_path(s,r['access_id'])+'/policies') or []
    if len(pol)!=1 or pol[0].get('decision')!='allow': raise Error('Expected exactly one Access allow policy.')
    inc=pol[0].get('include') or []
    if any(set(i)!= {'email'} for i in inc) or {i['email'].get('email','').lower() for i in inc}!=set(r['emails']): raise Error('Access email allowlist differs; refusing to publish.')
    return pol[0]
def get_team(s):
    org=call(s,'GET',account(s)+'/access/organizations') or {}
    auth=str(org.get('auth_domain','')).removeprefix('https://').rstrip('/')
    if not re.fullmatch(r'[a-z0-9-]+\.cloudflareaccess\.com',auth): raise Error('Create a Cloudflare Zero Trust organization first (team name).')
    return auth.split('.')[0]
def emails_for(b):
    emails=list(dict.fromkeys(x.strip().lower() for x in str(b.get('emails','')).replace('\n',',').split(',') if x.strip()))
    if not emails or len(emails)>30 or any(not re.fullmatch(r'[^\s@,]+@[^\s@,]+\.[^\s@,]+',e) for e in emails): raise Error('Enter 1–30 valid allowed email addresses.')
    return emails

def validate_route(s,b):
    host=str(b.get('hostname','')).strip().lower(); name=str(b.get('name','')).strip()[:80]
    if len(host)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in host.split('.')): raise Error('Invalid hostname.')
    if not name: raise Error('Enter a service name.')
    service=origin(b.get('service','')); z=route_zone(s,host); mode=b.get('access')
    if mode not in ('email','public'): raise Error('Choose an access mode.')
    if mode=='public' and b.get('confirm_public') is not True: raise Error('Confirm that this service may be accessible to anyone.')

    return {'name':name,'hostname':host,'service':service,'zone':z['id'],'access':mode,'emails':emails_for(b) if mode=='email' else [],'enabled':True,'origin_tls_name':str(b.get('origin_tls_name','')).strip()[:253]}

FALLBACK_SERVICE='http://127.0.0.1:8081'
LEGACY_HTML='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Temporarily unavailable</title><style>body{font:16px system-ui,sans-serif;background:#fff;color:#20252c;margin:0;min-height:100vh;display:grid;place-items:center}main{max-width:36rem;padding:2rem}h1{font-size:1.7rem;letter-spacing:-.03em}p{color:#606976;line-height:1.6}</style></head><body><main><h1>Temporarily unavailable</h1><p>This service is currently paused. Please check back later.</p></main></body></html>'
DEFAULT_HTML='<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Temporarily unavailable</title>\n  <style>\n    body { font: 16px system-ui, sans-serif; background: #fff;\n           color: #20252c; margin: 0; min-height: 100vh;\n           display: grid; place-items: center; }\n    main { max-width: 36rem; padding: 2rem; }\n    h1 { font-size: 1.7rem; letter-spacing: -.03em; }\n    p { color: #606976; line-height: 1.6; }\n  </style>\n</head>\n<body>\n  <main>\n    <h1>Temporarily unavailable</h1>\n    <p>This service is currently paused. Please check back later.</p>\n  </main>\n</body>\n</html>'

def fallback(s):
    f={'enabled':False,'mode':'html','target':'','html':DEFAULT_HTML,**s.get('fallback',{})}
    if f['html']==LEGACY_HTML: f['html']=DEFAULT_HTML
    return f
def host_ok(h):
    return len(h)<=253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in h.split('.'))
def redirect_url(v):
    v=v.strip()
    if '://' not in v: v='https://'+v
    try:
        if len(v)>2048 or any(ord(ch)<33 or ord(ch)>126 or ch=='\\' for ch in v): raise ValueError()
        u=urlsplit(v); h=u.hostname or ''; port=u.port
        if u.scheme not in ('http','https') or not h or u.username is not None or u.password is not None or not (port is None or 1<=port<=65535): raise ValueError()
        try: ipaddress.ip_address(h)
        except ValueError:
            if not host_ok(h) or '.' not in h: raise ValueError()
        if h.endswith('.cfargotunnel.com'): raise ValueError()
        return v
    except (ValueError,TypeError): raise Error('Enter a valid HTTP(S) website or IP URL without credentials.') from None

def check_fallback_conflict(s,f):
    if not f['enabled']: return
    rr=s.get('routes',[])
    if f['mode']=='redirect':
        h=(urlsplit(f['target']).hostname or '').rstrip('.').lower()
        if any(h==r['hostname'] for r in rr): raise Error('Redirect target is a managed hostname; this could create a loop.')
    if f['mode']=='origin':
        u=urlsplit(f['target'])
        if any((urlsplit(r['service']).hostname,urlsplit(r['service']).port)==(u.hostname,u.port) for r in rr): raise Error('Fallback origin must be different from every managed service.')

def validate_fallback(s,b):
    f=fallback(s)
    if not isinstance(b.get('enabled'),bool): raise Error('Choose whether fallback is enabled.')
    f['enabled']=b['enabled']; f['mode']=b.get('mode',f['mode'])
    if f['mode'] not in ('redirect','html','origin'): raise Error('Invalid fallback mode.')
    html=b.get('html',f['html']); target=b.get('target',f['target'])
    if not isinstance(html,str) or len(html.encode())>32768: raise Error('HTML must be at most 32 KiB.')
    if not isinstance(target,str) or len(target)>2048: raise Error('Invalid fallback destination.')
    f['html']=html; f['target']=target.strip()
    if f['mode']=='html' and f['enabled'] and not html.strip(): raise Error('Enter or upload an HTML page.')
    if f['mode']=='redirect' and (f['enabled'] or f['target']): f['target']=redirect_url(f['target'])
    if f['mode']=='origin' and (f['enabled'] or f['target']): f['target']=origin(f['target'])
    check_fallback_conflict(s,f)
    return f

def ingress(r,s=None):
    f=fallback(s or {}); active=r['enabled']; opts={}
    service=r['service'] if active else 'http_status:404'
    if active and r.get('origin_tls_name'): opts['originServerName']=r['origin_tls_name']
    if not active and f['enabled']:
        service=f['target'] if f['mode']=='origin' else FALLBACK_SERVICE
        if f['mode']!='origin': opts['httpHostHeader']=r['hostname']
    if not active and not f['enabled'] and r.get('origin_tls_name'): opts['originServerName']=r['origin_tls_name']
    if r.get('access')=='email' and (active or f['enabled']):
        opts['access']={'required':True,'teamName':r['team'],'audTag':[r['aud']]}
    return {'hostname':r['hostname'],'service':service,'originRequest':opts}

def canonical_rule(r):
    r=copy.deepcopy(r)
    if not r.get('originRequest'): r.pop('originRequest',None)
    if not r.get('path'): r.pop('path',None)
    return r

def canonical_rules(c): return [canonical_rule(r) for r in rules(c)]
def owned_rule(s,c,r):
    matches=[x for x in rules(c) if x.get('hostname')==r['hostname']]
    if len(matches)!=1 or canonical_rule(matches[0])!=canonical_rule(ingress(r,s)): raise Error('Remote ingress changed or is missing for '+r['hostname']+'. Refusing to overwrite; inspect Cloudflare.')

def check_dns(s,r,allow_missing=False):
    records=lookup_dns(s,r['zone'],r['hostname'])
    if allow_missing and not records: return records
    if len(records)!=1 or records[0]['id']!=r['dns_id'] or records[0].get('type')!='CNAME' or records[0].get('content','').rstrip('.')!=s['tunnel']+'.cfargotunnel.com' or records[0].get('proxied') is not True: raise Error('DNS ownership changed for '+r['hostname']+'; refusing to modify.')
    return records

def check_access(s,r):
    if r['access']!='email': return
    a=call(s,'GET',access_path(s,r['access_id']))
    if not a or a.get('domain')!=r['hostname'] or a.get('aud')!=r['aud']: raise Error('Access application missing or changed for '+r['hostname']+'.')
    verify_policy(s,r)

def replace_owned(c,r,s):
    c=copy.deepcopy(c)
    c['ingress']=[ingress(r,s) if x.get('hostname')==r['hostname'] and not x.get('path') else x for x in rules(c)]
    return c

def pending_path(): return DATA/'pending.json'
def recover(s):
    if not pending_path().exists(): return
    j=json.loads(pending_path().read_text())
    try: remote=canonical_rules(config(s))
    except Exception as e: raise Pending('Waiting for Cloudflare to confirm the change.') from e
    if remote==j['after']:
        s['routes']=j['routes']; s['fallback']=j['fallback']; save(s); pending_path().unlink(); event('Route update confirmed'); return True
    if remote==j['before']:
        if time.time()-j['time']<120: raise Pending('Waiting for Cloudflare to confirm the change.')
        raise Pending('Cloudflare still reports the previous configuration. Rechecking; no update will be resent automatically.')
    raise Conflict('Cloudflare ingress differs from both expected states. Inspect remote rules before making further changes.')

def commit_rules(s,new,c,target):
    before,after=canonical_rules(c),canonical_rules(target)
    if before==after:
        s.update(new); save(s); return
    if canonical_rules(config(s))!=before: raise Error('Cloudflare ingress changed during validation; retry after refreshing.')
    j={'before':before,'after':after,'routes':new.get('routes',[]),'fallback':fallback(new),'time':time.time()}
    write_json('pending.json',j)
    try: put(s,target)
    except Exception: event('Cloudflare write response not confirmed; checking configuration')
    recover(s)

def update_fallback(s,b):
    f=validate_fallback(s,b); new=copy.deepcopy(s); new['fallback']=f
    c=config(s); target=copy.deepcopy(c)
    for r in s.get('routes',[]):
        if r['enabled']: continue
        owned_rule(s,c,r); check_dns(s,r)
        if f['enabled']: check_access(s,r)
        target=replace_owned(target,r,new)
    commit_rules(s,new,c,target); event('Paused-route fallback '+('enabled' if f['enabled'] else 'disabled'))
    return {'ok':True}

def create_route(s,b):
    r=validate_route(s,b); host=r['hostname']; c=config(s)
    check_fallback_conflict({**s,'routes':s.get('routes',[])+[r]},fallback(s))
    if any(x.get('hostname')==host for x in rules(c)) or lookup_dns(s,r['zone'],host): raise Error('Hostname already has a tunnel rule or DNS record. Nothing overwritten.')

    if r['access']=='email':
        r['team']=get_team(s)
        apps=pages(s['token'],access_path(s))
        if any(a.get('domain')==host or any(d.get('uri')==host for d in (a.get('destinations') or []) if isinstance(d,dict)) for a in apps): raise Error('An Access app already exists for this hostname. Nothing overwritten.')
    r['id']=secrets.token_hex(8); r['access_id']=None; r['dns_id']=None
    try:
        if r['access']=='email':
            a=make_access(s,host,r['emails']); r['access_id']=a['id']
            r['aud']=a.get('aud')
            if not r['aud']: raise Error('Access application has no audience tag.')
            call(s,'POST',access_path(s,a['id'])+'/policies',{'name':'Allowed emails','decision':'allow','precedence':1,'include':[{'email':{'email':e}} for e in r['emails']]})
            verify_policy(s,r)
        put(s,set_rule(c,host,ingress(r)))
        d=call(s,'POST',dns_path(r['zone']),{'type':'CNAME','name':host,'content':s['tunnel']+'.cfargotunnel.com','proxied':True,'ttl':1}); r['dns_id']=d['id']
    except Exception as e:

        try: put(s,set_rule(config(s),host,None))
        except Exception: event('Rollback could not remove ingress for '+host)
        event('Creation failed for '+host+'; inspect Cloudflare for leftover Access/DNS records.')
        raise Error(str(e)+' — check Cloudflare for partial resources before retrying.') from None
    s.setdefault('routes',[]).append(r); save(s); event('Published '+host); return r

def modify(s,id,b,action):
    r=next((x for x in s.get('routes',[]) if x['id']==id),None)
    if not r: raise Error('Route not found.')
    c=config(s); owned_rule(s,c,r); host=r['hostname']; records=check_dns(s,r,action=='delete' and not r['enabled'])
    if action=='delete':
        if r['enabled']:
            modify(s,id,{'enabled':False},'toggle')
            r=next(x for x in s['routes'] if x['id']==id)
        if records: call(s,'DELETE',dns_path(r['zone'],r['dns_id']))
        latest=config(s); owned_rule(s,latest,r); put(s,set_rule(latest,host,None))
        if r.get('access_id'):
            try: call(s,'DELETE',access_path(s,r['access_id']))
            except Error: event('Access app remains for '+host+'; remove manually if desired.')
        s['routes'].remove(r); save(s); event('Deleted '+host); return
    new=copy.deepcopy(s); n=next(x for x in new['routes'] if x['id']==id)
    if action=='toggle':
        desired=b.get('enabled',not r['enabled'])
        if not isinstance(desired,bool): raise Error('Invalid route state.')
        if desired==r['enabled']: return
        n['enabled']=desired
    elif action=='edit':
        n['name']=str(b.get('name','')).strip()[:80]
        if not n['name']: raise Error('Enter a name.')
        n['service']=origin(b.get('service','')); n['origin_tls_name']=str(b.get('origin_tls_name','')).strip()[:253]
    check_fallback_conflict(new,fallback(new))
    if n['enabled'] or fallback(new)['enabled']: check_access(s,n)
    commit_rules(s,new,c,replace_owned(c,n,new)); event(action.title()+' '+host)

def private_routes(s):
    return [r for r in pages(s['token'],account(s)+'/teamnet/routes',{'is_deleted':'false'}) if r.get('tunnel_id')==s['tunnel']]
def private_add(s,b):
    ip=ipaddress.ip_address(urlsplit(origin('http://'+str(b.get('ip',''))+':80')).hostname)
    if b.get('confirm') is not True: raise Error('Confirm private network access and configure WARP enrollment/Gateway policies first.')
    r=call(s,'POST',account(s)+'/teamnet/routes',{'network':str(ip)+'/32','tunnel_id':s['tunnel'],'comment':'Tunnel Manager · '+str(b.get('name',''))[:80]}); event('Added private route '+str(ip)); return r

def probe(service):
    service=origin(service); u=urlsplit(service); start=time.monotonic()
    try:
        with OPENER.open(Request(service,method='GET',headers={'User-Agent':'TunnelManager health check'}),timeout=4) as r: status=r.status
    except HTTPError as e: status=e.code
    except Exception as e: return {'ok':False,'detail':str(e)[:180]}
    return {'ok':True,'detail':'HTTP '+str(status),'ms':round((time.monotonic()-start)*1000)}
def discover(ip):
    ip=urlsplit(origin('http://'+ip+':80')).hostname
    def check(p):
        try:
            with socket.create_connection((ip,p),timeout=.65): return p
        except OSError: return None
    with ThreadPoolExecutor(max_workers=10) as ex: return [p for p in ex.map(check,[80,443,3000,5000,8000,8080,8096,8123,8443,8920,9000,9443]) if p]

def connector_ready():
    try:
        with OPENER.open('http://127.0.0.1:20241/ready',timeout=1) as r: return r.status==200
    except Exception: return False

def supervise():
    global CHILD
    current=None
    while not STOP.is_set():
        try:
            s=load(); token=s.get('connector_token'); desired=token if s.get('run_connector',True) else None
            if CHILD and (CHILD.poll() is not None or desired!=current):
                if CHILD.poll() is None:
                    CHILD.terminate()
                    try: CHILD.wait(timeout=12)
                    except subprocess.TimeoutExpired: CHILD.kill(); CHILD.wait(timeout=3)
                CHILD=None; current=None
            if desired and not CHILD:
                DATA.mkdir(parents=True,exist_ok=True); p=DATA/'connector.token'; fd=os.open(p,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
                with os.fdopen(fd,'w') as f: f.write(desired)
                CHILD=subprocess.Popen(['cloudflared','tunnel','--no-autoupdate','--metrics','127.0.0.1:20241','run','--token-file',str(p)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
                current=desired; event('Connector started')
                def reader(proc,secret):
                    for line in proc.stdout: LOG.append(line.strip().replace(secret,'[redacted]')[:500])
                threading.Thread(target=reader,args=(CHILD,desired),daemon=True).start()
        except Exception as e: event('Connector supervisor: '+str(e)[:200])
        STOP.wait(5)
    if CHILD and CHILD.poll() is None:
        CHILD.terminate()
        try: CHILD.wait(timeout=12)
        except subprocess.TimeoutExpired: CHILD.kill()

def api(path,b):
    with LOCK:
        s=load(); recovery_error=''; recovery_pending=False
        if pending_path().exists():
            try: recover(s)
            except Pending as e: recovery_error=str(e); recovery_pending=True
            except Exception as e: recovery_error=str(e)[:500]
        if path=='/api/status':
            pending_ids=[]
            if pending_path().exists():
                j=json.loads(pending_path().read_text()); current={r['id']:r for r in s.get('routes',[])}
                pending_ids=[r['id'] for r in j['routes'] if current.get(r['id'])!=r or (not r['enabled'] and fallback(s)!=fallback(j))]
            return {'configured':bool(s.get('tunnel')),'connector':connector_ready(),'connector_running':bool(CHILD and CHILD.poll() is None),'run_connector':s.get('run_connector',True),'tunnel':s.get('tunnel'),'tunnel_name':s.get('tunnel_name'),'account':s.get('account'),'zones':s.get('zones',[]),'routes':s.get('routes',[]),'logs':list(LOG)[-80:],'fallback':{k:v for k,v in fallback(s).items() if k!='html'},'recovery_error':recovery_error,'recovery_pending':recovery_pending,'pending_routes':pending_ids,'recovery_can_clear':bool(recovery_pending and 'previous configuration' in recovery_error)}
        if recovery_error and path not in ('/api/remote','/api/fallback/get','/api/recovery/recheck','/api/recovery/discard'): raise Error(recovery_error)
        if path=='/api/recovery/recheck': return {'pending':recovery_pending,'error':recovery_error}
        if path=='/api/recovery/discard':
            if not pending_path().exists(): return {'ok':True}
            j=json.loads(pending_path().read_text())
            if time.time()-j['time']<120 or canonical_rules(config(s))!=j['before']: raise Error('Cannot clear: the previous configuration has not been verified after the confirmation window.')
            pending_path().unlink(); event('Unconfirmed update cleared by administrator'); return {'ok':True}
        if path=='/api/discover-account':
            token=str(b.get('token','')).strip()
            if not token or len(token)>500: raise Error('Enter a Cloudflare API token.')
            zz=zones(token); accounts={z['account'] for z in zz}; result=[]
            for a in accounts:
                tt=pages(token,'/accounts/'+a+'/cfd_tunnel',{'is_deleted':'false'})
                result.extend({'id':t['id'],'name':t['name'],'account':a,'status':t.get('status'),'remote':t.get('config_src')=='cloudflare' or t.get('remote_config') is True} for t in tt)
            return {'zones':zz,'tunnels':result}
        if path=='/api/setup':
            if s.get('tunnel'): raise Error('Already configured. Reinstallation requires a separate data volume.')
            token=str(b.get('token','')).strip(); a=valid_id(b.get('account')); zz=[z for z in zones(token) if z['account']==a and z['status']=='active']
            if not zz: raise Error('No active domains found in this account.')
            existing=b.get('tunnel'); name=str(b.get('name','home-tunnel')).strip()[:80]
            if existing:
                tid=valid_id(existing); t=cf(token,'GET','/accounts/'+a+'/cfd_tunnel/'+tid)
                if t.get('config_src')!='cloudflare' and t.get('remote_config') is not True: raise Error('Choose a remotely managed tunnel.')
            else:
                if not name: raise Error('Enter a tunnel name.')
                t=cf(token,'POST','/accounts/'+a+'/cfd_tunnel',{'name':name,'config_src':'cloudflare'}); tid=t['id']
            ct=t.get('token') or cf(token,'GET','/accounts/'+a+'/cfd_tunnel/'+tid+'/token')
            s={'token':token,'account':a,'tunnel':tid,'tunnel_name':t.get('name',name),'connector_token':ct,'zones':[z for z in zones(token) if z['account']==a],'routes':[],'run_connector':True}
            if not existing: put(s,{'ingress':[{'service':'http_status:404'}]})
            save(s)
            event('Tunnel configured'); return {'ok':True}
        if path=='/api/probe': return probe(b.get('service',''))
        if path=='/api/discover-lan': return {'ports':discover(str(b.get('ip','')))}
        if not s.get('tunnel'): raise Error('Complete setup first.')
        if path=='/api/remote':
            c=config(s); t=call(s,'GET',tunnel(s)); owned={r['hostname'] for r in s.get('routes',[])}
            return {'status':t.get('status'),'unmanaged':[r for r in rules(c) if r.get('hostname') and (r['hostname'] not in owned or r.get('path'))]}
        if path=='/api/refresh-zones': s['zones']=[z for z in zones(s['token']) if z['account']==s['account']]; save(s); return s['zones']
        if path=='/api/fallback/get': return fallback(s)
        if path=='/api/fallback/save':
            try: return update_fallback(s,b)
            except Pending: return {'pending':True}
        if path=='/api/route/create': return create_route(s,b)
        if path in ('/api/route/edit','/api/route/delete','/api/route/toggle'):
            try: modify(s,b.get('id'),b,path.rsplit('/',1)[-1]); return {'ok':True}
            except Pending:
                if path=='/api/route/delete': raise Error('Pause confirmation pending. Deletion has not completed; check the route before retrying.')
                return {'pending':True}
        if path=='/api/private/list': return private_routes(s)
        if path=='/api/private/add': return private_add(s,b)
        if path=='/api/private/delete':
            id=valid_id(b.get('id'))
            if not any(r.get('id')==id for r in private_routes(s)): raise Error('Private route does not belong to this tunnel.')
            call(s,'DELETE',account(s)+'/teamnet/routes/'+id); event('Private route removed'); return {'ok':True}
        if path=='/api/connector': s['run_connector']=bool(b.get('run')); save(s); return {'ok':True}
        if path=='/api/backup': return {'version':1,'tunnel':s['tunnel'],'account':s['account'],'routes':s.get('routes',[]),'fallback':fallback(s),'config':{'ingress':[ingress(r,s) for r in s.get('routes',[])]+[{'service':'http_status:404'}]}}
        if path=='/api/verify-public':
            r=next((r for r in s.get('routes',[]) if r['id']==b.get('id')),None)
            if not r: raise Error('Route not found.')
            marker=None
            try:
                with OPENER.open(Request('https://'+r['hostname'],method='GET'),timeout=8) as resp: code=resp.status; marker=resp.headers.get('X-Tunnel-Manager-Fallback')
            except HTTPError as e: code=e.code; marker=e.headers.get('X-Tunnel-Manager-Fallback')
            except Exception as e: return {'ok':False,'detail':str(e)[:180]}
            f=fallback(s)
            if not r['enabled'] and f['enabled'] and f['mode']=='html' and code==503 and marker=='html': return {'ok':True,'detail':'HTTP 503 — custom paused page'}
            if not r['enabled'] and not f['enabled'] and code==404: return {'ok':True,'detail':'HTTP 404 — route paused'}
            return {'ok':200<=code<400 or code in (401,403),'detail':f'Public HTTPS returned {code}; verify application/login in browser.'}
        raise Error('Unknown endpoint.')

class Handler(BaseHTTPRequestHandler):
    server_version='TunnelManager'; sys_version=''
    def log_message(self,*args): pass
    def respond(self,code,data,typ='application/json; charset=utf-8',cookie=None):
        data=json.dumps(data).encode() if isinstance(data,(dict,list)) else data
        self.send_response(code); self.send_header('Content-Type',typ); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie: self.send_header('Set-Cookie',cookie)
        self.end_headers(); self.wfile.write(data)
    def session(self):
        c=SimpleCookie()
        try: c.load(self.headers.get('Cookie','')); sid=c['tm'].value
        except Exception: return None,None
        with LOCK:
            ss=SESSIONS.get(sid)
            if ss and ss[1]>time.time(): return sid,ss[0]
        return None,None
    def do_GET(self):
        path=urlsplit(self.path).path
        if path in ('/','/index.html'): self.respond(200,(STATIC/'index.html').read_bytes(),'text/html; charset=utf-8')
        elif path=='/health': self.respond(200,{'ok':True})
        elif path=='/api/session':
            _,csrf=self.session(); self.respond(200,{'authenticated':bool(csrf),'csrf':csrf})
        else: self.respond(404,{'error':'Not found'})
    def do_POST(self):
        path=urlsplit(self.path).path
        try:
            if self.headers.get('Content-Type','').split(';')[0]!='application/json': raise Error('JSON required.')
            if self.headers.get('Sec-Fetch-Site')=='cross-site': raise Error('Cross-site request denied.')
            if self.headers.get('Origin') and urlsplit(self.headers['Origin']).netloc!=self.headers.get('Host'): raise Error('Origin mismatch.')
            n=int(self.headers.get('Content-Length',0))
            if not 0<n<=(262144 if path=='/api/fallback/save' else 65536): raise Error('Invalid request size.')
            b=json.loads(self.rfile.read(n));
            if not isinstance(b,dict): raise Error('JSON object required.')
            if path=='/api/login':
                ip=self.client_address[0]; now=time.time()
                with LOCK:
                    a=[x for x in ATTEMPTS.get(ip,[]) if now-x<300]
                    if len(a)>=8: self.respond(429,{'error':'Too many attempts. Try again in five minutes.'}); return
                    if not hmac.compare_digest(str(b.get('password','')).encode(),PASSWORD.encode()): ATTEMPTS[ip]=a+[now]; self.respond(401,{'error':'Incorrect password.'}); return
                    ATTEMPTS.pop(ip,None); sid=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32); SESSIONS[sid]=(csrf,now+43200)
                    for k,v in list(SESSIONS.items()):
                        if v[1]<=now: SESSIONS.pop(k,None)
                self.respond(200,{'csrf':csrf},cookie='tm='+sid+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200'+('; Secure' if SECURE else '')); return
            sid,csrf=self.session()
            if not csrf or not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),csrf): self.respond(401,{'error':'Sign in again.'}); return
            if path=='/api/logout':
                with LOCK: SESSIONS.pop(sid,None)
                self.respond(200,{'ok':True},cookie='tm=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'); return
            self.respond(200,api(path,b) or {'ok':True})
        except (Error,ValueError,TypeError,KeyError) as e: self.respond(400,{'error':str(e)[:800]})
        except Exception as e: event('Internal error: '+type(e).__name__); self.respond(500,{'error':'Internal error; inspect server logs.'})

class FallbackHandler(BaseHTTPRequestHandler):
    server_version='TunnelManager'; sys_version=''
    def setup(self):
        super().setup(); self.connection.settimeout(10)
    def log_message(self,*args): pass
    def serve(self):
        status=404; body=b'Not found'; typ='text/plain; charset=utf-8'; location=None
        try:
            s=load(); f=fallback(s); host=self.headers.get('Host','').lower().rstrip('.')
            r=next((r for r in s.get('routes',[]) if r['hostname']==host and not r['enabled']),None)
            if not (r and f['enabled'] and f['mode'] in ('redirect','html')):
                try:
                    j=json.loads(pending_path().read_text()); candidate=fallback(j)
                    desired=next((r for r in j['routes'] if r['hostname']==host and not r['enabled']),None)
                    if desired and candidate['enabled'] and candidate['mode'] in ('redirect','html') and any(x['hostname']==host for x in s.get('routes',[])):
                        r,f=desired,candidate
                except FileNotFoundError: pass
            if r and f['enabled'] and f['mode'] in ('redirect','html'):
                if self.command not in ('GET','HEAD'): status=503; body=b'Service paused'
                elif f['mode']=='redirect': status=302; location=redirect_url(f['target']); body=b'Service paused'
                else: status=503; typ='text/html; charset=utf-8'; body=f['html'].encode()
        except Exception: status=503; body=b'Service unavailable'; typ='text/plain; charset=utf-8'; location=None
        self.send_response(status)
        if location: self.send_header('Location',location)
        if typ.startswith('text/html'): self.send_header('X-Tunnel-Manager-Fallback','html')
        self.send_header('Content-Type',typ); self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store, private, max-age=0'); self.send_header('Pragma','no-cache')
        self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY'); self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command!='HEAD': self.wfile.write(body)
    do_GET=do_HEAD=do_POST=do_PUT=do_PATCH=do_DELETE=do_OPTIONS=serve

def main():
    if len(PASSWORD)<16: sys.exit('ADMIN_PASSWORD must be at least 16 characters; run install.sh.')
    os.umask(0o077); DATA.mkdir(parents=True,exist_ok=True)
    server=ThreadingHTTPServer(('0.0.0.0',8080),Handler)
    paused_server=ThreadingHTTPServer(('127.0.0.1',8081),FallbackHandler)
    threading.Thread(target=paused_server.serve_forever,daemon=True).start()
    supervisor=threading.Thread(target=supervise,daemon=True); supervisor.start()
    def stop(*_): STOP.set(); threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    try: server.serve_forever()
    finally: STOP.set(); paused_server.shutdown(); paused_server.server_close(); server.server_close(); supervisor.join(timeout=18)
if __name__=='__main__': main()
