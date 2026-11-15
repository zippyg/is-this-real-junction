"""Offline public API smoke, no keys or external connections."""
import asyncio,json,socket,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import httpx
from api.index import app
async def main():
 def blocked(*a,**k):raise AssertionError('Outbound connection attempted')
 socket.create_connection=blocked;socket.socket.connect=blocked
 async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as c:
  assert (await c.get('/')).status_code==200
  r=await c.post('/api/check',json={'value':'Pay a 75 euro activation fee today to start this job.','consent':True})
  assert r.status_code==200
  d=next(x['data'] for x in map(json.loads,r.text.splitlines()) if x['type']=='done')
  assert d['concerns'] and d['exa_calls']==0 and d['web_search_status']=='off'
  assert (await c.post('/api/check',json={'value':'https://example.org','consent':True})).status_code==503
 print('PASS: page200, message warnings without web search, link503 without key, zero outbound connections.')
asyncio.run(main())
