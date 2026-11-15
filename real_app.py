"""Public Is this real entry point. Recorded replays never call a provider."""
import asyncio
import hashlib
import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from fastapi.exceptions import RequestValidationError
from real_check import MeteredExa, run, configure_exa_key, finish, log_failure, web_url, line
from response_quality import local_facts, pressure_findings
from wording import recording

ROOT=Path(__file__).parent
if os.getenv('EXA_ENV_FILE') and not os.getenv('VERCEL'):
    load_dotenv(os.environ['EXA_ENV_FILE'],override=False)
    configure_exa_key()
app=FastAPI(title='Is this real?',docs_url=None,redoc_url=None)
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
@app.exception_handler(RequestValidationError)
async def invalid_input(request,error):
    return JSONResponse({'detail':'Use a link or redacted message shorter than 18,000 characters.'},status_code=422)

visitors=defaultdict(deque)
client=None


def cases():
    path=ROOT/'runtime/real-cases.json'
    return [recording(c,finish) for c in json.loads(path.read_text())] if path.exists() else []


def live():
    return bool(os.getenv('EXA_API_KEY')) and os.getenv('REAL_LIVE_ENABLED','0')=='1' and os.getenv('REAL_KILL_SWITCH','0')!='1'


@app.middleware('http')
async def boundary(request,call_next):
    if request.method=='POST' and request.headers.get('origin') and request.headers['origin']!=str(request.base_url).rstrip('/'):
        return JSONResponse({'detail':'Cross-origin requests are disabled.'},status_code=403)
    response=await call_next(request)
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    return response


@app.get('/')
def home():return FileResponse(ROOT/'static/real.html')


@app.get('/api/status')
def status():return {'live_enabled':live(),'cases':[{'id':c['id'],'title':c['title'],'recorded_at':c['recorded_at'],'source':c['input']} for c in cases()]}


class Check(BaseModel):
    value:str=Field(default='',max_length=18000)
    case_id:str=Field(default='',max_length=80)
    consent:bool=False


@app.post('/api/check')
async def check(body:Check,request:Request):
    recorded=next((c for c in cases() if c['id']==body.case_id),None)
    if body.case_id and not recorded:raise HTTPException(404,'Recorded case not found.')
    if recorded:
        async def replay():
            yield json.dumps({'type':'recording','data':'Recorded '+recorded['recorded_at']+'. Replayed for free; not a live check.'})+'\n'
            previous=0
            for item in recorded['events']:
                # Keep sequence with lightly compressed, visibly labelled replay pacing.
                await asyncio.sleep(min(.4,max(0,item['at']-previous)))
                previous=item['at']
                yield json.dumps(item['event'])+'\n'
        return StreamingResponse(replay(),media_type='application/x-ndjson')
    if not live() and web_url(body.value.strip()):raise HTTPException(503,'Live web checks are off. No web search ran; try a dated recorded case.')
    if not body.consent:raise HTTPException(400,'Confirm that this is public or redacted text before sending it to Exa.')
    if not body.value.strip():raise HTTPException(400,'Paste a link or message first.')
    # Best effort only: instances and restarts do not share this visitor window.
    peer=request.headers.get('x-forwarded-for','').split(',')[0] if os.getenv('VERCEL') else (request.client.host if request.client else 'unknown')
    key=hashlib.sha256(peer.encode()).hexdigest()
    current=time.monotonic()
    if len(visitors)>4096:
        for old in list(visitors):
            if not visitors[old] or current-visitors[old][-1]>60:visitors.pop(old,None)
        if len(visitors)>4096:raise HTTPException(429,'The live service is busy. Try a recorded case.')
    window=visitors[key]
    while window and current-window[0]>60:window.popleft()
    if len(window)>=3:raise HTTPException(429,'Three live checks per minute. Please wait or use a recording.')
    window.append(current)
    global client
    if client is None and live():client=MeteredExa()
    async def stream():
        try:
            async for event in run(client,body.value.strip()):yield json.dumps(event)+'\n'
        except Exception as error:
            log_failure('response stream',error)
            url=web_url(body.value.strip())
            facts=local_facts('' if url else body.value,url)
            facts['input_kind']='link' if url else 'message'
            rows=[] if url else pressure_findings(body.value.strip())
            rows.append(line('Source','Page reading did not finish.',polarity='could not check'))
            done=finish(rows,facts,False,time.monotonic()-current)
            for row in done['findings']+done['unavailable']:
                yield json.dumps({'type':'evidence','data':row})+'\n'
            yield json.dumps({'type':'done','data':done})+'\n'
    return StreamingResponse(stream(),media_type='application/x-ndjson')
