"""Nemotron and cached public Exa evidence. No alternate model provider."""
from collections import deque
import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
import httpx
from privacy import profile_page, strip_contacts, careers_index, ats_host, has_contact

REQUIRED = ('EXA_API_KEY', 'NEMOTRON_BASE_URL', 'NEMOTRON_API_KEY', 'NEMOTRON_MODEL')
MODEL_TIMEOUT = 90
AI_TIMEOUT = 'The AI service timed out after 90 seconds. Try again in a minute.'
CACHE = Path(__file__).parent / '.cache'


def missing_keys():
    return [k for k in REQUIRED if not os.getenv(k)]


class ProviderError(Exception):
    pass


class Clients:
    def __init__(self, transport=None, cache=CACHE):
        self.transport, self.cache = transport, cache
        self.inflight=asyncio.Semaphore(8)
        self.request_counts={}
        self.funnel=deque(maxlen=2048)

    async def post(self, provider, url, headers, body):
        for attempt in range(2 if provider=='Nemotron' else 1):
            try:
                async with self.inflight:
                    if provider=='Exa' and int(os.getenv('EXA_CALL_LIMIT','0')) and self.request_counts.get('Exa',0)>=int(os.environ['EXA_CALL_LIMIT']):
                        raise ProviderError('The local Exa call budget has been reached.')
                    self.request_counts[provider]=self.request_counts.get(provider,0)+1
                    async with httpx.AsyncClient(timeout=MODEL_TIMEOUT if provider=='Nemotron' else 18, transport=self.transport, follow_redirects=False) as client:
                        response = await client.post(url, headers=headers, json=body)
                        response.raise_for_status()
                        return response.json()
            except (httpx.HTTPError, ValueError) as error:
                if provider=='Nemotron':
                    if isinstance(error,httpx.HTTPStatusError) and error.response.status_code not in (502,503):
                        raise ProviderError(f'The AI service returned HTTP {error.response.status_code}. Check endpoint and sponsor quota.') from None
                    if isinstance(error,httpx.TimeoutException):
                        raise ProviderError(AI_TIMEOUT) from None
                    if attempt==0:
                        await asyncio.sleep(0.3)
                        continue
                    raise ProviderError('The AI service did not respond. Try again in a minute.') from None
                logging.getLogger(__name__).warning('Exa transport failure: %s',type(error).__name__)
                if isinstance(error,httpx.HTTPStatusError):
                    raise ProviderError(f'{provider} returned HTTP {error.response.status_code}. Check endpoint and sponsor quota.') from None
                raise ProviderError(f'{provider} request failed. No result was substituted.') from None

    async def public_page(self, url, validate_url):
        from public_pages import fetch_public
        return await fetch_public(url,validate_url,transport=self.transport)

    async def brain(self, messages, tools=None, schema=None):
        body = dict(model=os.environ['NEMOTRON_MODEL'], messages=messages, temperature=0, max_tokens=1400 if schema else 700,
                    chat_template_kwargs={'enable_thinking':False})
        if schema:
            body['response_format']={'type':'json_schema','json_schema':{'name':'retained_output','schema':schema,'strict':True}}
        if tools:
            body.update(tools=tools, tool_choice='auto')
        result = await self.post('Nemotron', os.environ['NEMOTRON_BASE_URL'].rstrip('/') + '/chat/completions',
                                 {'Authorization': 'Bearer ' + os.environ['NEMOTRON_API_KEY']}, body)
        try:
            return result['choices'][0]['message']
        except (KeyError, IndexError, TypeError):
            raise ProviderError('The AI service did not respond. Try again in a minute.') from None

    async def exa(self, endpoint, body):
        key = hashlib.sha256(json.dumps([endpoint, body], sort_keys=True).encode()).hexdigest()
        path = self.cache / (key + '.json') if self.cache and body.get('maxAgeHours')!=0 else None
        if path and path.exists() and time.time() - path.stat().st_mtime < 3600:
            cached=json.loads(path.read_text())
            if cached:
                safe=[strip_contacts(p) for p in cached if not profile_page(p)]
                if safe!=cached:path.write_text(json.dumps(safe))
                self.funnel.append(dict(stage='cache',readable=len(safe),privacy_dropped=len(cached)-len(safe)))
                return [p|{'from_cache':True} for p in safe]
        data = await self.post('Exa', 'https://api.exa.ai/' + endpoint,
                               {'x-api-key': os.environ['EXA_API_KEY']}, body)
        fetched = datetime.now(timezone.utc).isoformat()
        def flatten(rows):
            pages = []
            for row in rows:
                if row.get('text'):
                    pages.append(dict(url=row['url'], title=row.get('title') or row['url'],
                        text=row['text'][:max(4000,min(12000,(body.get('text') or {}).get('maxCharacters',4000)))], published_date=row.get('publishedDate'), fetched_at=fetched,
                        links=[u for u in (row.get('extras') or {}).get('links',[]) if isinstance(u,str) and not has_contact(u) and not profile_page(dict(url=u,title='',text='')) and (careers_index(dict(url=u,title='',text='')) or ats_host(u))][:30]))
                pages.extend(flatten(row.get('subpages') or []))
            return pages
        statuses={r.get('id'):r for r in data.get('statuses',[]) if isinstance(r,dict)}
        rows=[r for r in data.get('results',[]) if statuses.get(r.get('url'),{}).get('status')!='error']
        raw=flatten(rows)
        if endpoint=='contents' and body.get('maxAgeHours')==0:
            raw=[p|{'live_fetched':True} for p in raw]
        pages = [strip_contacts(p)|{'from_cache':False} for p in raw if not profile_page(p)]
        self.funnel.append(dict(stage=endpoint,raw=len(raw),privacy_dropped=len(raw)-len(pages),readable=len(pages)))
        if endpoint=='contents' and body.get('subpages') and len(pages)<=1:
            __import__('logging').getLogger(__name__).info('Exa Contents returned no readable subpages')
        if endpoint=='contents' and not pages:
            codes=sorted({str(r.get('error',{}).get('tag','unreadable')) for r in data.get('statuses',[]) if isinstance(r.get('error'),dict)})
            self.last_contents_reason='Exa Contents returned no readable text' + (': '+', '.join(codes) if codes else '.')
        if path and pages:
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps(pages))
        return pages

    async def search(self, query, domains=None, start=None, category=None, num_results=3, highlights=False):
        body = dict(query=query, type='auto', numResults=min(10,max(1,num_results)),
            contents={'text': {'maxCharacters': 4000}, 'maxAgeHours': 1})
        if highlights:body['contents']['highlights']=True
        if domains:
            body['includeDomains'] = domains
        if start:
            body['startPublishedDate'] = start
        if category:
            body['category'] = category
        return await self.exa('search', body)

    async def contents(self, url, subpages=0, subpage_targets=None, fresh=False):
        return await self.exa('contents', dict(urls=url if isinstance(url,list) else [url], text={'maxCharacters':12000 if fresh else 4000},
            maxAgeHours=0 if fresh else 1, livecrawlTimeout=2000, extras={'links':100}, subpages=subpages, subpageTarget=subpage_targets or ['careers','jobs','team']))
