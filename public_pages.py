"""Bounded public HTTPS fallback using only stdlib HTML parsing and httpx."""
import asyncio
import json
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
import httpx
from clients import ProviderError
from feed_jobs import canonical_job, posting_feed, posting_fields


class PageText(HTMLParser):
    def __init__(self):
        super().__init__();self.parts=[];self.skip=0;self.job_script=False;self.script=[];self.anchor=None
    def handle_starttag(self,tag,attrs):
        if tag=='a':
            self.anchor=dict(attrs).get('href')
        if tag in ('script','style','noscript'):
            self.skip+=1
            if tag=='script' and dict(attrs).get('type')=='application/ld+json':
                self.job_script=True;self.script=[]
    def handle_endtag(self,tag):
        if tag=='a':self.anchor=None
        if tag in ('script','style','noscript'):
            if self.job_script and tag=='script':
                try:
                    self.read_job(json.loads(''.join(self.script)))
                except ValueError:
                    pass
                self.job_script=False
            self.skip=max(0,self.skip-1)
    def read_job(self,value):
        if isinstance(value,list):
            for item in value:self.read_job(item)
        elif isinstance(value,dict):
            if value.get('@type')=='JobPosting':
                for key in ('title','description','datePosted','validThrough'):
                    if isinstance(value.get(key),str):
                        parser=PageText();parser.feed(value[key]);self.parts.extend(parser.parts)
            if '@graph' in value:self.read_job(value['@graph'])
    def handle_data(self,data):
        if self.job_script:self.script.append(data)
        if not self.skip and data.strip():
            target=self.anchor
            job_link=target and __import__('re').search(r'job|career|position|opening|vacanc',target,__import__('re').I)
            self.parts.append(f'[{data.strip()}]({target})' if job_link else data.strip())


async def _fetch_public(url, validate_url, transport=None):
    url=canonical_job(url)
    feed=posting_feed(url)
    async with httpx.AsyncClient(timeout=6,follow_redirects=False,transport=transport) as client:
        if feed:
            endpoint,kind,identifier=feed
            await asyncio.to_thread(validate_url,endpoint)
            response=await client.get(endpoint)
            if response.status_code!=200:raise ProviderError(f'Public posting feed returned HTTP {response.status_code}.')
            if len(response.content)>8_000_000:raise ProviderError('Public posting feed exceeds reading limit.')
            try:title,location,date,description=posting_fields(response.json(),kind,identifier)
            except (ValueError,KeyError,TypeError):raise ProviderError('Current public posting could not be confirmed.') from None
            parser=PageText();parser.feed(description)
            text='\n'.join([f'{title} / {location}', 'Apply now']+parser.parts)[:12000]
            return [dict(url=url,title=title,text=text,fetched_at=datetime.now(timezone.utc).isoformat(),published_date=date,retrieval='public posting API')]
        for _ in range(4):
            await asyncio.to_thread(validate_url,url)
            async with client.stream('GET',url,headers={'User-Agent':'Junction public job ad reader'}) as response:
                if response.is_redirect:
                    url=urljoin(url,response.headers.get('location',''))
                    continue
                if response.status_code!=200:
                    raise ProviderError(f'Public page fetch returned HTTP {response.status_code}.')
                if 'text/html' not in response.headers.get('content-type',''):
                    raise ProviderError('Public page fetch did not return HTML.')
                raw=bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw)>512_000:
                        raise ProviderError('Public page exceeds the 512 KB reading limit.')
                parser=PageText();parser.feed(raw.decode('utf-8',errors='replace'))
                text='\n'.join(parser.parts)[:12000]
                if len(text)<200:
                    raise ProviderError('Public page contains too little readable text; it may require JavaScript.')
                return [dict(url=url,title=url,text=text,fetched_at=datetime.now(timezone.utc).isoformat(),
                             published_date=None,retrieval='public HTTP',retrieval_note='Exa Contents returned no readable text; public HTML used.')]
    raise ProviderError('Public page exceeded the redirect limit.')


async def fetch_public(url, validate_url, transport=None):
    try:
        return await _fetch_public(url,validate_url,transport)
    except httpx.HTTPError:
        raise ProviderError('Public page fetch failed or timed out. No text was substituted.') from None
