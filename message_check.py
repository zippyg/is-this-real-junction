"""Three bounded Exa queries for pasted messages. Retrieved text is data, never instructions."""
import asyncio
import os
import re
import time
from urllib.parse import urlsplit
from response_quality import local_facts,pressure_findings,readable,source_name,identity_evidence,registrable_domain
from real_check import finish,line,web_url,human_date,now,log_failure

FI_SOURCES=['vero.fi','poliisi.fi','kyberturvallisuuskeskus.fi','kkv.fi','finanssivalvonta.fi','posti.fi','tulli.fi']
BANK_SITES={'op':'op.fi','nordea':'nordea.fi','danske bank':'danskebank.fi','s-pankki':'s-pankki.fi'}
OTHER_SOURCES=['consumer.ftc.gov','ftc.gov','scamwatch.gov.au','actionfraud.police.uk','fca.org.uk','gov.uk','uspis.gov','cbp.gov','royalmail.com']


def message_facts(text):
    facts=local_facts(text);facts['input_kind']='message'
    if not facts['name']:
        names=re.search(r'\b(?i:at|from|on behalf of|employer is|company is|we are|I represent|työnantaja on|yritykseltä|yrityksessä|olemme|edustan)\s+([A-ZÅÄÖ][\w&\x27’-]*(?:\s+(?:[A-ZÅÄÖ][\w&\x27’-]*|of|and|the)){0,6})',text)
        prefix=re.match(r'^([A-ZÅÄÖ][\w&-]*(?:\s+[A-ZÅÄÖ][\w&-]*){0,4}):',text)
        banner=re.match(r'^([A-ZÅÄÖ][\w&-]*(?:\s+[A-ZÅÄÖ][\w&-]*){0,4})\s+(?i:security|fraud|account|turva|tili)',text)
        if names or prefix or banner:facts['name']=(names or prefix or banner)[1]
    emails=list(dict.fromkeys(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',text)))
    domains=list(dict.fromkeys(re.findall(r'(?i)(?<![\w@])(?:https?://)?(?:www\.)?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24})\b',text)))
    domains=list(dict.fromkeys([e.rsplit('@',1)[1] for e in emails]+domains))
    phones=list(dict.fromkeys(m[0].strip() for m in re.finditer(r'(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)',text)))
    sentences=re.split(r'(?<=[.!?])\s+|\n+',text)
    distinctive=next((s.strip() for s in sentences if 8<=len(s.split())<=40 and len(s)<=260),'')
    facts.update(contact_email=emails[0] if emails else '',contact_phone=phones[0] if phones else '',official_domain=domains[0] if domains else '',contact_emails=emails,contact_phones=phones,contact_domains=domains,distinctive_sentence=distinctive)
    return facts


def plan_queries(text,facts,signs):
    kinds={r['pressure_kind'] for r in signs};kind=facts['kind']
    finnish=bool(re.search(r'(?i)[äö]|\b(?:Finland|Finnish|Helsinki|Otaniemi|Kalevankatu|Posti|Vero|asunto|vuokra|pankki|paketti|Tikkurila)\b',text))
    bank_domain=BANK_SITES.get(facts['name'].casefold())
    if bank_domain and kinds & {'bank_access','link_login'}:
        topic='bank message and code requests';query=facts['name']+' huijausviesti pankkitunnukset linkki vahvistuskoodi';terms=r'huija|phish|kood|tunnus|link|code|bank'
    elif re.search(r'(?i)\b(?:tax|refund|Vero|veronpalaut\w*)\b',text) and kinds & {'bank_access','link_login','upfront_payment'}:
        topic='tax refund messages';query='Vero veronpalautus huijausviesti pankkitunnukset linkki' if finnish else 'tax authority refund phishing message banking codes link warning';terms=r'tax|refund|vero|pankkitunn|huija'
    elif kind=='parcel':
        topic='parcel fee messages' if signs else 'parcel collection'
        query=('paketti tulli posti käsittelymaksu huijaus pankkitunnukset' if signs else 'Posti paketin noutaminen noutokoodi ohje') if finnish else ('parcel customs handling fee link bank codes scam warning' if signs else 'postal service parcel collection pickup notice guidance')
        terms=r'paket|tulli|post[ia]|parcel|customs|delivery|postage'
    elif kind=='job' and kinds & {'upfront_payment','payment_for_job'}:
        topic='job advance fees';query='työtarjous ennakkomaksu koulutusmaksu huijaus' if finnish else 'job offer advance fee training fee gift cards scam warning';terms=r'job|work|employment|recruit|työ|rekry'
    elif kind=='rental' and kinds & {'upfront_payment','money_transfer','no_viewing'}:
        topic='rental deposit requests';query='vuokra asunto vuokravakuus ennakkomaksu huijaus näyttö ulkomailla' if finnish else 'rental scam deposit before viewing third party abroad account warning';terms=r'rent|landlord|deposit|vuokra|asunto|vakuus'
    elif 'bank_access' in kinds:
        topic='bank-code requests';query='pankkitunnukset huijaus älä luovuta' if finnish else 'bank login security codes request scam warning';terms=r'bank|code|pankki|tunnus'
    elif re.search(r'(?i)membership|gym|jäsen',text):
        topic='membership charges';query='jäsenyys jatkuva korttiveloitus kuluttaja ohje' if finnish else 'consumer membership recurring card payment guidance';terms=r'member|subscription|charge|jäsen|veloit'
    else:
        topic='checking an offer';query='tarjous viesti lähettäjä tarkistaminen huijaus ohje' if finnish else 'consumer verify offer sender message official guidance';terms=r'contact.{0,70}(?:company|organisation|person directly)|check.{0,70}(?:message|genuine)|(?:message|call).{0,70}(?:genuine|check)|verif.{0,70}(?:credential|sender|message)|tarkist|varmist'
    identity=facts['name'] or facts['official_domain'] or facts['contact_email'] or facts['contact_phone']
    identity_query='"'+identity+'" official website company register' if identity else ''
    if bank_domain and facts['contact_domains'] and kinds & {'bank_access','link_login'}:identity_query='"'+identity+'" official website kotisivu Wikipedia'
    return [dict(check='What others say',purpose='pattern',topic=topic,query=query,domains=[bank_domain] if bank_domain and kinds & {'bank_access','link_login'} else FI_SOURCES if finnish else OTHER_SOURCES,terms=terms),
            dict(check='Who is behind it',purpose='organisation',topic=identity,query=identity_query,domains=None),
            dict(check='Copies',purpose='copies',topic='the distinctive sentence',query='"'+facts['distinctive_sentence']+'"' if facts['distinctive_sentence'] else '',domains=None)]


def sentence(page,plan,facts):
    body=page.get('text') or ''
    candidates=[]
    for part in re.split(r'(?<=[.!?])\s+|\n+',body):
        q=part.strip()
        if not 6<=len(q.split())<=100 or len(q)>650 or not re.search(r'[.!?]$',q):continue
        if not readable(q) or re.search(r'(?i)cookie|accept all|all rights reserved|skip to|javascript',q) or q.startswith(('#','|')):continue
        if plan['purpose']=='pattern' and re.search(plan['terms'],q,re.I):candidates.append(q)
        elif plan['purpose']=='organisation' and plan['topic'].casefold() in q.casefold() and (re.search(re.escape(plan['topic'])+r'(?:\s+(?:Oy|Oyj|Ltd|Limited|Inc))?\s+(?:is|was|on|registered)\b',q,re.I) or re.search(r'(?i)(?:business ID|company number|registration number|y-tunnus).{0,25}\d',q)):candidates.append(q)
        elif plan['purpose']=='copies' and ' '.join(facts['distinctive_sentence'].split()).casefold() in ' '.join(q.split()).casefold():candidates.append(q)
    if plan['purpose']=='pattern':candidates.sort(key=lambda q:len(re.findall(r'(?i)pay|fee|money|deposit|bank|code|link|maks|raha|vakuus|tunnus|huija|scam',q)),reverse=True)
    return candidates[0] if candidates else ''


def web_rows(report,plan,facts,seen):
    rows=[]
    for page in report.get('results',[]):
        if not isinstance(page,dict) or not isinstance(page.get('text'),str):continue
        url=web_url(page.get('url') or '');host=(urlsplit(url).hostname or '').removeprefix('www.')
        if not url or url in seen or not readable(page.get('text') or ''):continue
        if plan['purpose']=='pattern' and not any(host==d or host.endswith('.'+d) for d in plan['domains']):continue
        quote=sentence(page,plan,facts)
        if not quote:continue
        title=str(page.get('title') or host);publisher=source_name(url)
        if plan['purpose']=='pattern':finding=publisher+(' warns about ' if re.search(r'(?i)warn|scam|fraud|huija|varo',title+' '+quote) else ' explains ')+plan['topic']+'.'
        elif plan['purpose']=='organisation':finding=publisher+' lists '+plan['topic']+' in company information.'
        else:finding=publisher+' repeats the searched sentence.'
        row=line(plan['check'],finding,quote,url,page.get('publishedDate'),polarity='found')
        row.update(origin='exa',origin_label='Found on the web (Exa)',source_name=publisher+': '+title,title=title,quote=quote,raw_url=page.get('url'),publication_date=page.get('publishedDate'),caveat='Pattern guidance, not a warning about this sender.' if plan['purpose']=='pattern' else 'This page does not verify the sender or this offer.',evidence_scope=plan['purpose'],search_query=plan['query'],retrieved_at=report.get('searched_at'),cached=report['status']=='cached')
        rows.append(row);seen.add(url)
    return rows


def message_address_rows(report,plan,facts,signs):
    usual=BANK_SITES.get(facts['name'].casefold())
    if plan['purpose']!='organisation' or not usual or not facts['contact_domains'] or not any(r['pressure_kind'] in ('bank_access','link_login') for r in signs):return []
    # The known site is only a search hint. A public source must explicitly
    # connect this named organisation to that domain before comparing addresses.
    pages=[]
    for page in report.get('results',[]):
        if not isinstance(page,dict) or not isinstance(page.get('text'),str) or not web_url(page.get('url') or ''):continue
        title=str(page.get('title') or '')
        names=title+' '+re.sub(r'(?i)(?:https?://)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,24}', ' ',page['text'])
        if re.search(r'(?<!\w)'+re.escape(facts['name'])+r'(?!\w)',names,re.I):pages.append(dict(page,title=title))
    ties=identity_evidence(pages,'https://'+usual,line)
    ties=[r for r in ties if r.get('verified_domain')==usual]
    offered=next((d for d in facts['contact_domains'] if registrable_domain(d)!=registrable_domain(usual) and registrable_domain(d).split('.')[0]!=registrable_domain(usual).split('.')[0]),'')
    if not ties or not offered:return []
    if identity_evidence(pages,'https://'+offered,line):return []
    row=dict(ties[0]);page=next(p for p in pages if web_url(p.get('url',''))==row['url'])
    publisher=row['source_name'];title=page.get('title') or publisher
    row.update(finding="The address in the message is not the organisation's usual one.",attention=False,polarity='worth checking',offered_domain=offered,known_official_domain=usual,origin='exa',origin_label='Found on the web (Exa)',source_name=publisher+': '+title,title=title,raw_url=page['url'],publication_date=page.get('publishedDate'),evidence_scope='organisation',search_query=plan['query'],retrieved_at=report.get('searched_at'),cached=report['status']=='cached',caveat='The message uses '+offered+'; '+publisher+' lists '+usual+'. This does not identify the sender.')
    return [row]


def receipt(report,plan):
    status=report['status'];query=plan['query']
    if status=='not_applicable':text='No organisation/contact was supplied; that search did not run.' if plan['purpose']=='organisation' else 'No distinctive sentence was available; copy search did not run.'
    elif status=='off_not_run':text='No web search ran: live web search is off.'
    elif status=='budget_not_run':text='No web search ran for '+plan['topic']+': the budget is spent.'
    elif status=='failed':text='Search attempted for '+query+': it failed. No conclusion can be drawn.'
    else:
        prefix='Cached Exa search for ' if status=='cached' else 'Searched for '
        result=(str(report['result_count'])+' results; '+str(report['shown_count'])+' source passages' if report['shown_count'] else 'no matching passage found in '+str(report['result_count'])+' results') if report['result_count'] else 'nothing found'
        text=prefix+query+': '+result+'. That is not proof either way.'
    return dict(check='Web search',finding=text,quote='',url='',attention=False,polarity='could not check',origin='web_search',source_name='Exa search receipt',primary=False)


async def message_run(client,text):
    started=time.perf_counter();facts=message_facts(text);signs=pressure_findings(text)
    for row in signs:
        row.update(origin='message',origin_label='Read from your message (rule)',span_source='input')
        wording=row['finding'].removeprefix('Your message ')
        row['finding']=wording[:1].upper()+wording[1:]
    plans=plan_queries(text,facts,signs)
    enabled=client is not None and bool(os.getenv('EXA_API_KEY')) and os.getenv('REAL_LIVE_ENABLED','0')=='1' and os.getenv('REAL_KILL_SWITCH','0')!='1'
    yield {'type':'phase','data':'Reading your message and checking up to three Exa searches.' if enabled else 'Reading your message. No live web search is enabled.'}
    rows=list(signs);reports=[];seen=set()
    async def search(plan):
        if not plan['query']:return dict(status='not_applicable',results=[],provider_calls=0)
        if not enabled:return dict(status='off_not_run',results=[],provider_calls=0)
        try:return await client.message_search(plan['query'],plan['domains'])
        except Exception as error:
            log_failure('message retrieval',error)
            return dict(status='failed',results=[],provider_calls=0,error_type=type(error).__name__)
    responses=await asyncio.gather(*(search(plan) for plan in plans))
    for plan,report in zip(plans,responses):
        found=web_rows(report,plan,facts,seen)
        addresses=message_address_rows(report,plan,facts,signs)
        if addresses:
            found=[r for r in found if r['url']!=addresses[0]['url']]+addresses
            seen.add(addresses[0]['url'])
        report.update(check=plan['check'],purpose=plan['purpose'],query=plan['query'],domains=plan['domains'],result_count=len(report.get('results',[])),shown_count=len(found))
        rows+=found;reports.append({k:v for k,v in report.items() if k!='results'})
    done=finish(rows,facts,True,time.perf_counter()-started)
    for plan,report in zip(plans,reports):
        report['shown_count']=sum(r.get('origin')=='exa' and r.get('search_query')==plan['query'] for r in done['findings'])
        done['unavailable'].append(receipt(report,plan))
    # A retrieved source must be visible next to the pinned message signs.
    sources=[r for r in done['findings'] if r.get('origin')=='exa']
    sources.sort(key=lambda r:not bool(r.get('offered_domain')))
    if not done['concerns']:
        for row in sources:
            row['finding']=row['source_name'].split(': ',1)[0]+': '+('company information.' if row['evidence_scope']=='organisation' else 'a matching sentence on this page.' if row['evidence_scope']=='copies' else 'how to check a message or call before you act.' if next(plan['topic'] for plan in plans if plan['query']==row['search_query'])=='checking an offer' else 'general guidance on '+next(plan['topic'] for plan in plans if plan['query']==row['search_query'])+'.')
            row['caveat']='General guidance, not a concern about this message.'
    if sources:
        for r in done['findings']:r['primary']=False
        if done['concerns']:
            for r in ([r for r in done['findings'] if r.get('origin')=='message'][:2]+sources[:3])[:3]:r['primary']=True
    calls=sum(r['provider_calls'] for r in reports)
    status='off' if not enabled else 'searched' if calls else 'cached' if any(r['status']=='cached' for r in reports) else 'budget_not_run' if any(r['status']=='budget_not_run' for r in reports) else 'not_run'
    done.update(web_searches=reports,exa_calls=calls,web_search_ran=bool(calls),web_search_status=status)
    yield {'type':'done','data':done}
