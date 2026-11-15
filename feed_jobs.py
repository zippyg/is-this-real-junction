"""Read public ATS posting fields without relying on JavaScript-rendered HTML."""
from urllib.parse import urlsplit


def canonical_job(url):
    return url.removesuffix('/application') if urlsplit(url).hostname=='jobs.ashbyhq.com' else url


def posting_feed(url):
    p=urlsplit(canonical_job(url));parts=p.path.strip('/').split('/')
    if p.hostname=='jobs.ashbyhq.com' and len(parts)==2:
        return f'https://api.ashbyhq.com/posting-api/job-board/{parts[0]}','ashby',parts[1]
    if p.hostname=='jobs.lever.co' and len(parts)==2:
        return f'https://api.lever.co/v0/postings/{parts[0]}/{parts[1]}?mode=json','lever',parts[1]
    if p.hostname=='apply.workable.com' and len(parts)>=3 and parts[1]=='j':
        return f'https://apply.workable.com/api/v2/accounts/{parts[0]}/jobs/{parts[2]}','workable',parts[2]
    return None


def posting_fields(data,kind,identifier):
    if kind=='ashby':
        job=next((j for j in data.get('jobs',[]) if j.get('id')==identifier),None)
        if job is None:raise ValueError('Posting is absent from the current public job board.')
        title,location,date=job['title'],job.get('location',''),job.get('publishedAt')
        description=job.get('descriptionPlain','') or job.get('descriptionHtml','')
    elif kind=='lever':
        job=data;title=job['text'];location=job.get('categories',{}).get('location','')
        date=job.get('createdAt');description=job.get('descriptionPlain','')
        if isinstance(date,(float,int)):
            from datetime import datetime,timezone
            date=datetime.fromtimestamp(date/1000,timezone.utc).isoformat()
    else:
        job=data;title=job['title'];loc=job.get('location',{})
        location=', '.join(str(loc[k]) for k in ('city','region','country') if loc.get(k)) if isinstance(loc,dict) else str(loc)
        date=job.get('published_on');description=job.get('description','')
    if job.get('isListed') is False or job.get('state') in ('closed','archived'):raise ValueError('Posting is not currently listed.')
    return title,location,date,description
