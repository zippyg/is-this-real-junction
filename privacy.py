"""Conservative English/Finnish guards. No person records or names are extracted."""
import re
from urllib.parse import unquote, urlsplit

CONTACT = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?:\+?\d[\d ()-]{6,}\d)')
SELF = re.compile(r'(?i:\b(?:my name is|minun nimeni|nimeni on|nimeltä|nimelta)\b)|\b(?:I am|Olen|olen)\s+[A-ZÅÄÖ][a-zåäöéèü-]+.{0,90}\b(?:work|työskentelen|tyoskentelen|toimin)\b')
NAME = r'[A-ZÅÄÖ][a-zåäöéèü-]+(?:[ -][A-ZÅÄÖ][a-zåäöéèü-]+){1,3}'
NAMED_ROLE = re.compile(r'(?:^|\n)\s*(?:[#>*-]+\s*)?'+NAME+r'\s*[,|]\s*\w|\b'+NAME+r'\s+(?:works|is a|työskentelee|tyoskentelee|toimii|on\s+\w+)\b|\b(?i:says|said|kertoo|sanoo|our colleague|our employee|meet|tapaa|työntekijämme|kollegamme)\s+'+NAME)
PEOPLE_PATH = re.compile(r'(?:^|/)(?:people|team|our-team|our-people|staff|employees?|henkil[oö]st[oö]|ihmiset|tiimi|ty[oö]ntekij[aä]t)(?:/|$)|(?:^|/)(?:meet-|meetthe|tapaa-|tutustu-)',re.I)
INDEX = re.compile(r'^(?:careers?|jobs?|vacancies|open-positions|openings|positions|join-us|work-with-us|avoimet-ty[oö]paikat|ty[oö]paikat|rekrytointi|vacatures|werken-bij|karriere|jobb|lediga-jobb|emplois|empleo|stellenangebote)(?:\.(?:php|html?))?$',re.I)
JOB = re.compile(r'job|engineer|developer|manager|designer|analyst|specialist|p[aä][aä]llik|kehitt[aä]j|asiantuntij|suunnittelij|ty[oö]paik',re.I)
ATS_HOSTS=('teamtailor.com','greenhouse.io','ashbyhq.com','workable.com','lever.co','myworkdayjobs.com','recruitee.com',
           'smartrecruiters.com','jobylon.com','varbi.com')


def ats_host(url):
    host=(urlsplit(url).hostname or '').lower()
    return any(host==h or host.endswith('.'+h) for h in ATS_HOSTS)


REFUSAL = 'Retained does not look up people, names or personal contact details. You can search employers instead.'


def has_contact(text):
    if re.search(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',text):return True
    text=re.sub(r'https?://\S+','',text)
    text=re.sub(r'\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}[./]\d{1,2}[./]\d{4}\b','',text)
    return bool(CONTACT.search(text))


def people_request(text):
    if re.search(r'\b(?:who (?:heads|leads|runs)|write to (?:that|this) person|hiring manager.{0,30}(?:name|email))\b',text,re.I):return True
    return bool(re.search(r'\b(?:find|look up|search|list|give|etsi|hae|anna|n[aä]yt[aä])\b',text,re.I) and
        re.search(r'\b(?:names?|emails?|e-mails?|people|employees?|staff|personal contacts?|contact details|nimi[aä]|nimet|s[aä]hk[oö]post\w*|henkil[oö]\w*)\b',text,re.I)) or has_contact(text)


def named_employee(text):
    for match in NAMED_ROLE.finditer(text):
        # Capitalized job headings also have the shape "Two Words, Location".
        # An explicit organization noun identifies company copy, not an employee role.
        if match.group().endswith('is a') and re.match(
            r'(?i)(?:(?:leading|global|software|technology|Finnish|British|German|climate|energy|innovative|independent)\s+){0,3}(?:company|business|startup)\b(?=[.,;:]|\s+(?:that|which|based|building|offering|providing|speciali[sz]ing|founded|headquartered|focused|with|for|in|and)\b|$)',
            text[match.end():].lstrip()):continue
        heading=match.group().split(',')[0].split('|')[0]
        if re.search(r'[,|]',match.group()) and JOB.search(heading):continue
        return True
    return False


def private_text(text):
    return bool('[contact omitted]' in text or has_contact(text) or SELF.search(text) or named_employee(text))


def profile_page(page):
    path=unquote(urlsplit(page['url']).path).strip('/')
    title=page.get('title','')
    if PEOPLE_PATH.search(path) or re.match(r'\s*(?:meet\b|our people|tapaa\b|tutustu\b|henkil[oö]st[oö])',title,re.I):return True
    segments=path.split('/')
    if len(segments)>=2 and re.fullmatch(r'careers?',segments[-2],re.I):
        tail=segments[-1]
        if not INDEX.fullmatch(tail) and '-' not in tail and not JOB.search(tail):return True
    return bool(SELF.search(page.get('text','')))


def careers_index(page):
    if profile_page(page):return False
    parsed=urlsplit(page['url']);segments=unquote(parsed.path).strip('/').split('/')
    if page.get('linked_ats') and ats_host(page['url']) and re.search(r'career|jobs|open positions|vacanc',page.get('title','')+' '+page.get('text','')[:100],re.I):return True
    return bool(INDEX.fullmatch(segments[-1]) or
        (not parsed.path.strip('/') and (parsed.hostname or '').split('.')[0] in ('careers','jobs','ura')))



def strip_contacts(page):
    """Remove contact strings from ordinary company pages before cache/model input."""
    text=re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}','[contact omitted]',page.get('text',''))
    text=re.sub(r'(?<!\w)\+\d[\d ()-]{6,}\d','[contact omitted]',text)
    return page|{'text':text}
