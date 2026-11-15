"""Readable, attributed findings and exact message annotations. No model calls."""
import re
import unicodedata
from urllib.parse import urlsplit

SOURCES = {'vero.fi':'Finnish Tax Administration (Vero)', 'tulli.fi':'Finnish Customs (Tulli)', 'posti.fi':'Posti', 'poliisi.fi':'Finnish Police', 'kkv.fi':'Finnish Competition and Consumer Authority (KKV)', 'uspis.gov':'US Postal Inspection Service', 'accc.gov.au': "Australia's consumer authority (ACCC)", 'fca.org.uk': "the UK's Financial Conduct Authority (FCA)", 'police.fi': 'Finnish Police', 'kyberturvallisuuskeskus.fi': "Finland's National Cyber Security Centre", 'consumer.ftc.gov': 'the US Federal Trade Commission (FTC)', 'ftc.gov': 'the US Federal Trade Commission (FTC)', 'scamwatch.gov.au': "Australia's Scamwatch", 'actionfraud.police.uk': "the UK's Action Fraud", 'prh.fi': 'the Finnish Patent and Registration Office', 'ytj.fi': 'the Finnish business information system (YTJ)'}


def source_name(url):
    host=(urlsplit(url).hostname or '').removeprefix('www.')
    return next((v for k,v in SOURCES.items() if host==k or host.endswith('.'+k)),host)


def readable(text):
    text=str(text or '').strip()
    if len(text)<15 or '\ufffd' in text[:150] or re.search(r'[¯ÞÐÆëóß]{2,}',text[:100]):return False
    words=re.findall(r'[^\W\d_]{2,}',text[:800],re.UNICODE)
    return len(words)>=4 and sum(len(w) for w in words)/max(1,len(text[:800]))>.45


IDENTITY_ITEMS = [
    (r'\bpassport\w*|\bpassi\w*', 'a passport'),
    (r'\b(?:photo\s+)?id(?:\s+card)?\b|\bidentity\s+(?:card|document)\w*|\bhenkilö(?:kort|todist)\w*', 'an ID document'),
    (r'\bresidence\s+permit(?:\s+card)?|\boleskelulu[vp]\w*', 'a residence permit'),
    (r'\b(?:bank|credit|debit|visa)\s+card\b|\b(?:pankki|luotto)kort\w*', 'bank card details'),
    (r'\bvisa\b|\bviisum\w*', 'a visa'),
    (r'\bdriv(?:ing|er(?:[\x27’]?s)?)\s+licen[cs]e\w*|\bajokort\w*', 'a driving licence'),
    (r'\b(?:social\s+security|personal\s+identity)\s+number\w*|\bhenkilötunn\w*|\bsosiaaliturvatunn\w*|\bhetu\b|\bSSN\b', 'a personal identity number')]
IDENTITY_ITEMS.append((r'\bpermit\b|\blicen[cs]e\b', 'a permit or licence'))
IDENTITY_WORDS='(?:'+'|'.join(pattern for pattern,_ in IDENTITY_ITEMS)+')'
BANK_ACCESS = r'\b(?:PIN|passwords?|salasana\w*|tunnusluku\w*|card\s+details|korttitied\w*|bank(?:ing)?\s+(?:login|credentials?|access|passwords?|codes?)|online\s+banking\s+(?:codes?|credentials?|login)|card\s+number\s*(?:and|with|&|,)\s*(?:CVV|CVC)|one[- ]time\s+(?:codes?|passwords?)|BankID|CVV|CVC|pankin\s+kirjautumistunn\w*|(?:verkko)?pankkitunn\w*|mobiilivarmen\w*|kertakäyttö(?:kood|tunnus)\w*|kortin\s+numero\s+ja\s+(?:CVV|CVC|turvakoodi))\b'
REQUEST = r'\b(?:send|provide|upload|scan|copy|share|email|e-mail|attach|text|give|need|require|submit|lähet\w*|toimita|jaa|lataa|anna|ilmoita|liitä|tarvits\w*)\b'
PAY = r'\b(?:pay|cover|settle|top\s+up|remit|forward|shoulder|send|transfer|wire|buy|purchase|mail|need|requires?|suorita|tilitä|hoida|kuittaa|kustant\w*|kattaa|vaatii|edellyttää|maksa\w*|maksamalla|siirrä|lähet\w*|osta\w*)\b'
PAYMENT = r'(?:[€$£]\s*\d+(?:[.,]\d+)?|\b\d+(?:[.,]\d+)?\s*(?:euro(?:a|n|s)?|EUR|USD|GBP|€|e\b)(?!\w)|\b(?:deposits?|security\s+bond|fees?|charges?|costs?|kits?|rent|payments?|equipment|training|vouchers?|gift\s*cards?|crypto\w*|bitcoin\w*|usdt\w*|(?:vuokra)?vakuus\w*|takuuvuokra\w*|vuokra\w*|ennakko\w*|(?:aloitus|perehdytys|koulutus|rekisteröinti|varaus|hakemus|liittymis|palvelu)?maksu\w*|aloituspaket\w*|lahjakort\w*)\b)'
PAYMENT_APPS = r'\b(?:Revolut\w*|Wise(?:lla|lle|n)?|MobilePay\w*|PayPal\w*|Venmo\w*|Zelle\w*|Cash\s+App)\b'
PRIVATE_PAYEE = r'\b(?:personally|personal\s+account|(?:my|our|your)\s+(?:\w+\s+){0,2}(?:friend|brother|sister|cousin|coordinator|supervisor|recruiter|agent|assistant|manager)|someone\s+else|another\s+country|abroad|overseas|henkilökohtaisesti|(?:veljeni|siskoni|ystäväni|kaverini|yksityishenkilön)\s+til\w*|ohjaajalle|koordinaattorille|ulkomai\w*)\b'
BARE_MONEY_REQUEST = r'\b(?:pay|cover|settle|transfer|wire|top\s+up|buy|remit|maksa\w*|siirrä|suorita|tilitä|kattaa)\b'
PAYMENT_REQUEST = PAY+r'|\byou\s+(?:must|need\s+to|have\s+to)|\bbefore\s+you|\bennen\s+kuin|\bsinun\s+(?:täytyy|pitää|on)|\b(?:paid|advance|upfront|mandatory|required)\b|\b(?:ennakko|varaus)mak\w*'
# Match actions, objects and conditions, rather than whole example sentences.
PRESSURE = [
 ('upfront_payment',PAYMENT+r'|\b\d+(?:[.,]\d+)?\b'),
 ('money_transfer',r'\b(?:Western\s+Union|Money\s*Gram|wire\s+service|gift\s*cards?|prepaid\s+voucher|crypto\w*|krypto\w*|bitcoin\w*|usdt\w*|PayPal(?:in)?\s+(?:friends\s*(?:and|&)\s*family|ystävät\s+ja\s+perhe)|(?:mail|post|send)\s+cash(?:\s+in\s+an?\s+envelope)?|cash\s+by\s+post|(?:lähet\w*|postit\w*)\s+(?:rahat|käteis\w*)\s+(?:kirje\w*|post\w*)|käteis\w*\s+post\w*|lahjakort\w*)\b|\b(?:to\s+)?(?:my|a|your|the)\s+(?:friend|sister|brother|cousin|partner|relative|third\s+person|private\s+person)(?:[’\x27]s)?\s+(?:bank\s+)?account(?:\s+(?:in|abroad)\s+\w+)?|\b(?:foreign|personal|overseas|offshore)\s+(?:bank\s+)?account|\b(?:yksityishenkilön|kaverini|ystäväni|siskoni|veljeni|ulkomais\w*)\s+til\w*|\b(?:send|share)\s+(?:the|its|their|your)\s+codes?\b|\blähet\w*\s+(?:korttien\s+)?koodit\b'),
 ('no_viewing',r'\b(?:at\s+sea\s+until\s+\w+|(?:abroad|overseas|travelling|traveling)[^.!?\n;]{0,45}(?:cannot|can.t|unable)[^.!?\n;]{0,20}(?:show|meet|view)|(?:cannot|can.t)\s+be\s+(?:shown|viewed)|(?:(?:I|we)\b[^.!?\n;]{0,45}(?:abroad|overseas|moved\s+to\s+\w+)[^.!?\n;]{0,40})?(?:viewings?|visits?)\s+(?:(?:is|are)\s+)?(?:not\s+possible|unavailable|cannot\s+be\s+arranged)|näyttö[äa]?\s+(?:ei\s+onnistu|ei\s+(?:voida|voi)\s+järjestää|ei\s+ole\s+mahdollinen)(?:[^.!?\n;]{0,45}\bolen\s+ulkomailla)?|en(?:kä)?\s+pääse\s+näyttämään(?:\s+\w+)?|(?:I am|I.m|we are)[^.!?\n;]{0,30}abroad[^.!?\n;]{0,65}(?:cannot|can.t|unable)[^.!?\n;]{0,25}(?:show|view)(?: it| the (?:flat|property))?|(?:cannot|can.t|unable to)\s+(?:meet(?:\s+you)?|show(?:\s+(?:it|the flat|the property))?|arrange a viewing)|no\s+viewing|olen\b[^.!?\n;]{0,25}ulkomailla[^.!?\n;]{0,60}|ei\s+näyttöä|en(?:kä)?\s+voi\s+(?:näyttää|tavata)[^.!?\n;]{0,25})'),
 ('posted_keys',r'\b(?:(?:post|mail|send|courier|deliver)\s+(?:you\s+)?(?:the\s+)?keys|keys\s+(?:(?:will|can)\s+be\s+|are\s+)?(?:couriered|posted|mailed|delivered)|(?:my|the)\s+(?:lawyer|solicitor|agent)\b[^.!?\n;]{0,35}(?:send|post|mail|courier|deliver)\b[^.!?\n;]{0,20}\bkeys|(?:kuriiri|lakimie\w*|välittäjä)\b[^.!?\n;]{0,25}(?:toimitta\w*|lähettä\w*|postitta\w*)\s+avaim\w*|keys\s+(?:by|in\s+the)\s+(?:post|mail)|postit\w*\s+avaim\w*|lähet\w*\s+avaim\w*\s+post\w*)'),
 ('low_price',r'(?:(?:rent|price)[^.!?\n]{0,45}(?:far below|half|much (?:lower|cheaper))[^.!?\n]{0,45}(?:area|market|local|usual)|(?:far below|half)[^.!?\n]{0,30}(?:area|market|local|usual)[^.!?\n]{0,20}(?:rent|price)|(?:vuokra|hinta)[^.!?\n]{0,45}(?:alle puolet|huomattavasti halvempi)[^.!?\n]{0,30})'),
 ('deadline',r'\b(?:(?:(?:for|within|in)\s+)?\d+\s*(?:minutes?|hours?|minuut\w*|tunn\w*)(?:\s+(?:only|vain|sisällä|kuluessa))?|today|tonight|immediately|within\s+(?:the\s+|an?\s+|\d+\s+|one\s+|two\s+)hours?|(?:offer\s+)?expires(?:\s+(?:in\s+\d+\s+hours?|at\s+midnight))?|(?:by|before)\s+(?:this\s+evening|(?:the\s+)?end\s+of\s+(?:the\s+)?day|tonight)|(?:by|before)\s*\d{1,2}(?:[:.]\d{2}|\s*[ap]m)|tänään|tänä\s+iltana|vuorokauden\s+(?:sisällä|kuluessa)|heti|(?:(?:\d+|yhden|kahden|kolmen|neljän|viiden|kuuden|seitsemän|kahdeksan|yhdeksän|kymmenen|muutaman|puolen)\s+)?tunnin\s+(?:sisällä|kuluessa|päästä)|(?:tarjous\s+)?vanhenee|klo\s*\d{1,2}(?:[.:]\d{2})?\s*mennessä)\b'),
 ('scarcity',r'\b(?:kiinnostuneita\s+on\s+(?:monta|useita|paljon)|(?:monta|useita|paljon)\s+kiinnostun\w*|(?:others|someone\s+else)\s+(?:wants?|is\s+waiting|will\s+get)|(?:goes?|will\s+go)\s+to\s+(?:someone|somebody)\s+else|(?:menee|annetaan|tarjotaan)\s+toiselle|(?:many|several|other|lots\s+of)\s+(?:other\s+)?(?:people|applicants|tenants|buyers|others)[^.!?\n;]{0,25}(?:interested|waiting|want)|last\s+(?:one|room|flat|place|unit|chance)\b|only\s+(?:one|room|flat|place|unit)\s+(?:left|available|remaining)|muitakin\s+kiinnostuneita[^.!?\n;]{0,20}|(?:moni|monet|paljon\s+muita)[^.!?\n;]{0,20}kiinnostun\w*|viimeinen\s+(?:vapaa\s+)?(?:asunto|paikka|huone|mahdollisuus))'),
 ('messaging_only',r'(?:only[^.!?\n;]{0,25}(?:whatsapp|telegram|signal)|(?:whatsapp|telegram|signal)[^.!?\n;]{0,25}only|(?:vain|ainoastaan)[^.!?\n;]{0,25}(?:whatsapp|telegram|signal)|(?:whatsapp|telegram|signal)[^.!?\n;]{0,20}(?:vain|ainoastaan)|(?:office (?:phone|line)|(?:our|the) (?:office )?phone|phone line)\s+(?:(?:is )?(?:not in use|not working|out of service)|isn.t working|does not work)|(?:(?:toimist\w*|meidän)\s+)?puhelin(?:linja|numero|memme)?\s+(?:ei (?:ole )?(?:toimi|käytössä)|on (?:rikki|pois käytöstä)))'),
 ('no_direct_contact',r'(?:(?:do not|don.t|never)\s+(?:contact|call|phone)[^.!?\n;]{0,55}(?:company|employer|landlord|agency|office)|no\s+calls\s+to\s+(?:our|the)\s+(?:office|employer)|älä\s+(?:ota\s+yhteyttä|soita)[^.!?\n;]{0,55}(?:yritykseen|työnantajaan|vuokranantajaan|suoraan|toimistoon|vuokrayhtiöön|taloyhtiöön))'),
 ('unsolicited',r'(?:you (?:did not|didn.t|have not|haven.t) appl(?:y|ied)|you are selected for|without (?:an? )?application|et (?:ole )?hakenut|ilman hakemusta)'),
 ('high_pay',r'(?:(?:[€$£]\s*[3-9][\d,.]{3,}|[3-9][\d,.]{3,}\s*(?:EUR|USD|euros?|euroa))[^.!?\n]{0,80}(?:[12]|one|two|yksi|kaksi|yhden|kahden)\s*(?:hours?|tuntia|tunnin|tunti)[^.!?\n]{0,20}(?:day|daily|päivässä))')]


def clause(text,start,end):
    left=max(text.rfind(c,0,start) for c in '.!?;\n')+1
    right=next((i for i in range(end,len(text)) if text[i] in '.!?;\n'),len(text))
    return left,text[left:right]


def negated(text,start,end):
    if re.match(r'(?i)\s+(?:nothing|zero|no\s+(?:fee|charge)|0\b)',text[end:]):return True
    left,body=clause(text,start,end)
    before=text[left:start]
    before=re.split(r'(?i),\s*(?:reply|contact|send|give|email|pay|lähetä|anna|maksa|vastaa)\b',before)[-1]
    return bool(re.search(r"(?i)\b(?:no|without|ilman|does(?:n.t| not)\s+require)\s*[- ]?\s*$",before) or re.search(r"(?i)\b(?:never|do not|don't|avoid\s+(?:send\w*|shar\w*|enter\w*|click\w*|logg\w*|giv\w*|disclos\w*)|älä|emme|ei tarvitse|ei vaadi|no fee|no payment)\b",before) or re.search(r'(?i)\b(?:not required|not payable|ei tarvita|ei vaadita)\b',body))


def after_agreement(text,start,end):
    _,body=clause(text,start,end)
    return bool(re.search(r'(?i)after[^.!?;]{0,65}(?:viewing|contract|signing|agreement)|(?:näytön|sopimuksen|allekirjoituksen)\s+jälkeen|allekirjoitetun\s+(?:vuokra|työ)?sopimuksen\s+jälkeen',body)) and not re.search(r'(?i)\bbefore\b|\bennen\b|to (?:hold|activate|start|secure)',body)


def ordinary_payment(text,start,end):
    left,body=clause(text,start,end)
    # Payment timing can be in this sentence or the one immediately before it.
    previous=max(0,left-1)
    previous=max(text.rfind(c,0,previous) for c in '.!?;\n')+1
    context=text[previous:left+len(body)]
    protected=re.search(r'(?i)\b(?:blocked|escrow|rental\s+deposit|security\s+deposit)\s+(?:(?:rental|deposit|bank)\s+){0,3}account\b|vuokravakuustil\w*|suljet\w*.{0,35}(?:tili|vakuus)',context)
    deferred=re.search(r'(?i)\bafter\s+(?:(?:we|you|both|have|had|the|a|our|your)\s+){0,5}(?:sign(?:ing|ed)?|view(?:ing|ed)?|deliver(?:y|ed))\b|after\s+(?:the\s+)?(?:lease|contract)\s+(?:is|was|has\s+been)\s+signed|(?:näytön|toimituksen|noudon|(?:vuokra|työ|jäsen)?sopimuksen\s+allekirjoit\w*|allekirjoitetun\s+(?:vuokra)?sopimuksen)\s+jälkeen',context)
    card_hold=re.search(r'(?i)(?:hold|held|pre-authoris\w*|pre-authoriz\w*|reserve)\b.{0,75}\bcard\b.{0,60}(?:pick.?up|collect)|(?:vakuus|katevaraus|summa).{0,35}(?:varataan|varaus).{0,40}kort\w*.{0,60}(?:nout|noud)',context)
    membership=re.search(r'(?i)membership|jäsen',body) and re.search(r'(?i)signed.{0,30}contract|contract.{0,20}signed|sopimus.{0,20}allekirjoitettu',context)
    local=text[max(left,text.rfind(',',left,start)+1):start]
    stated=re.search(r'(?i)\b(?:rent|price|salary|wages?|vuokra|hinta|palkka)\s*(?:(?:is|are|on|will be)\s*|:\s*)$',local) and not re.search(PAYMENT_REQUEST,local,re.I)
    return bool(protected or deferred or card_hold or membership or stated)


# Explicit reference addresses, not a guess from a brand-shaped hostname.
ORGANISATION_SITES = {
    'Danske Bank': ('danskebank.fi','danskebank.dk','danskebank.com','danskebank.co.uk'),
    'Nordea': ('nordea.fi','nordea.com','nordea.se','nordea.dk','nordea.no'),
    'S-Pankki': ('s-pankki.fi',), 'OP': ('op.fi',),
    'Posti': ('posti.fi',), 'Vero': ('vero.fi',), 'Tulli': ('tulli.fi',),
    'Kela': ('kela.fi',), 'Elisa': ('elisa.fi',), 'DNA': ('dna.fi',),
    'Telia': ('telia.fi','telia.se','telia.com'), 'DHL': ('dhl.com','dhl.de'),
    'Royal Mail': ('royalmail.com',), 'UPS': ('ups.com',), 'FedEx': ('fedex.com',),
    'HSL': ('hsl.fi',), 'Verkkokauppa.com': ('verkkokauppa.com',),
}


def claimed_organisation(text):
    # A domain containing a brand is not itself an organisation claim.
    words=re.sub(r'(?i)(?:https?://)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,24}(?:/[^\s]*)?', ' ',text)
    for name,sites in ORGANISATION_SITES.items():
        if re.search(r'(?i)^\s*'+re.escape(name)+r'(?=[: ,]|$)|\b(?:from|on behalf of|viesti|lähettäjä)\s*:?\s*'+re.escape(name)+r'(?![\w-])',words):return name,sites
    # The shop's actual dotted name can also be the sender banner.
    if re.match(r'(?i)^\s*Verkkokauppa\.com\s*:',text):return 'Verkkokauppa.com',ORGANISATION_SITES['Verkkokauppa.com']
    return '',()


def message_brand_names(text):
    words=re.sub(r'(?i)(?:https?://)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,24}(?:/[^\s]*)?', ' ',text)
    # Capitalised names are taken from the message, never inferred from a URL.
    names=re.findall(r'(?<![\w-])[A-ZÅÄÖ][A-Za-zÅÄÖåäö0-9-]{1,40}(?![\w-])',words)
    names+=re.findall(r'(?<![\w-])[A-ZÅÄÖ][A-Za-zÅÄÖåäö0-9-]*(?:\s+(?:[A-ZÅÄÖ][A-Za-zÅÄÖåäö0-9-]*|of|and|the)){1,4}',words)
    header=re.match(r'^\s*([\w .&-]{2,50}):',words)
    if header:names+=re.findall(r'[\w-]+',header[1])
    names+=re.findall(r'(?i)\b(?:your|from|täällä|sender|lähettäjä)\s+([a-zåäö][a-zåäö0-9-]{1,40})(?=\s+(?:payment|invoice|account|receipt|refund)|[.:])',words)
    ignored={'security','notice','account','billing','refund','delivery','parcel','statement','support','dear','good','news','tomorrow','today','verify','settle','renew','manage','new','current','latest','your','you','hello','hi','hei','please','pay','enter','confirm','update','bank','tax','administration','payment','invoice','receipt','card','code','thanks','next','view','open','track','read','we','our','this','to','if','the','no','a','maksa','syötä','vahvista','lue','pakettisi','seuraa'}
    return [n for n in names if n.casefold() not in ignored]


def brand_address_shape(text,address):
    host=(urlsplit(address if '://' in address else 'https://'+address).hostname or '').lower()
    registered=registrable_domain(host);stem=registered.split('.')[0]
    names=message_brand_names(text)
    # A destination matching any organisation actually named in the message is
    # allowed, including a named payment provider and its ordinary subdomains.
    if any(folded(stem)==folded(n) for n in names):return None
    pieces=re.split(r'[.-]',host)
    for name in names:
        token=folded(name)
        if len(token)<2:continue
        if token in [folded(x) for x in pieces] or (len(token)>=4 and any(folded(label).startswith(token) and folded(label)!=token for label in host.split('.')[:-1])):
            return dict(name=name,basis='message_brand_domain_shape',registered=registered)
    # A complete website-looking prefix can be embedded under somebody else's
    # registered domain, even when the sender uses a translated organisation name.
    prefix=host[:-len(registered)].rstrip('.')
    if re.search(r'(?:^|\.)[a-z0-9-]+\.(?:fi|se|no|dk|com|net|org|co\.uk|com\.au)(?:\.|$)',prefix) and re.match(r'^[^:\n]{2,60}:',text):
        return dict(name='',basis='embedded_domain_shape',registered=registered)
    return None


def pressure_findings(text, url=''):
    out=[];kind=local_facts(text)['kind']
    protected_deposit=kind=='rental' and bool(re.search(r'(?i)signed.{0,30}(?:lease|tenancy|contract)|(?:lease|contract).{0,25}(?:signed|allekirjoitettu)|vuokrasopimus.{0,25}allekirjoitettu|allekirjoitetun vuokrasopimuksen',text)) and bool(re.search(r'(?i)blocked.{0,35}(?:deposit|account)|suljet\w*.{0,35}(?:vakuustil|tili)',text)) and not re.search(r'(?i)before (?:a |the )?(?:viewing|signing)|ennen näyttöä|ennen sopimusta',text)
    offered_viewing=bool(re.search(r'(?i)\bviewing\s+(?:(?:is|on|at)\s+){1,2}(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|\d)|näyttö\s+(?:sopii|on|järjestetään)\s+(?:maanantaina|tiistaina|keskiviikkona|torstaina|perjantaina|lauantaina|sunnuntaina|\d)',text))
    def add(kind,start,end):
        quote=text[start:end]
        if not quote or any(r['pressure_kind']==kind and r['quote_start']==start and r['quote_end']==end for r in out):return
        out.append(dict(check='Pressure signs',finding=pressure_sentence(kind,quote),quote=quote,url=url,published_at=None,attention=True,polarity='warning',source_name='Your message',caveat='No comparable local pay rate was verified.' if kind=='high_pay' else "This is the message's price claim; no comparable local rent was verified." if kind=='low_price' else 'This wording does not establish who sent the offer.',pressure_kind=kind,span={'start':start,'end':end},quote_start=start,quote_end=end,span_utf16={'start':len(text[:start].encode('utf-16-le'))//2,'end':len(text[:end].encode('utf-16-le'))//2},anchor=quote))
    # Find every requested item separately: passport and bank login must never merge.
    for family,pattern in [('bank_access',BANK_ACCESS),('identity_documents',IDENTITY_WORDS)]:
        for match in re.finditer(pattern,text,re.I):
            start,end=match.span();left,body=clause(text,start,end)
            requests=list(re.finditer(REQUEST+(r'|\b(?:enter|type|confirm|verify|authenticate|syötä|vahvista|kirjaudu)\b' if family=='bank_access' else '')+r'|\b(?:selfie|photo|scan|copy|kuva|valokuva|kopio)\w*',text[left:start],re.I))
            if not requests and not re.search(r'(?i)selfie|scan|copy|photo|kuva|kopio',text[max(left,start-30):end]):continue
            request_start=left+requests[-1].start() if requests else start
            if requests and re.match(r'(?i)lähet(?:ettiin|etään|etty|ämme|imme|än|in|ti)|toimit(?:ettiin|etaan|amme|imme)',requests[-1][0]):continue
            if requests and re.fullmatch(r'(?i)send|provide|give|email|text|attach|share',requests[-1][0]) and re.search(r'(?i)\b(?:we|I|they|system|bank)\s+(?:(?:will|can)\s+)?$',text[max(left,request_start-25):request_start]):continue
            if start-request_start>150 or negated(text,request_start,end) or negated(text,start,end):continue
            if family=='identity_documents' and after_agreement(text,start,end):continue
            # Quote the short request when adjacent; otherwise pin just this item.
            pin=request_start if start-request_start<=45 else start
            if family=='bank_access' and re.search(IDENTITY_WORDS+r'|\bcard\s+details\b|\bkorttitied\w*',text[request_start:start],re.I):pin=start
            if family=='identity_documents' and any(r['pressure_kind']=='bank_access' and start<r['quote_end'] and end>r['quote_start'] for r in out):continue
            add(family,pin,end)
    # A received code is information. Asking to relay it, or enter it at a
    # message-supplied destination, is a different action.
    message_link=r'(?i)\blink\w*|\bbutton\b|painik\w*|https?://'
    code_requests=r'(?i)\b(?:enter|type|send|share|tell|relay|forward|provide|give|reply|read\s+out|syötä|kirjoita|kerro|sanele|välitä|lähet\w*|anna|ilmoita)\b'
    for match in re.finditer(r'(?i)\b(?:(?:verification|security|SMS|text|one[- ]time)\s+)?codes?\b|\b(?:vahvistus|turva|kertakäyttö)?kood\w*|vahvistusnumero\w*',text):
        start,end=match.span();left,body=clause(text,start,end)
        if re.search(r'(?i)gift\s*card|voucher|lahjakort|korttien',body) and not re.search(r'(?i)SMS|phone|mobile|one[- ]time|security|verification|pankki|puhelin|vahvistus|kertakäyttö',body):continue
        requests=list(re.finditer(code_requests,text[left:start]))
        if not requests:continue
        request=requests[-1];pin=left+request.start()
        if re.match(r'(?i)lähet(?:ettiin|etään|etty|ämme|imme|än|in|ti)|toimit(?:ettiin|etaan|amme|imme)',request[0]):continue
        if start-pin>140 or negated(text,pin,end) or negated(text,start,end):continue
        # "We send you a code" is not asking the reader to share one.
        if re.search(r'(?i)\b(?:we|I|they|system|bank)\s+(?:(?:will|can)\s+)?$',text[max(left,pin-25):pin]):continue
        sharing=re.fullmatch(r'(?i)send|share|tell|relay|forward|provide|give|reply|read\s+out|kerro|sanele|välitä|lähet\w*|anna|ilmoita',request[0])
        if not sharing and not re.search(message_link,body):continue
        if any(r['pressure_kind']=='bank_access' and pin<r['quote_end'] and end>r['quote_start'] for r in out):continue
        add('bank_access',pin if start-pin<=65 else start,end)
    # Resolve a code mentioned here or in the immediately preceding sentence.
    # A request to pass it to another person differs from a code notice.
    relay=r'(?i)\b(?:read(?:\s+out)?|tell|send|give|share|forward|relay|repeat|kerro|lue|lähet\w*|anna|välitä|sanele)\s+(?:it|that(?:\s+(?:code|number))?|this(?:\s+(?:code|number))?|the\s+(?:code|number)|se|sen|sitä)\b'
    for match in re.finditer(relay,text):
        start,end=match.span();left,body=clause(text,start,end)
        previous=max(text.rfind(c,0,max(0,left-1)) for c in '.!?;\n')+1
        context=text[max(previous,left-400):start]
        code=re.search(r'(?i)(?:verification|security|one[- ]time|SMS)\s+(?:code|number)|(?:vahvistus|turva|kertakäyttö)kood\w*|vahvistusnumero\w*',context)
        delivered=re.search(r'(?i)\bcode\b|\bkood\w*',context) and re.search(r'(?i)phone|mobile|texted|SMS|puhelim|tekstiviest',context)
        if not (code or delivered) or negated(text,start,end):continue
        if re.search(r'(?i)gift\s*card|voucher|lahjakort',context) and not code:continue
        tail=body[match.end()-left:]
        stop=re.search(r'(?i)\bso\b|,?\s*\b(?:niin|jotta)\b',tail)
        end=min(left+len(body),end+(stop.start() if stop else len(tail)),start+100)
        while end>start and text[end-1] in ' ,':end-=1
        if any(r['pressure_kind']=='bank_access' and start<r['quote_end'] and end>r['quote_start'] for r in out):continue
        add('bank_access',start,end)
    linked_clauses=set()
    actions=r'(?i)\b(?:log(?:ging)?\s*(?:in|on)|sign(?:ing)?\s*(?:in(?:to)?|on)|authenticate|verify|confirm|enter|type)\b|\b(?:vahvista|varmenna|syötä|kirjaudu|kirjautu\w*|tunnistaudu|tunnistautu\w*|kirjoita)\b'
    for match in re.finditer(actions,text):
        start,end=match.span();left,body=clause(text,start,end)
        link=re.search(message_link,body)
        target=re.search(r'(?i)identit|account|codes?|bank|phone|henkilöllis|tili|kood|tunnus|vahvistusnumero',body)
        login=re.fullmatch(r'(?i)log(?:ging)?\s*(?:in|on)|sign(?:ing)?\s*(?:in(?:to)?|on)|authenticate|kirjaudu|kirjautu\w*|tunnistaudu|tunnistautu\w*',match[0])
        if not link or (not target and not login) or left in linked_clauses or negated(text,start,end) or negated(text,left+link.start(),left+link.end()):continue
        add('link_login',start,max(end,left+link.end()))
        linked_clauses.add(left)
    # A banking action at a supplied address needs a nearby credential request.
    # Mere order, calendar, tracking and HR links do not meet that condition.
    addresses=[] if url else list(re.finditer(r'(?i)(?<![\w@])(?:https?://)?(?:www\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24}(?:/[^\s,;]*)?',text))
    for action in re.finditer(r'(?i)\b(?:cancel|reject|stop|reverse|go\s+to|visit|open|follow|peruuta|estä|avaa|mene|siirry|käy)\b',text):
        start=action.start()
        address=next((m for m in addresses if m.start()>=action.end() and m.start()-action.end()<=110 and not re.search(r'[.!?;\n]',text[action.end():m.start()])),None)
        if not address or negated(text,start,action.end()):continue
        window_start=max(0,start-160);window=text[window_start:address.end()+180]
        bank_header=re.match(r'(?i)^\s*(?:OP|Nordea|S[- ]Pankki|Danske\s+Bank|(?:your\s+)?bank(?:ing)?\s+(?:notice|alert|security))\b',text)
        if re.search(r'(?i)\b(?:HR|employee|employer|employment|onboarding|payroll|staff|human\s+resources)\b|henkilöstö|työsopim',window):continue
        if not bank_header and kind in ('job','rental','shop','parcel'):continue
        if not bank_header and not re.search(r'(?i)\b(?:payment|transfer|debit)\b|maksu|pankkitili',window):continue
        nearby=any(r['pressure_kind']=='bank_access' and start-100<=r['quote_start']<=address.end()+180 for r in out)
        if not nearby:
            secret=re.search(BANK_ACCESS+r'|\bbank\s+ID\b',window,re.I)
            requests=list(re.finditer(r'(?i)\b(?:confirm|approve|sign|enter|verify|authenticate|vahvista|hyväksy|anna|syötä|tunnistaudu)\b',window[:secret.start()] if secret else ''))
            if not secret or not requests:continue
            pin=window_start+requests[-1].start();secret_end=window_start+secret.end()
            if negated(text,pin,secret_end):continue
            add('bank_access',pin,secret_end)
        end=address.end()
        while end>start and text[end-1] in '.!?),':end-=1
        if any(r['pressure_kind']=='link_login' and start<r['quote_end'] and end>r['quote_start'] for r in out):continue
        add('link_login',start,end)
    # Compare an explicitly named organisation with the destination of a
    # sensitive action. Full-message windows preserve decimal amounts and URLs.
    organisation,sites=claimed_organisation(text)
    sensitive=r'(?i)\b(?:updat(?:e|ing)|päivitä|pay(?:ing)?|settle|remit|cancel|reject|stop|reverse|log(?:ging)?\s*(?:in|on)|sign(?:ing)?\s*in|verify|confirm|enter(?:ing)?|go\s+to|visit|open|claim|release|maksa\w*|suorita|peruuta\w*|estä|kirjaudu|tunnistaudu|vahvista|syötä|avaa|mene|siirry|lunasta)\b'
    finance=r'(?i)identit|henkilöllis|pay|invoice|bill|subscription|lasku|payment|transaction|debit|transfer|refund|charge|fee|parcel|shipment|delivery|codes?|credentials?|login|account|card|maksu|veloit|tilisiir|palautus|paketti|pankki|tunnus|koodi'
    if addresses:
        for address in addresses:
            offered=registrable_domain(address[0].rstrip('.!?),'))
            shape=brand_address_shape(text,address[0].rstrip('.!?),'))
            if offered in sites or any(folded(offered.split('.')[0])==folded(n) for n in message_brand_names(text)) or (not shape and not organisation):continue
            window_start=max(0,address.start()-180)
            window=text[window_start:min(len(text),address.end()+160)]
            actions=list(re.finditer(sensitive,window))
            actions=[m for m in actions if not (address.start()<=window_start+m.start()<address.end()) and not negated(text,window_start+m.start(),window_start+m.end())]
            if not actions or not re.search(finance,window):continue
            if re.search(r'(?i)\b(?:HR|employee|employer|employment|onboarding|payroll|staff|human\s+resources)\b|henkilöstö|työsopim',window):continue
            before=[m for m in actions if window_start+m.end()<=address.start()]
            action=min(before or actions,key=lambda m:abs(window_start+m.start()-address.start()))
            pin=window_start+action.start();end=address.end()
            if re.match(r'(?i)(?:cancel|stop|reject|peruuta)\w*\s+(?:your\s+|the\s+)?(?:appointment|meeting|interview|booking|calendar|tapaami\w*|haastattelu\w*)',text[pin:]):continue
            # A neutral open/visit instruction needs a financial or credential
            # demand, not merely a statement about a payment already received.
            direct=re.search(r'(?i)pay(?:ing)?|settle|remit|cancel|reject|stop|reverse|log(?:ging)?\s*(?:in|on)|sign(?:ing)?\s*in|maksa|suorita|peruuta|estä|kirjaudu|lunasta',action[0])
            credential=re.search(BANK_ACCESS+r'|\baccess\s+codes?\b|\bbank\s+ID\b|\bcard\s+number\b|kortin\s+numero',window,re.I)
            request=re.search(r'(?i)\b(?:updat(?:e|ing)|päivitä|enter(?:ing)?|give|confirm|verify|type|syötä|anna|vahvista|kirjoita|tunnistaudu)\b',window)
            if not direct and not (credential and request):continue
            if any(negated(text,window_start+m.start(),window_start+m.end()) for m in re.finditer(r'(?i)\b(?:pay|payment|maksa|maksu)\b',window)) and not credential:continue
            if not any(r['pressure_kind']=='link_login' and max(pin,address.start())>=r['quote_start'] and min(end,address.end())<=r['quote_end'] for r in out):
                add('link_login',min(pin,address.start()),max(window_start+action.end(),end))
            if credential and request:
                a=window_start+request.start();b=window_start+credential.end()
                if a<b and not negated(text,a,b) and not any(r['pressure_kind']=='bank_access' and a<r['quote_end'] and b>r['quote_start'] for r in out):add('bank_access',a,b)
            urgency=re.search(r'(?i)\b(?:now|nyt)\b',text[min(pin,address.start()):min(len(text),address.end()+50)])
            if urgency and not negated(text,min(pin,address.start())+urgency.start(),min(pin,address.start())+urgency.end()):add('deadline',min(pin,address.start())+urgency.start(),min(pin,address.start())+urgency.end())
            add('address_mismatch',address.start(),address.end())
            if shape:
                out[-1].update(offered_domain=offered,identity_basis=shape['basis'],finding=('Your message uses '+shape['name']+' inside a different domain.' if shape['name'] else 'Your message puts one website name inside another.'),caveat=('The address contains '+shape['name']+' but sits under '+offered+'.' if shape['name'] else 'The website-looking prefix is a subdomain of '+offered+'.')+' This shape does not establish who owns it or sent the message.')
            else:
                out[-1].update(offered_domain=offered,known_official_domain=sites[0],identity_basis='configured_organisation_domain',caveat=organisation+' uses '+sites[0]+'. This message supplies '+offered+'. This does not identify the sender.')
    for family,pattern in PRESSURE:
        if family=='money_transfer':pattern='(?:'+pattern+'|'+PAYMENT_APPS+')'
        matches=[]
        for match in re.finditer(pattern,text,re.I):
            start,end=match.span();left,body=clause(text,start,end)
            if family!='no_direct_contact' and negated(text,start,end):
                if family not in ('deadline','scarcity') or not re.search(r'(?i)if you[^.!?;]{0,20}(?:not|fail)|unless|jos et',body):continue
            if family=='upfront_payment':
                if protected_deposit or ordinary_payment(text,start,end):continue
                if re.fullmatch(r'\d+(?:[.,]\d+)?',match[0]) and (not re.search(BARE_MONEY_REQUEST,body,re.I) or re.match(r'\s*(?:minutes?|hours?|minuut\w*|tunn\w*)',text[end:],re.I)):continue
                # Locate money first, then its demand anywhere in this clause.
                requests=list(re.finditer(PAYMENT_REQUEST,body,re.I))
                before=[m for m in requests if left+m.start()<=start]
                request=before[-1] if before else requests[0] if requests else None
                if request is None:continue
                if request[0].lower()=='paid' and not re.search(r'(?i)must|need|require|to\s+be|will\s+be|once|before|after\s+(?:you|your)|advance|upfront',body):continue
                if not before and re.search(PAYMENT,body[request.end():],re.I):continue
                if any(clause(text,a,b)[0]==left for a,b in matches):continue
                # A work instruction about sending goods does not turn the
                # following offered wage into money requested from the reader.
                gap=body[request.start():end-left]
                if re.search(r'(?i)\b(?:send|forward|transfer|ship|mail)\s+(?:the\s+)?(?:packages?|parcels?|goods|items|them)\s+(?:on|abroad|overseas|to|back|forward)\b|\b(?:lähet\w*|postita|toimita)\s+(?:paket\w*|tavara\w*|ne)\s+(?:edelleen|ulkomaille|eteenpäin|asiakkaille)\b',gap) and not re.search(r'(?i)\b(?:fees?|costs?|charges?|deposits?|rent|payment|money|funds|bond|maksu\w*|vuokra\w*|vakuus\w*)\b',gap):continue
                start=min(start,left+request.start())
                # A nearby amount and its fee name are one payment, not two signs.
                tail_start=end
                for extra in re.finditer(PAYMENT,text[tail_start:min(left+len(body),tail_start+40)],re.I):
                    gap=text[end:tail_start+extra.start()]
                    if re.search(r'[,;.!?]|\band\b|\bja\b',gap,re.I):break
                    end=tail_start+extra.end()
                if negated(text,start,end):continue
                # The employer paying wages is not the recipient paying to get work.
                if re.match(r'(?i)(?:pay|cover|settle|send|transfer|wire|buy|purchase|mail)\b',text[start:end]) and re.search(r'(?i)\b(?:we|I|they|the employer|the company)(?: (?:will|can|would))?\s*$',text[max(left,start-40):start]):continue
                if re.match(r'(?i)(?:maksamme|maksan|lähetämme|lähetän|siirrämme|siirrän|ostamme|ostan)\b',text[start:end]):continue
                if kind!='job' and (after_agreement(text,start,end) or (re.search(r'(?i)monthly rent|rent is due|rent due|vuokra erääntyy',body) and not re.search(r'(?i)before|ennen|to (?:hold|activate|reserve)',body))):continue
                if not (kind in ('job','rental','parcel') or re.search(r'(?i)before|upfront|advance|to (?:activate|hold|secure|reserve|receive|release|claim|unlock|start|begin)|(?:release|claim|unlock)[^.!?;]{0,35}(?:refund|prize|parcel)|ennen|ennakko|vapautta\w*|lunastaa',body)):continue
            if family=='no_viewing' and (offered_viewing or (kind!='rental' and re.match(r'(?i)at\s+sea',match[0]))):continue
            if family=='deadline' and not out and (protected_deposit or ordinary_payment(text,start,end)):continue
            if family=='money_transfer' and re.fullmatch(PAYMENT_APPS,text[start:end],re.I):
                if protected_deposit:continue
                private=re.search(PRIVATE_PAYEE,body,re.I)
                if not private:continue
                end=max(end,left+private.end())
                # Keep the full payee phrase when it continues to personally/account.
                tail=re.search(r'(?i)personally|henkilökohtaisesti|tilille|account',text[end:min(left+len(body),end+45)])
                if tail:end+=tail.end()
            if family=='money_transfer' and not (re.search(PAY+r'|maksamalla|korttien koodit',text[max(0,left-130):end],re.I) or any(r['pressure_kind']=='upfront_payment' and clause(text,r['quote_start'],r['quote_end'])[0]==left for r in out)):continue
            if family=='deadline' and not out and (after_agreement(text,start,end) or (re.search(r'(?i)monthly rent|rent is due|rent due|vuokra erääntyy',body) and not re.search(r'(?i)before|ennen|to (?:hold|activate|reserve)',body))):continue
            if family=='unsolicited' and re.search(r'(?i)thank you for appl|your application|kiitos hakemuks',text):continue
            # One short pin per independent sign, with overlap collapsed within a family.
            if any(start<e and end>s for s,e in matches):continue
            matches.append((start,end));add(family,start,end)
        # A payment condition for getting work is distinct from its payment route.
        if family=='upfront_payment' and kind=='job' and matches:
            add('payment_for_job',*matches[0])
    substantive={'upfront_payment','payment_for_job','money_transfer','identity_documents','bank_access','link_login','address_mismatch'}
    demanded=any(r['pressure_kind'] in substantive for r in out)
    # Deadlines, scarcity and descriptive offer claims cannot justify each other.
    # Calendar attendance and routine appointment confirmations are not offers
    # demanding money, documents, account access or an immediate commitment.
    decision=kind in ('job','rental') and bool(re.search(r'(?i)\b(?:accept|decide|commit)\b|\bpäätä\b|hyväksy\w*',text))
    descriptive={'deadline','scarcity','no_viewing','posted_keys','high_pay','low_price','unsolicited'}
    out=[r for r in out if r['pressure_kind'] not in descriptive or demanded or decision]
    out=[r for r in out if r['pressure_kind']!='messaging_only' or demanded or re.search(r'(?i)reply|contact|write|message|vastaa|kirjoita|ota\s+yhteyttä',clause(text,r['quote_start'],r['quote_end'])[1])]
    return out


def local_facts(text,url='',title=''):
    body=text+' '+url+' '+title
    # Strong offer nouns win over transactional verbs such as buy, order or transfer.
    job=bool(re.search(r'(?i)offer\w*.{0,40}remote data entry|etätyö|tietojen syött|work from home|remote work|start work|työn aloitt|töihin|työntekij|\b(?:job|careers?|recruit\w*|employ\w*|interview|payroll|salary|wages?|vacancy|shift|role|position|CV|shortlisted)\b|työhaastattel|työpaik|työtarjou|työtehtäv|työhön|etätyö|varastotyö|palkka|työsopim|työhakem',body))
    rental=bool(re.search(r'(?i)\b(?:landlord|apartment|flat|studio|room|(?:one|two|three)[ -]bedroom|security\s+bond|tenancy|cottage|letting|housing|rent(?:al)?)\b|vuokra|asun[nt]|yksiö|lägenhet|hyres|bostad',body))
    kind='job' if job and not rental else 'rental' if rental and not job else 'unknown' if job and rental else 'parcel' if re.search(r'(?i)\bparcel\b|customs|paketti|tulli',body) else 'shop' if re.search(r'(?i)\b(?:shop|cart|product|store|checkout|delivery|order)\b|verkkokaup|tilauks|tuotteet|kassassa',body) else 'unknown'
    name=re.search(r'(?im)^(?:company|employer|yritys|työnantaja)\s*:\s*([^\n.!?]{3,70})',text)
    domain=urlsplit(url).hostname if url else ''
    return dict(kind=kind,source_kind='offer',name=name[1].strip() if name else domain or '',official_domain=domain or '',distinctive_sentence='',country='',role_or_item='',price='')


def select(rows):
    candidates=[]; unavailable=[]; seen=set(); statements=set()
    for row in sorted(rows,key=lambda r:(r.get('pressure_kind')!='bank_access',not r.get('official_warning'),not r.get('positive_mismatch'),r.get('check')!='Pressure signs',{'bank_access':-1,'upfront_payment':0,'identity_documents':1,'money_transfer':2,'payment_for_job':3,'no_viewing':4,'deadline':5}.get(r.get('pressure_kind'),5),r.get('polarity')!='reassuring',r.get('identity_basis')!='independent_domain_reference')):
        r=dict(row); r['primary']=False
        if r.get('check')=='Pressure signs' and not r.get('pressure_kind'):continue
        if r.get('polarity')=='could not check' or r.get('check') in ('Source','Recorded case provenance'):
            unavailable.append(r);continue
        if not r.get('source_name') or not r.get('quote') or (not r.get('pressure_kind') and not readable(r['finding'])):continue
        key=('message:'+r['pressure_kind'],r.get('quote_start'),r.get('quote_end')) if r.get('pressure_kind') else r.get('url')
        statement=(r.get('polarity'),folded(r.get('finding','')),r.get('quote_start') if r.get('pressure_kind') else None)
        if key in seen or statement in statements:continue
        seen.add(key);statements.add(statement);candidates.append(r)
    for r in candidates[:3]:r['primary']=True
    return candidates,unavailable


def folded(value):
    return ''.join(c.lower() for c in unicodedata.normalize('NFKD',value) if c.isalnum())


def organisation_domain(url):
    host=(urlsplit(url).hostname or '').removeprefix('www.')
    parts=host.split('.')
    return '.'.join(parts[1:]) if len(parts)>2 and parts[0] in ('careers','jobs','recruitment') else host


def identity_evidence(results, offered_url, make_line, claimed_name=''):
    domain=organisation_domain(offered_url)
    trusted=('wikipedia.org','wikidata.org','nasdaq.com','londonstockexchange.com','nyse.com','sec.gov','companieshouse.gov.uk','prh.fi','ytj.fi','reuters.com','bloomberg.com')
    out=[]
    for page in results:
        url=page.get('url','');host=(urlsplit(url).hostname or '').removeprefix('www.')
        independent=any(host==x or host.endswith('.'+x) for x in trusted) or host.endswith(('.gov.uk','.gov.fi','.gov','.gov.se'))
        public_link=host.endswith(('.edu','.ac.uk')) or registrable_domain(url) in ('hel.fi','helsinki.fi','aalto.fi','tuni.fi','oulu.fi','turku.fi','tampere.fi','jyu.fi','utu.fi','uef.fi','lut.fi','abo.fi')
        directory=bool(re.search(r'(?i)member directory|trade association|chamber of commerce|kauppakamari|public register|municipality|kaupunki|kommun',page.get('title','')))
        if registrable_domain(url)==registrable_domain(offered_url):continue
        if not (independent or public_link or directory) or not readable(page.get('text','')):continue
        if independent:public_link=directory=False
        body=page.get('text','')
        country_listing=independent and folded(page.get('title',''))==folded(registrable_domain(offered_url).split('.')[0])
        matches=list(re.finditer(r'(?<![\w.@-])(?:www\.)?'+re.escape(domain)+r'(?![\w.-])',body,re.I))
        match=next((m for m in matches if public_link or directory or re.match(r'^\|\s*(?:https?://)?(?:www\.)?'+re.escape(domain)+r'\s*\|',body[body.rfind('\n',0,m.start())+1:]) or re.search((r'(?i)country|countries|international|Finland|Sweden|Suomi|Sverige|' if country_listing else '(?i)')+r'website|web site|homepage|official|verkkosivu|kotisivu|hemsida|webbplats|honlap',body[body.rfind('\n',0,m.start())+1:body.find('\n',m.end()) if body.find('\n',m.end())!=-1 else len(body)])),None)
        if not match:continue
        start=body.rfind('\n',0,match.start())+1
        end=body.find('\n',match.end())
        if end==-1:end=len(body)
        quote=body[start:end].strip()
        if len(quote)>300:
            start=body.rfind(' ',0,max(start,match.start()-85))+1
            end=body.find(' ',match.end()+60)
            quote=body[start:end if end!=-1 else len(body)].strip()
        if re.search(r'(?i)scam|fraud|impersonat|fake|not (?:their|the|its) (?:official )?website',quote):continue
        # Domain references must be in website/contact metadata or a company description.
        if not (public_link or directory or country_listing or re.match(r'^\|\s*(?:https?://)?(?:www\.)?'+re.escape(domain)+r'\s*\|',quote)) and not re.search(r'(?i)website|web site|homepage|official|verkkosivu|kotisivu|hemsida|webbplats|honlap',quote):continue
        publisher='Wikipedia' if host.endswith('wikipedia.org') else source_name(url)
        r=make_line('Who is behind it',publisher+(' links to '+domain+'.' if public_link or directory else ' names '+domain+" as the organisation's website."),quote,url,page.get('publishedDate'),polarity='reassuring')
        r.update(quote=quote,source_name=publisher,caveat='This connects the domain to the organisation, not a person messaging you.',identity_basis='public_directory_link' if public_link or directory else 'independent_domain_reference',verified_domain=domain,raw_url=url)
        out.append(r)
    if not out and claimed_name:
        out=domain_mismatch(results,offered_url,claimed_name,make_line)
    return out


def registrable_domain(url):
    host=(urlsplit(url if '://' in url else 'https://'+url).hostname or '').removeprefix('www.')
    parts=host.split('.')
    count=3 if len(parts)>2 and len(parts[-1])==2 and parts[-2] in ('co','com','org','net','ac','gov','edu') else 2
    return '.'.join(parts[-count:])


def domain_mismatch(results,offered_url,claimed_name,make_line):
    offered=registrable_domain(offered_url)
    brand=folded(re.split(r'\s[|]\s| - ',claimed_name)[0])
    for page in results:
        host=(urlsplit(page.get('url','')).hostname or '')
        if not host.endswith('.wikipedia.org'):continue
        body=page.get('text','')
        match=re.search(r'(?im)^.*(?:Website|Kotisivu|Webbplats)\s*[|:]\s*(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})[^\n]*',body)
        if not match:continue
        official=registrable_domain(match[1])
        if offered.split('.')[0]!=official.split('.')[0] and folded(page.get('title',''))!=brand:continue
        # A same-brand country variant needs more evidence, never a mismatch by absence.
        if offered==official:continue
        # An explicit link from the confirmed main domain establishes an allowed sibling.
        for candidate in results:
            if registrable_domain(candidate.get('url',''))==official and re.search(r'(?<![\w.@-])(?:www\.)?'+re.escape(offered)+r'(?![\w.-])',candidate.get('text',''),re.I):
                body=candidate['text'];at=body.lower().find(offered.lower())
                start=body.rfind('\n',0,at)+1;end=body.find('\n',at+len(offered))
                quote=body[start:end if end!=-1 else len(body)].strip()
                r=make_line('Who is behind it',official+' links to '+offered+' as another address for the organisation.',quote,candidate['url'],polarity='reassuring')
                r.update(source_name=official,quote=quote,caveat='This links the addresses, not a person messaging you.',identity_basis='confirmed_main_site_link',verified_domain=offered)
                return [r]
        if offered.split('.')[0]==official.split('.')[0]:continue
        r=make_line('Who is behind it','The page uses '+claimed_name+', but Wikipedia lists '+official+' as its website; the supplied address is '+offered+'.',match[0].strip(),page['url'],attention=True,polarity='warning')
        r.update(source_name='Wikipedia',quote=match[0].strip(),caveat='This is an address mismatch, not proof of who operates the supplied page.',positive_mismatch=True,offered_domain=offered,known_official_domain=official,identity_basis='positive_domain_mismatch')
        return [r]
    return []


def confirmed_main_domains(results,offered_url):
    offered=registrable_domain(offered_url)
    domains=[]
    for page in results:
        if not (urlsplit(page.get('url','')).hostname or '').endswith('.wikipedia.org'):continue
        match=re.search(r'(?im)^.*(?:Website|Kotisivu|Webbplats)\s*[|:]\s*(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})[^\n]*',page.get('text',''))
        if match:
            main=registrable_domain(match[1])
            if main!=offered and main.split('.')[0]==offered.split('.')[0]:domains.append(main)
    return list(dict.fromkeys(domains))[:2]


def pressure_sentence(kind,quote):
    if kind=='address_mismatch':return "Your message uses an address outside the organisation's usual sites."
    if kind=='identity_documents':
        item=next((label for pattern,label in IDENTITY_ITEMS if re.search(pattern,quote,re.I)), 'identity details')
        return 'Your message asks for '+item+'.'
    if kind=='messaging_only':
        app=re.search(r'(?i)whatsapp|telegram|signal',quote)
        return 'Your message restricts contact to '+({'whatsapp':'WhatsApp','telegram':'Telegram','signal':'Signal'}[app[0].lower()])+'.' if app else 'Your message says the phone is unavailable.'
    if kind=='link_login':
        if re.search(r'(?i)card\s+(?:number|details)|korttitied|kortin\s+numero',quote):return 'Your message asks for card details through an address it supplies.'
        if re.search(r'(?i)\bpay(?:ing)?\b|maksamalla|maksa\b|suorita\s+maksu',quote):return 'Your message asks for payment through an address it supplies.'
        if re.search(r'(?i)\b(?:cancel|reject|stop|reverse|go\s+to|visit|open|follow|peruuta|estä|avaa|mene|siirry|käy)\b',quote):return 'Your message directs banking action through an address it supplies.'
        return 'Your message asks you to confirm identity or log in through a link.'
    if kind=='bank_access':
        if re.search(r'(?i)\bPIN\b|password|salasana|tunnusluku',quote):return 'Your message asks for a PIN or password.'
        if re.search(r'(?i)card\s+(?:details|number)|korttitied|kortin\s+numero',quote):return 'Your message asks for payment card details.'
        return 'Your message asks for '+('card number and CVV.' if re.search(r'(?i)CVV|CVC|kortin',quote) else 'bank logins.' if re.search(r'(?i)login|credentials|pankkitunn',quote) else 'BankID or mobile authentication.' if re.search(r'(?i)Bank\s*ID|mobiilivarmen',quote) else 'banking or one-time security codes.')
    if kind=='money_transfer':
        app=re.search(PAYMENT_APPS,quote,re.I)
        if app and not re.search(r'(?i)friends|ystävät',quote):return 'Your message directs '+next(name for name in ('Revolut','Wise','MobilePay','PayPal','Venmo','Zelle','Cash App') if app[0].lower().startswith(name.lower()))+" payment to a private payee."
        if re.search(r'(?i)gift|lahjakort|voucher',quote):return 'Your message requests payment with gift cards or vouchers.'
        if re.search(r'(?i)codes?|kood',quote):return 'Your message asks you to send payment codes.'
        if re.search(r'(?i)crypto|krypto|bitcoin|usdt',quote):return 'Your message requests cryptocurrency payment.'
        if re.search(r'(?i)PayPal',quote):return 'Your message requests PayPal friends-and-family payment.'
        if re.search(r'(?i)cash|käteis',quote):return 'Your message requests cash sent by post.'
        if re.search(r'(?i)account|til',quote):return 'Your message requests payment to a private or overseas account.'
        service=re.search(r'(?i)Western Union|Money\s*Gram',quote)
        return 'Your message requests payment through '+('MoneyGram' if 'gram' in service[0].lower() else 'Western Union')+'.' if service else 'Your message requests an unusual payment route.'
    if kind=='deadline':
        return 'Your message sets a deadline: “'+quote+'”.'
    if kind=='no_direct_contact':
        party='landlord' if re.search(r'(?i)landlord|vuokranantaj',quote) else 'company'
        return 'Your message discourages direct '+party+' contact.'
    return {'bank_access':'Your message asks for bank access or security codes.',
            'payment_for_job':'Your message makes payment a condition of getting work.',
            'scarcity':'Your message pressures you with competing interest or scarce availability.',
            'posted_keys':'Your message offers keys by delivery or a third party.',
            'upfront_payment':'Your message asks for an upfront payment.',
            'no_viewing':'Your message says a viewing is unavailable.',
            'low_price':'Your message claims rent below the local level.',
            'unsolicited':'Your message announces your selection.',
            'high_pay':'Your message pairs high pay with little work.'}[kind]
