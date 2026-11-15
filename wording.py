"""Short presentation text, kept separate from evidence and source decisions."""
import copy
import re


def reply_parts(facts, rows, identity=False):
    kinds={r.get('pressure_kind') for r in rows}
    kind=facts.get('kind')
    opening='Thank you for the offer. Could you please:'
    if kind=='rental':
        asks=[('Send ownership proof or agency registration and a verifiable phone number.' if kinds & {'messaging_only','no_direct_contact'} else 'Show proof of ownership or your letting agency registration.'),
              'Arrange a viewing before any deposit.',
              'Send the tenancy agreement, full rent and all charges.']
    elif kind=='job':
        asks=[] if identity else [('Send your registered company name, number and verifiable phone contact.' if kinds & {'messaging_only','no_direct_contact'} else "Send the company's registered name and number.")]
        asks.append('Send a written contract with the pay and duties.')
        if kinds & {'upfront_payment','money_transfer','payment_for_job'}:asks.append('Confirm no payment is required to get this job.')
    elif kind=='parcel':
        opening='Before I use this link, could you please:'
        asks=['Send the tracking number and the official fee notice.']
    elif kind=='shop':
        opening='Before I order, could you please:'
        asks=[] if identity else ['Send the registered business name and address.']
        asks+=['Confirm the full price, delivery and return terms.']
        if kinds & {'upfront_payment','money_transfer'}:asks.append('Offer a protected payment method.')
    else:
        asks=[] if identity else ["Provide your organisation or ownership details and a verifiable contact."]
        asks.append('Send the full offer and its terms in writing.')
    if 'identity_documents' in kinds:
        asks.append('Explain why you need my identity details now.')
    elif kinds & {'messaging_only','no_direct_contact'} and not any('phone' in ask for ask in asks):
        asks.append('Provide a working phone number I can verify independently.')
    closing=('I will never share bank logins or codes, or pay before verification.' if 'bank_access' in kinds else 'I will not send money or documents before then.' if kinds else 'Thank you. I will check the details before proceeding.')
    return dict(opening=opening,asks=asks[:4],closing=closing)


def reply_text(parts):
    if not parts['asks'] and not parts['closing']:return parts['opening']
    return parts['opening']+'\n'+'\n'.join(f'{i}. {ask}' for i,ask in enumerate(parts['asks'],1))+'\n'+parts['closing']


def unknown_text(row):
    text=row.get('finding','').lower();check=row.get('check','')
    if check=='Recorded case provenance':return 'Authority report, not an original offer.'
    if check=='Source':
        if 'root' in text:return 'Offer page unreadable; homepage only.'
        if 'classif' in text:return 'Offer type is unclear.'
        if 'warning or report' in text:return 'Authority report, not an original offer.'
        return 'Page reading did not finish.'
    if check=='Who is behind it':
        if 'country' in text:return 'Company register: country not stated in the offer.'
        if 'no independent' in text:return 'No independent mention found; common for local sites.'
        if 'no named' in text or 'not extracted' in text:return "The sender's organisation was not named."
        return 'Organisation details were not confirmed.'
    if check=='Copies':return 'Copies: no sentence to compare.' if 'distinctive' in text else 'Copies: no exact match found.'
    if check=='What others say':return 'Warnings: no matching report found.' if 'no matching' in text else 'Warning search did not finish.'
    if check=='Pressure signs':return 'Message wording could not be read.'
    if check=='How old it is':return 'Site history was not checked.'
    if check=='Too good to be true':return 'Price comparison was not checked.'
    return 'This check did not finish.'


def present(row):
    r=dict(row)
    if r.get('origin') in ('exa','web_search'):return r
    text=r.get('finding','');source=r.get('source_name','')
    if r.get('positive_mismatch'):
        r['finding']=f"Wikipedia names {r['known_official_domain']}; this page uses {r['offered_domain']}."
        r['polarity']='warning'
    elif r.get('polarity')=='could not check' or r.get('check')=='Recorded case provenance':
        r['finding']=unknown_text(r)
    elif r.get('official_warning'):
        target=r.get('anchor') or next(iter(re.findall(r'\b[a-z0-9-]+\.(?:com|fi|org|net|co\.uk)\b',text,re.I)), 'this address')
        r['finding']=source+' names '+target+' in a '+('ghost-store' if 'ghost store' in text.lower() else 'public')+' warning.'
    elif r.get('identity_basis')=='site_self_description':
        title=r.get('quote','');words=title.split()
        title=' '.join(words[:9])+('…' if len(words)>9 else '')
        r['finding']=source+' publishes “'+title+'”.'
    elif r.get('check')=='What others say' and 'unlock' in text.lower():
        r['finding']="Australia's Scamwatch describes paying to unlock job tasks."
    elif r.get('check')=='What others say' and 'below-market rental' in text.lower():
        r['finding']="The UK's Action Fraud describes rental deposits before viewings."
    elif r.get('check')=='Copies' and source:
        r['finding']=source+' repeats a sentence from this offer.'
    elif r.get('check')=='Source':
        r['finding']=('Exa returned text; its age is unknown.' if 'text returned by exa' in text.lower() else 'You supplied this message; its claims are unverified.' if 'pasted message' in text.lower() else 'Authority report, not an original offer.')
    return r


def recording(case, finish):
    case=copy.deepcopy(case)
    for item in case['events']:
        event=item['event']
        if event['type']=='evidence':event['data']=present(event['data'])
        elif event['type']=='done':
            old=event['data']
            current=finish(old.get('findings',[])+old.get('unavailable',[]),old.get('facts',{}),old['overall']!='We could not read this page',old.get('seconds',0))
            for key in ('overall','checked_at','seconds','polarity'):current[key]=old[key]
            event['data']=current
    return case
