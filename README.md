# Is this real?
Check a job or flat offer before sending money or documents, with sourced findings and an editable reply.
Live: https://is-this-real-junction.vercel.app

## Try it in a minute
1. Paste this message:
   > Congratulations! You have been selected for the remote data entry role at Nordic Staffing Partners, 38 euros an hour. To activate your account, buy a 120 euro starter kit with Apple gift cards and send the codes today. Reply only on Telegram. Offer expires in 2 hours.
2. Tick the box confirming that you removed personal details, then check it. The verified public example says **Do not send money or documents yet**, marks seven signs and shows a US Postal Inspection Service source found with Exa.
3. Read the source beside the marked words and edit the reply. Nothing is sent from the page.

## How it works
- English and Finnish rules mark payment, identity-document, credential, deadline and restricted-contact demands.
- Exa searches for official pattern warnings, organisation information and copies of the wording.
- Each message check uses at most three Exa calls. Identical queries can reuse cached evidence.
- Source guidance describes a pattern, not the sender. Missing results do not prove safety or wrongdoing.
- The server returns a plain overall line, pinned findings and a reply asking for the missing proof.

## Run locally
Python 3.11 or newer, from this repository's root:
```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
REAL_LIVE_ENABLED=0 python -m uvicorn real_app:app --host 127.0.0.1 --port 8182
```
In another terminal:
```sh
curl --fail http://127.0.0.1:8182/api/status
```
Without a key, pasted messages still get wording checks and a clear statement that no web search ran. Link checks return 503 rather than pretending to have read the page. Five dated recordings can replay without credentials.
Live web checks need `EXA_API_KEY` and `REAL_LIVE_ENABLED=1`. An explicit `EXA_ENV_FILE` can supply a local key; hosted deployments use environment variables. The current checker makes no model calls.
The shared retrieval client retains optional model settings, but this checker does not call a model.

## Deploy on Vercel
Import this repository with its root as the project root and the supplied `vercel.json`.
Install from `requirements-vercel.txt`, which includes the runtime requirements. The entry point is `api/index.py`.
Set `EXA_API_KEY` as a secret and `REAL_LIVE_ENABLED=1` to enable web checks. Leave live checks disabled for a no-key recording/message demo.
Set `REAL_BUDGET_USD` and `REAL_LEDGER` deliberately. The SQLite ledger is local to the filesystem; it is not a shared global account cap across serverless instances. Keep provider credit limits in place.
Never commit a key or `.env` file. `.env.example` lists configuration names.

## Tests
```sh
REAL_LIVE_ENABLED=0 python api/check.py
```
Checks the real public app without network access: page response, message findings, no-search disclosure and the no-key link refusal.

## Limits
It reports what sources say and never accuses a named person or company.
This is not identity verification, a guarantee of safety or a replacement for checking independently.
Wording rules can miss new phrases. Address-shape findings do not establish ownership.
The verified seven-sign example needs live Exa access for its web source; the no-key demonstration does not reproduce a live search.
Rate limiting and filesystem budget accounting are best effort across multiple hosted instances.

## Licence and credits
MIT, see LICENSE. Font licences are included with the static assets.
Exa supplies web retrieval. Authorities and publishers own the linked warnings and quoted source text. Stored public recordings retain their evidence dates.
