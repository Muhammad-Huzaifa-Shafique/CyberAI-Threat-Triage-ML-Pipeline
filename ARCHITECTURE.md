# CyberAI architecture

This note explains how the two parts of CyberAI that are not in this repository work: the machine-learning scoring pipeline and the chat assistant. This repository holds the standalone triage tool (`CyberAI.py`, described in the README). The source of the pipeline and the assistant is not published yet.

The excerpts below are copied from the working copy of the project. Typography is simplified to plain ASCII, and `...` marks a shortened body. Nothing in this note is a measured result. Accuracy has not been measured, and the section "What is not measured" says why.

Interactive explainers for the same rules are on the [CyberAI page](https://muhammad-huzaifa-shafique.github.io/cyberai.html).

## The parts

| Part | What it does | Where |
|---|---|---|
| Triage tool | Scores a link, an email or a PDF with fixed points and lists the reasons | `CyberAI.py` in this repository |
| Scoring pipeline | Builds features, scores indicators with a classifier, an outlier detector and a risk regression, watches for drift, and queues unsure cases for a person | `CyberAI.py` in the working copy (a larger file than the one here) |
| Chat assistant | Answers questions from a local cache and shows its evidence | `CyberAI_chat.py` and `app_chat.py` |
| Earlier triage tool | Can be called by the pipeline as an optional second opinion | `threat_triage.py` |

The pipeline has a command line (`train`, `evaluate`, `evaluate_holdout`, `score`, `review`, `label`, `serve` and others). When FastAPI is installed it also runs as a small HTTP service with `GET /healthz` and `POST /score`.

## 1. Features

`extract_features()` turns every record into numbers. Which numbers depends on the record type:

- domains and URLs: length, Shannon entropy, a rank for the top-level domain, and endpoint heuristics (digit ratio, how many of the words api, login, secure and update appear, hyphen count, unusual port)
- hashes: length and the share of hexadecimal characters
- IP addresses: mean and spread of the octets
- text: word count
- events: a rare-event flag and a failed ratio

~~~python
def _shannon_entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    total = float(len(value)) or 1.0
    return -sum((count / total) * math.log2(count / total) for count in counts.values())
...
def extract_features(record: IndicatorRecord) -> Dict[str, Any]:
    ...
    if record.indicator_type in {"domain", "url"}:
        feats.update(
            {
                "length": len(record.indicator_value),
                "entropy": _shannon_entropy(record.indicator_value),
                "tld_rank": _tld_rank(record.indicator_value),
            }
        )
        feats.update(_fake_api_heuristics(record.indicator_value))
~~~

## 2. Classifier

`SimpleModel` joins the numeric features with a small bag of words over each record's text (tokens of three or more letters or digits, vocabulary capped at the 300 most frequent) and fits a logistic regression. The feature names and the vocabulary are frozen when the model is fitted, so new records are always vectorized the same way. If the training labels contain only one class, it falls back to a dummy model that predicts the most frequent class instead of failing.

~~~python
class SimpleModel:
    ...
    def fit(self, records: Sequence["IndicatorRecord"]):
        # 1) Freeze numeric schema and vocab on *training set*
        self.feature_names_ = self._numeric_feature_keys(records)
        self.vocab_ = self._fit_vocab(records)

        # 2) Build matrix and fit a safe model (falls back to Dummy if single-class)
        X = self.vectorize(records)
        y = _y_from_records(records)

        uniq = np.unique(y)
        if uniq.size < 2:
            self.model = DummyClassifier(strategy="most_frequent")
            self.model.fit(X, y)
            return self

        self.model = LogisticRegression(max_iter=1000)
        self.model.fit(X, y)
        return self
~~~

Labels become 0 or 1 in one place. Anything that is not a malicious-like value counts as 0:

~~~python
def _y_from_records(records):
    """Map record labels to {0,1}. Adjust the mappings if your labels differ."""
    def to_bin(v):
        return 1 if v in (1, True, "1", "malicious", "bad", "evil") else 0
    return np.array([to_bin(getattr(r, "label", 0)) for r in records], dtype=int)
~~~

## 3. Outliers and risk

An Isolation Forest scores how unusual a record is compared with the training data. The code negates scikit-learn's `score_samples`, so a higher value means more anomalous. About 5% of the training points are treated as outliers.

~~~python
class AnomalyDetector:
    ...
    def fit(self, records: Sequence[IndicatorRecord]) -> None:
        ...
        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X)
        self.model = model
    ...
    def score(self, records: Sequence[IndicatorRecord]) -> List[float]:
        ...
        # higher score = more anomalous
        return (-self.model.score_samples(X)).tolist()
~~~

A separate elastic-net regression predicts a risk score between 0 and 1. Its target is each record's `severity` divided by 10, and its predictions are clipped to the 0 to 1 range.

~~~python
class RegressionRiskModel:
    ...
    def _prepare_targets(self, records: Sequence[IndicatorRecord]) -> List[float]:
        return [float(r.severity) / 10.0 for r in records]
    ...
    def fit(self, records: Sequence[IndicatorRecord]) -> None:
        ...
        model = ElasticNet(max_iter=500, l1_ratio=0.5)
        model.fit(X_np, y_np)
        self.model = model
    ...
    def predict(self, records: Sequence[IndicatorRecord]) -> List[float]:
        ...
        preds = np.clip(self.model.predict(X_np), 0.0, 1.0)
~~~

## 4. Drift

The drift monitor stores each numeric feature's mean and standard deviation at training time. For a new batch it compares each feature's mean with its baseline, in units of the baseline standard deviation, and averages the result across features. It raises an alert when that average is above 0.25. The threshold can be changed in the settings.

~~~python
class DriftMonitor:
    ...
    def detect(self, records: Sequence[IndicatorRecord]) -> Dict[str, Any]:
        if not self.baseline:
            return {"alert": False, "score": 0.0}
        features = [extract_features(r) for r in records]
        score_total = 0.0
        comparisons = 0
        for key, (base_mean, base_std) in self.baseline.items():
            values = [float(feat.get(key, 0.0)) for feat in features]
            if not values:
                continue
            current_mean = statistics.fmean(values)
            comparisons += 1
            denom = base_std + 1e-6
            score_total += abs(current_mean - base_mean) / denom
        drift_score = score_total / comparisons if comparisons else 0.0
        return {"alert": drift_score > self.threshold, "score": drift_score}
~~~

## 5. Review queue

A record whose probability is within 0.15 of 0.5 (so between 0.35 and 0.65) is written to a SQLite table for a person to look at.

~~~python
class ScoringPipeline:
    ...
    def score(self, records: Sequence[IndicatorRecord], enqueue_uncertain: bool = True) -> List[Dict[str, Any]]:
            ...
            if enqueue_uncertain and abs(prob - 0.5) < 0.15:
                REVIEW_QUEUE.enqueue(record, prob, anomaly)
~~~

~~~sql
CREATE TABLE IF NOT EXISTS review_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    context_text TEXT,
    probability REAL,
    anomaly_score REAL,
    label TEXT
)
~~~

Two commands let a person work through the queue. `review` lists the pending items, highest probability first, and `label` stores benign, malicious or unknown for one item. The code calls this an active-learning queue, but nothing in the working copy feeds those labels back into training.

~~~python
@cli.command()
@click.option("--limit", default=10, type=int)
def review(limit: int) -> None:
    """Display pending items in the active learning review queue."""
    items = REVIEW_QUEUE.fetch_pending(limit=limit)
    click.echo(json.dumps(items, indent=2))
...
@cli.command()
@click.option("--id", "item_id", type=int, required=True)
@click.option("--label", type=click.Choice(["benign", "malicious", "unknown"]), required=True)
def label(item_id: int, label: str) -> None:
    """Label a queued item and persist the feedback."""
    REVIEW_QUEUE.update_label(item_id, label)
    click.echo(f"Updated item {item_id} with label {label}")
~~~

## 6. Optional second opinion from the earlier triage tool

When `use_ttt` is on, URLs, and text that contains a link, are also sent to the earlier triage tool. Its verdict is mapped to a probability and blended with the classifier's probability, with weights of 0.6 and 0.4 by default.

~~~python
class TTTAdapter:
    ...
    MAP = {"Clean": 0.1, "Suspicious": 0.5, "Malware": 0.9}
~~~

~~~python
class ScoringPipeline:
    ...
    def score(self, records: Sequence[IndicatorRecord], enqueue_uncertain: bool = True) -> List[Dict[str, Any]]:
        probabilities = self.classifier.predict_proba(records)
        new_probs = self.classifier.predict_proba(records)
        ...
        probs = []
        for np_, tp_ in zip(new_probs, ttt_probs):
            if tp_ is None:
                probs.append(np_)
            else:
                probs.append(self.w_new * np_ + self.w_ttt * float(tp_))
        ...
        for record, prob, anomaly, risk in zip(records, probabilities, anomaly_scores, risk_scores):
~~~

The blended list `probs` is not what the result loop reads, which is the first known issue at the end of this note.

## 7. The chat assistant

The chat assistant (`CyberAI_chat.py`) is offline-first. For each message it works in this order:

1. If the message contains a URL, a file or an email, it runs the triage tool and shows the result.
2. Otherwise it searches the local cache. The cache is indexed with TF-IDF (single words, English stop words removed) and queried by cosine similarity, and the top 4 matches are kept.
3. If at least one match scores 0.18 or higher, it answers from the cache.
4. If not, and offline-only mode is on, it says there is not enough local material.
5. If not, and online mode is allowed, it tries a public-web fallback, an indicator lookup and a quick live ingest, then searches again. If that still finds nothing relevant, it says so.

~~~python
class CacheIndex:
    ...
    def build(self):
                ...
                self.vec = TfidfVectorizer(ngram_range=(1,1), max_df=0.95, min_df=1, stop_words="english")
    ...
    def search(self, q: str, k: int = TOP_K) -> List[Tuple[float, Dict]]:
            ...
            sims = cosine_similarity(qv, self.mat).ravel()
~~~

~~~python
MIN_SIM = float(os.environ.get("CY_MIN_SIM", "0.18"))          # similarity required to trust offline answer
MIN_DOCS = int(os.environ.get("CY_MIN_DOCS", "1"))             # min #docs to accept offline only
TOP_K = int(os.environ.get("CY_TOPK", "4"))                   # candidates shown in evidence
~~~

~~~python
hits = INDEX.search(q, k=TOP_K)
strong = [h for h in hits if h[0] >= MIN_SIM]
verdict = "Answer derived from local cache" if len(strong) >= MIN_DOCS else "Cache too weak"

if strong:
    payload = make_answer_from_docs(q, strong)
~~~

The answer shown first is extractive. The code splits the best documents into sentences, scores each sentence by how often the question's terms appear in it, plus half of the document's similarity, plus a small bonus for the first three sentences, and keeps the top three that are not near-duplicates. Each reply has the answer, a line saying why, and the evidence: the source path, its similarity score and the sentences that matched.

~~~python
# score: term coverage + small boost from doc similarity + early-sentence bias
term_hits = sum(low.count(t) for t in term_set)
if term_hits == 0 and q_terms:
    continue
s_score = term_hits + 0.5 * float(score) + (0.15 if idx <= 2 else 0.0)
~~~

After a triage run in the console chat, and after each answer in the web chat, the question and the answer are saved as a pair under `cache/qa/`. The next index rebuild includes them, so an earlier answer can come back later as evidence. This is the "self-training" in the code comments. Nothing is trained: the pairs are added to the search index. Of the 25 pairs in the working copy, 18 are triage assessments and 7 have the saved answer None.

~~~python
def learn_from_chat_turn(question: str, answer_text: str):
    qa_dir = CACHE_DIR / "qa"
    qa_dir.mkdir(parents=True, exist_ok=True)
    rec = {
        "text": f"Q: {question}\nA: {answer_text}",
        "kind": "qa",
        "ts": int(time.time())
    }
    write_jsonl(qa_dir / "pairs.jsonl", rec)
~~~

### Optional language-model answer

When a language model is available, it writes the answer text from the evidence passages and replaces the extractive answer. The provider comes from `CY_LLM_PROVIDER`. If that is not set, OpenAI is used when `OPENAI_API_KEY` exists, Ollama when a local server answers within 1.5 seconds, and otherwise no model is used. The defaults are the Ollama model `llama3` (`gpt-4o-mini` for OpenAI) and temperature 0.3, with a 1,500-token cap on OpenAI replies. If the local Ollama server is not running, the model call returns an empty string and the assistant keeps the extractive answer.

~~~python
def _autodetect_llm_provider():
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if _ollama_ready():
        return "ollama"
    return "none"

LLM_PROVIDER   = (os.environ.get("CY_LLM_PROVIDER") or "").lower() or _autodetect_llm_provider()
USE_GENERATIVE = os.environ.get("CY_USE_GENERATIVE", "1") == "1"
 # 'ollama' | 'openai' | 'none'
LLM_MODEL      = os.environ.get("CY_LLM_MODEL", "llama3")     # ollama: 'llama3','qwen2','mistral'...
LLM_MAX_TOKENS = int(os.environ.get("CY_LLM_MAX_TOKENS", "1500"))
LLM_TEMPERATURE= float(os.environ.get("CY_LLM_TEMPERATURE", "0.3"))
~~~

The prompt asks for inline citations numbered like the evidence list, and tells the model not to invent facts:

~~~python
def build_rag_prompt(question: str, snippets: list[dict], mode: str = "long") -> str:
    """
    'snippets' are the evidence you already show below the green box.
    We ask the model to cite them as [1], [2], ... according to list order.
    """
    lines = []
    lines.append("You are a cybersecurity assistant. Write a clear, factual, structured answer.")
    lines.append("Cite evidence inline with bracketed numbers [1], [2], ... referring to the sources below.")
    lines.append("Do NOT invent facts not supported by the sources. If sources are weak or off-topic, say so briefly.")
    if mode == "long":
        lines.append("Give a thorough, multi-paragraph explanation with bullets where helpful.")
    else:
        lines.append("Keep it concise (one paragraph).")
    lines.append("")
    lines.append(f"Question: {question.strip()}")
    lines.append("")
    lines.append("Sources (use these for citations):")
    for i, s in enumerate(snippets, start=1):
        src = s.get("path","")
        txt = (s.get("snippet","") or "").replace("\n"," ")
        lines.append(f"[{i}] {src} :: {txt[:600]}")  # cap each source to keep prompt small
    lines.append("")
    lines.append("Now write the answer with inline citations like [1], [2], then stop.")
    return "\n".join(lines)
~~~

A second prompt writes a short summary of a URL triage result:

~~~python
prompt = (
    "You are a SOC analyst. Write 4-6 concise sentences summarizing this URL triage. "
    "State overall risk, why, and concrete next steps for IR.\n"
    f"URL: {url}\nTRIAGE JSON:\n```json\n{json.dumps(triage, ensure_ascii=False)}\n```"
)
llm_out = (_llm_openai(prompt) or _llm_ollama(prompt) or "").strip()
if len(llm_out) > 30:
~~~

## 8. Embedding index

The source also has code that loads a FAISS index built with `sentence-transformers/all-MiniLM-L6-v2`. The working copy holds the manifest of one such index: 20,000 rows, 384 dimensions, built from Hugging Face phishing data imported into the cache. The chat in this version does not call that code, so the search that decides whether to answer is TF-IDF only.

## 9. What is not measured

- **No accuracy figure.** The code has a hold-out evaluation command (`evaluate_holdout`, a random 80/20 split of the manifest), but the working copy has no model file and no evaluation output.
- **The training data in the working copy cannot support a meaningful test.** The manifest that `train` reads by default has 450 records: 25 MalwareBazaar file hashes labeled `malicious`, 375 web pages and 50 RSS items labeled `unknown`. The training code counts every label other than a malicious one as benign. A classifier could tell the two groups apart by record type alone, without learning anything about threats. In that manifest the `severity` field also takes one value per source, so the risk regression has the same problem.
- **The assistant's search has no question set.** There is no list of questions with known right passages, so there is no recall figure for the TF-IDF search.
- **The review queue is empty,** so it has not been exercised on stored data.
- **The cache is not real-time threat intelligence.** Live feeds were hard to scrape reliably, so the cache was seeded with public cybersecurity datasets from Hugging Face.

What would make it measurable: a labeled public phishing dataset, a split made before training, precision and recall reported next to the hand-set triage score, and a short list of questions with known right passages for the assistant.

## Known issues

These come from reading the code. None of them is fixed in this note.

1. The second-opinion blend in `ScoringPipeline.score` is computed and then not used. The loop that builds each result reads `probabilities`, the classifier-only list, so the earlier triage tool does not change the output. Iterating over `probs` instead would fix it.
2. `MIN_DOCS` only changes the verdict label. The branch that answers from the cache tests `if strong:`, so with `MIN_DOCS` above 1 the assistant would still answer from a single strong match while labeling the cache too weak.
3. `_llm_openai` returns an error string instead of raising. In `generate_answer_llm` that text replaces the extractive answer. In `summarize_triage`, which calls `_llm_openai(prompt) or _llm_ollama(prompt)`, the text passes the 30-character length check and is returned as the summary, so Ollama is never tried when OpenAI is not set up.
4. The drift monitor divides by the baseline standard deviation plus 1e-6. A feature that never varied in the training data has a standard deviation of 0, so any change in it gives an enormous score that dominates the average. Features that a record type does not have are filled with 0.0, which can move a batch mean by itself.
5. The embedding-index loader is defined but not called (section 8).
6. Saved answers become evidence (section 7). Because answers are written back into the indexed cache, a wrong answer can be retrieved later as if it were a source, and the 7 pairs whose answer is None are searchable too.

One name promises more than the code does: `LLMReasoner` in the pipeline is not a language model. After redacting email addresses and key-like strings, it returns the first two sentences and counts five keywords. It is off unless `ENABLE_LLM` is set.
