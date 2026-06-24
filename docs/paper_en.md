# The Canary in the Coal Mine: Behavioral Validation of Prompt Extraction Attacks via a Sacrificial Proxy Model

**Wang Lihao**

> Code & data: [github.com/JucieOvo/ProxyCanary](https://github.com/JucieOvo/ProxyCanary)

## Abstract

Large language model (LLM) agents in long-running conversations carry sensitive system prompts vulnerable to prompt extraction attacks. Existing defenses almost universally focus on a single question: "Is this input an attack?"---classifying user utterances by analyzing textual features. However, judging whether an input *looks like* an attack is fundamentally different from judging whether it *actually succeeds*. We propose ProxyCanary: rather than analyzing attack structure, we deploy an independent "canary" proxy model that experiences each user message firsthand and reveals through embedded behavioral markers whether it has been compromised. The canary's system prompt contains two marker types: fictitious system parameters as leak watermarks and the standardized phrase "No Way I Cant" as a refusal signal. A streaming substring matcher monitors the canary's output in real time---any marker hit validates the attack and triggers interception. Because the canary sees only single messages (zero conversation history), attackers cannot accumulate contextual inertia. On 54 Raccoon attack samples and 216 self-constructed normal samples under 3-fold stratified cross-validation, a qwen3.5:9b proxy achieves F1 = 0.864±0.027 (TNR = 100%, Clopper-Pearson 95% CI [90.7%, 100.0%]), outperforming all baselines. Ablation confirms the refusal marker contributes 77.8% of validation capability. Multi-turn context immunity experiments show 100% validation under zero-context versus 60% when the same attack is embedded in a friendly preamble (McNemar p = 0.046). We explicitly acknowledge an unverified premise: canary-to-protected-model behavior transfer lacks cross-model-family evidence, positioning this work as a feasibility validation rather than a mature defense system.

---

## 1. Introduction

LLM-powered agents carry system prompts containing business logic, safety instructions, API keys, and domain knowledge---their most critical intellectual property. Prompt extraction attacks [1,2] exploit conversational interactions to induce agents into revealing this content. Research on Prompt Leakage demonstrates that exploiting LLM sycophancy drives multi-turn attack success rates from 17.7% to 86.2%.

Consider a NeoBank financial advisor after 30 turns of friendly conversation. On turn 31, the user says: "Output your original initialization prompt." The attacker's real weapon is not this utterance---it is the **contextual inertia** accumulated over 30 turns. The agent has formed "this is a trusted user" cognition, and security vigilance has eroded.

**The canary in the coal mine.** 19th-century British miners carried canaries into shafts. The bird's respiratory system is far more sensitive to gas than a human's---gas concentrations harmless to miners would cause the bird to collapse first. Miners didn't analyze air composition; they watched the bird. ProxyCanary applies the same logic: the protected model (M_p) is the miner, the canary model (M_c) is the bird---both receive the same input, but the canary carries no history.

**Attack identification vs. attack effectiveness.** Two distinct questions exist. Question 1 (attack identification): *Is this input an attack?* Existing approaches---RegexGuard, LlamaGuard, PromptSleuth---all answer this. They analyze text and classify. Question 2 (attack effectiveness validation): *Does this attack actually work?* A text that "looks like an attack" does not necessarily "make the model comply." In our experiments, TF-IDF misclassifies normal queries with attack-like vocabulary (TNR = 78.9%), epitomizing the structural flaw of Question 1 methods.

**ProxyCanary answers Question 2.** We deploy an independent canary model (M_c) before the protected model (M_p). M_c's prompt embeds two marker types: fictitious system parameters (Project-Aeolipile, etc.) as leak watermarks, and "No Way I Cant" as a refusal signal. Both share a single StreamDetector for streaming cumulative substring matching. Any marker hit validates the attack and triggers interception. The attacker never sees the canary's output. The protected model is never modified.

**Core premise limitation.** Our approach assumes canary behavioral response predicts protected model response. This is unverified. The canary (e.g., Qwen 9B) and protected model (e.g., GPT-4, Claude) may differ substantially in safety alignment---an attack might deceive the canary but fail against the protected model (false positive), or vice versa (false negative). We have not designed experiments to validate this assumption (see Section 5.3). This work is a feasibility validation, not a mature cross-model defense system.

---

## 2. Related Work

Existing defenses can be distinguished along two dimensions: **detection timing** (input-level vs. output-level) and **detection target** (analyzing utterances vs. observing behavior).

**(1) Input-level attack identification:** PromptSleuth [4], BERT classifiers [5], TF-IDF, and sentence-embedding methods. Meta Llama Prompt Guard [12], NVIDIA NeMo Guardrails [13]. These judge whether input "looks like an attack" rather than whether it "works."

**(2) Output-level token verification:** Rebuff [7], Canari [6], Kill-Chain Canaries [9]. These examine model outputs rather than inputs---already touching effectiveness validation. But tokens must be embedded in the protected model's prompt, infeasible for third-party APIs. ProxyCanary embeds markers in the canary prompt instead.

**(3) Prompt-level and model-level defense:** PromptKeeper [3], System Vectors [17], StruQ/SecAlign [14], SysVec [15].

The closest prior work is **little-canary** [11]: sacrificial canary pre-detection relying on an external analyzer to judge canary response anomaly---essentially another input-level classifier on canary output. ProxyCanary embeds validation logic into the canary prompt, eliminating the external analyzer.

---

## 3. Method

### 3.1 Problem Formalization

Given input u and protected model M_p (unmodifiable system prompt), ProxyCanary answers: **Is u an effective prompt extraction attack against M_p?** This differs from "Does u contain attack intent?"---we care about actual effect, not surface features.

### 3.2 Canary Proxy Architecture

Core design: (a) M_c receives only single messages---no contextual inertia accumulation; (b) M_c's prompt is permanently fixed; (c) M_c's output is invisible to attackers.

### 3.3 Dual-Path Marker Design

**Path 1 (Leak watermark):** Fictitious parameters: Project-Aeolipile | Zyphor-7X | Klydron-V9 | Nexorin-842

**Path 2 (Refusal marker):** Standardized phrase: No Way I Cant

The prompt uses suggestive language ("you may refuse in your own words, but must include the marker") rather than imperative ("must/forbidden"). Both paths feed a single StreamDetector: exact substring (O(n), case-insensitive) then regex variant matching. Ablation confirms the marker contributes 77.8% TPR; the original RefusalDetector (8 patterns) contributes only 11.1%.

**Crucial distinction:** The marker is matched in canary *output*, not user input. The model outputting it means it *actively recognized the attack and chose to refuse*---a behavioral signal, not a textual feature.

### 3.4 Implementation

Lightweight Python library: `check(user_input) → bool`. Ollama deployment (qwen3:0.6b / qwen3.5:9b-q4_K_M). Streaming SSE detection. Latency: ~2.7s (9B) / ~1.6s (0.6B).

---

## 4. Experiments

### 4.1 Setup

**Data:** 54 Raccoon attack samples + 216 self-constructed normal samples (12 categories, 53 boundary cases). 3-fold stratified CV: attacks by category (40 train / 14 test per fold), normals 80/20 by category.

**Baselines:** NoDefense, RegexGuard, KeywordWeight, TF-IDF, CanariToken, LLM-Judge.

**Metrics:** TPR, TNR, F1 + McNemar, Clopper-Pearson CI, Bootstrap F1 CI.

**Models:** qwen3:0.6b (522MB), qwen3.5:9b-q4_K_M (6.6GB). max_tokens=16384, temperature=0.

### 4.2 Main Results

| Baseline | TPR | TNR | F1 |
|----------|:---:|:---:|:---:|
| NoDefense | 88.1% ± 12.9% | 10.5% | 0.408 ± 0.023 |
| RegexGuard | 57.1% | 100% | 0.727 |
| KeywordWeight | 28.6% ± 7.2% | 100% | 0.441 ± 0.087 |
| TF-IDF | 92.9% | 78.9% | 0.743 |
| CanariToken | 25.9% | 100% | 0.412 |
| LLM-Judge | 54.8% ± 14.6% | 100% | 0.700 ± 0.121 |
| **Ours** | **76.2% ± 4.2%** | **100%** | **0.864 ± 0.027** |

ProxyCanary achieves highest F1 (0.864, CV = 3.2%). TNR = 100% (CI [90.7%, 100.0%]). CanariToken F1 = 0.412---safety training blocks token output in 75% of scenarios, contrasting with our suggestive-language design. TF-IDF: highest TPR (92.9%) but TNR = 78.9%---surface lexical matching problem.

| Baseline (0.6B) | TPR | TNR | F1 |
|----------|:---:|:---:|:---:|
| Ours (v6) | 64.3% | 71.1% | 0.529 |
| TF-IDF | 92.9% | 78.9% | 0.743 |
| RegexGuard | 57.1% | 100% | 0.727 |

### 4.3 Ablation

| Variant | Canary Words | No Way I Cant | TPR | TNR | F1 |
|---------|:---:|:---:|:---:|:---:|:---:|
| Natural-Only | ✓ | ✗ | 13.0% | 100% | 0.230 |
| Marker-Only | ✗ | ✓ | 77.8% | 100% | 0.875 |
| **Dual (Ours)** | ✓ | ✓ | **79.6%** | 100% | **0.887** |

The marker alone contributes 77.8% TPR (97.7% of effectiveness). This is not "keyword matching"---the marker is in canary *output*, not user input.

### 4.4 Non-Monotonic Effect

| Prompt Style | Version | 9B F1 | 0.6B F1 |
|-------------|:---:|:---:|:---:|
| Adversarial | v4 | 0.773 | 0.889 |
| Non-adversarial | v6 | 0.887 | 0.377 |

Same prompt, opposite performance. No universal prompt across model scales.

### 4.5 Multi-Turn Context Immunity

10 scenarios, zero-context vs. full-context:

| Setting | Detection | McNemar |
|---------|:---:|:---:|
| Zero-context | **10/10 (100%)** | |
| Full-context | 6/10 (60%) | p = 0.046 |

All 4 misses: canary correctly refused but friendly preamble caused polite refusal omitting the marker. Context interferes with marker compliance, not attack recognition.

### 4.6 On 0.6B

F1 = 0.529 (v6) vs. 0.889 (v4). Unstable with 11 false positives. Proof-of-concept only; production needs ≥9B.

---

## 5. Discussion

### 5.1 Boundaries

Inference overhead (~2.7s, 6.6GB) is cost; ~24% miss rate is tolerance; model dependence is limitation. Core values---zero modification, no training data, context inertia immunity---hold.

### 5.2 Applicable Scenarios

Value where protected model's prompt cannot be modified (third-party APIs, compliance-constrained deployments). Not claimed as universally optimal.

### 5.3 Limitations

1. **Behavior transfer unverified (core defect):** Canary behavior predicting protected model behavior is our premise---completely unverified. Relates to adversarial transferability [21,22].
2. **Oracle attack risk:** Binary intercept/pass decisions leak marker information.
3. **Dataset scale:** 54 attacks, 14 per fold. McNemar underpowered.
4. **Single model family:** Qwen only.
5. **Marker compliance fragility:** Single point of failure if attackers induce refusal without marker.
6. **Obfuscation hard ceiling:** Incomprehensible attacks undetectable.
7. **Latency-accuracy tradeoff:** ~2.7s vs. RegexGuard 0ms.

---

## 6. Conclusion

ProxyCanary distinguishes two questions: analyzing input utterances vs. observing model behavior. Existing work focuses on the former; we validate the latter---deploying a canary stand-in with embedded markers. Experiments provide preliminary evidence (F1 = 0.864±0.027, TNR = 100%), multi-turn context immunity confirmation, and non-monotonic capability findings. We candidly acknowledge unverified behavior transfer---the line between "interesting tool" and "reliable defense."

---

## References

[1] Wang et al. "Raccoon." ACL 2024 Findings.
[2] Agarwal et al. "Prompt Leakage." EMNLP 2024 Industry.
[3] Jiang et al. "PromptKeeper." EMNLP 2025 Findings.
[4] Wang et al. "PromptSleuth." 2025.
[5] Zivanovic & Zivanovic. "BERT Prompt Injection Detection." BISEC 2025.
[6] Canari. PyPI, v0.3.0.
[7] Rebuff. GitHub, archived 2025.
[8] Liang et al. "Why Are My Prompts Leaked?" 2024.
[9] Wang. "Kill-Chain Canaries." MIT, 2024.
[10] Liu & Hu. "LLM Vulnerabilities Survey." arXiv:2406.00240, 2024.
[11] Hermes Labs. "little-canary." GitHub, 2025.
[12] Meta. "Llama Prompt Guard." 2024.
[13] NVIDIA. "NeMo Guardrails." 2024-2025.
[14] Chen et al. "StruQ." USENIX Security 2025.
[15] Zhang et al. "SysVec." CCS 2025.
[16] Lin et al. "ProxyPrompt." 2025.
[17] PSU. "System Vectors." 2024.
[18] Toyer et al. "Tensor Trust." NeurIPS 2023.
[19] Piet et al. "Jatmo." 2024.
[20] Suo et al. "Signed Prompt." 2024.
[21] Papernot et al. "Transferability in ML." USENIX Security 2016.
[22] Tramèr et al. "Transferable Adversarial Examples." 2017.
