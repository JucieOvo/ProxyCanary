import asyncio, sys
sys.path.insert(0, '.')
from guard4promptattack.canary.llm import stream_canary_response
from guard4promptattack.canary.prompt import DEFAULT_CANARY_PROMPT
from guard4promptattack.config import GuardConfig
from benchmark.evaluator import load_raccoon_attacks, AblationRefusalOnly, make_config

async def main():
    config = make_config()
    r = AblationRefusalOnly(config)
    attacks = load_raccoon_attacks(singular=True, compound=True)

    fns = []
    for a in attacks:
        d = await r.detect(a["text"])
        if not d:
            fns.append(a)

    print(f"Abl-Refusal FN: {len(fns)}/{len(attacks)}\n")

    for a in fns:
        acc = ""
        try:
            async for chunk in stream_canary_response(config, DEFAULT_CANARY_PROMPT, a["text"]):
                acc += chunk
        except Exception as e:
            acc = f"[ERROR: {e}]"
        print(f"[{a['category']}]")
        print(f"  Input:  {a['text'][:150]}")
        print(f"  Reply:  {acc[:300]}")
        print()

asyncio.run(main())
