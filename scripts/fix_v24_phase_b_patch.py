from pathlib import Path

patch_path = Path('scripts/v24_phase_b_patch.py')
text = patch_path.read_text()
old = '''replace_once(\n    'app.js',\n    "    weeklyGross, repoSuggestion, geo, fatigue, origin, dest,",\n    "    weeklyGross, geo, fatigue, origin, dest,",\n    'remove duplicate repo suggestion input'\n)'''
new = '''# Scope this edit to the one final buildUnifiedDecisionContract({...}) call.\n# The same field list also appears in compatibility/render destructuring and\n# must not be changed there.\np_app = Path('app.js')\napp_text = p_app.read_text()\ncall_start = app_text.find("  const unifiedDecision = buildUnifiedDecisionContract({")\nif call_start < 0:\n    raise SystemExit('canonical contract call start not found')\ncall_end = app_text.find("  });\\n  _mwRenderDecision", call_start)\nif call_end < 0:\n    raise SystemExit('canonical contract call end not found')\ncall_block = app_text[call_start:call_end]\nneedle = "    weeklyGross, repoSuggestion, geo, fatigue, origin, dest,"\nif call_block.count(needle) != 1:\n    raise SystemExit(f'canonical contract repoSuggestion field: expected 1 scoped match, found {call_block.count(needle)}')\ncall_block = call_block.replace(needle, "    weeklyGross, geo, fatigue, origin, dest,", 1)\np_app.write_text(app_text[:call_start] + call_block + app_text[call_end:])'''
if text.count(old) != 1:
    raise SystemExit(f'Phase B matcher block: expected 1 match, found {text.count(old)}')
patch_path.write_text(text.replace(old, new, 1))
Path('scripts/fix_v24_phase_b_patch.py').unlink()
