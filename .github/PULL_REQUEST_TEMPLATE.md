## Summary

<!-- What does this PR do? One paragraph max. -->

## Type of change

- [ ] Bug fix
- [ ] New detection rule (YAML)
- [ ] New behavioral heuristic
- [ ] New eBPF hook
- [ ] Frontend feature
- [ ] Documentation
- [ ] Refactor / cleanup
- [ ] Other

## Changes

<!-- List the key changes made. -->

-
-
-

## Testing

<!-- How did you test this? -->

- [ ] `make attack-test` — no regressions (19/27 or better)
- [ ] Manually verified the new detection fires correctly
- [ ] Frontend compiles: `cd frontend && npm run build`
- [ ] `DEMO_MODE = true` still works

## Checklist

- [ ] New YAML rules have a `message` field
- [ ] Behavioral rules handle the 60-second state expiry
- [ ] eBPF changes include a fallback probe for older kernels
- [ ] README updated if new commands, config, or features added
- [ ] No hardcoded credentials or sensitive data

## Related issues

<!-- Closes #123 -->
