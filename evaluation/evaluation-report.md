# Experimental Evaluation

Target: `examples/vulnerable-rest-api`

## Summary

| Metric | Value |
|---|---:|
| Ground truth vulnerable endpoints | 19 |
| Endpoints detected by collector | 24 |
| Ground truth endpoints matched | 17 |
| Endpoint coverage | 89.5% |
| Ground truth vulnerability categories | 11 |
| Categories matched by route/pattern collector | 7 |
| Category coverage | 63.6% |
| Dangerous patterns detected | 12 |
| Manual test cases generated | 0 |
| AI triage status | Chưa có security-report.json để tính AI triage |

## Ground Truth Endpoint Coverage

| Endpoint | Category | Detected |
|---|---|---|
| `POST /api/users` | business_logic | Yes |
| `GET /api/authors` | info_leak | Yes |
| `GET /api/books` | info_leak | Yes |
| `GET /api/users/:param` | redos | Yes |
| `PUT /api/users/:param` | xss | Yes |
| `POST /api/auth` | idor_candidate | Yes |
| `POST /api/otp` | idor_candidate | No |
| `POST /api/books` | authz | Yes |
| `PUT /api/books/:param` | authz | Yes |
| `DELETE /api/books/:param` | authz | Yes |
| `POST /api/authors` | authz | Yes |
| `PUT /api/authors/:param` | authz | Yes |
| `DELETE /api/authors/:param` | authz | Yes |
| `GET /api/system/key` | auth | Yes |
| `POST /api/adminAuth` | auth | Yes |
| `POST /api/users/verify` | auth | Yes |
| `GET /api/logs` | info_leak | Yes |
| `GET /profile/:param` | business_logic | No |
| `GET /api/me` | cache | Yes |

## Vulnerability Category Coverage

| Category | Detected |
|---|---|
| mass_assign | Yes |
| info_leak | Yes |
| idor_candidate | Yes |
| authz | No |
| ssrf | Yes |
| xss | No |
| auth | Yes |
| redos | Yes |
| business_logic | No |
| nosqli | Yes |
| cache | No |

## False Positive / AI Triage

| Metric | Value |
|---|---:|
| Raw findings before AI | N/A |
| Findings marked false positive by AI | N/A |
| Actionable findings after AI | N/A |
| Estimated false positive rate after AI | N/A |

> Before-AI false positive rate requires manual labeling of raw scanner findings. This script reports after-AI false positive classification from `security-report.json` when available.

## Missed Ground Truth Endpoints

- `POST /api/otp` (idor_candidate)
- `GET /profile/:param` (business_logic)

## Missed Categories

- authz
- xss
- business_logic
- cache
