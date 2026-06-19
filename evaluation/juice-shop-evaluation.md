# Juice Shop Ground Truth Evaluation

Ground truth: OWASP Juice Shop `challenges.yml` (112 challenges).

System output: `security-report.json` (89 scanner findings) plus manual checklist extracted from `security-report.html`.

## Summary

| Metric | Value |
|---|---:|
| Juice Shop ground-truth challenges | 112 |
| Raw scanner findings | 89 |
| Manual test cases in HTML | 154 |
| Unique manual tests after de-duplication | 87 |
| Exact ground-truth challenges matched | 13 / 112 |
| Useful/exact+partial challenge matches | 28 / 112 |

## Manual Test Accuracy

| Metric | Value |
|---|---:|
| Unique manual tests | 87 |
| Exact true positives | 8 |
| Partial / right surface, wrong or broad label | 11 |
| No challenge mapping | 68 |
| Strict precision | 9.2% |
| Useful precision | 21.8% |

Strict precision counts only exact vulnerability-type + endpoint matches. Useful precision also counts cases that point to a real Juice Shop challenge surface but with a broad or imperfect label.

## Manual Accuracy By Type

| Type | Tests | Exact TP | Partial | No challenge mapping | Strict Precision | Useful Precision |
|---|---:|---:|---:|---:|---:|---:|
| Auth_Bypass | 11 | 1 | 1 | 9 | 9.1% | 18.2% |
| BFLA | 27 | 3 | 4 | 20 | 11.1% | 25.9% |
| IDOR | 18 | 3 | 1 | 14 | 16.7% | 22.2% |
| Mass_Assignment | 17 | 1 | 2 | 14 | 5.9% | 17.6% |
| Race_Condition | 14 | 0 | 3 | 11 | 0.0% | 21.4% |

## Scanner Match Against Ground Truth

| Metric | Value |
|---|---:|
| Findings | 89 |
| Exact TP | 10 |
| Partial | 49 |
| No challenge mapping | 30 |
| Strict precision | 11.2% |
| Useful precision | 66.3% |

## Manual True Positives

- `BFLA - PUT /api/Products/:id` => Product Tampering: Product Tampering depends on the intentionally missing authorization for PUT /api/Products/:id.
- `IDOR - PUT /api/BasketItems/:id` => Manipulate Basket: Manipulate Basket is solved when PUT /api/BasketItems/:id changes another BasketId.
- `BFLA - PUT /api/Feedbacks/:id` => Five-Star Feedback: Five-Star Feedback can be solved by deleting/updating all 5-star feedback through exposed feedback APIs.
- `Mass_Assignment - POST /api/Users` => Admin Registration: Juice Shop solves Admin Registration when POST /api/Users contains role=admin.
- `BFLA - PATCH /rest/products/reviews` => Forged Review: Updating another user review is explicitly handled by the Forged Review challenge.
- `IDOR - POST /api/BasketItems` => Manipulate Basket: Manipulate Basket is solved by posting an item with another BasketId.
- `IDOR - GET /rest/basket/:id` => View Basket: View Basket is solved by reading another user basket via /rest/basket/:id.
- `Auth_Bypass - GET /rest/user/change-password` => Change Bender's Password: Change Bender Password is solved through /rest/user/change-password without the current password.

## Manual Partial Matches

- `BFLA - POST /rest/basket/:id/checkout` => Payback Time (partial): Checkout is a real challenge surface, but the intended weakness is business/input logic.
- `Race_Condition - POST /rest/basket/:id/checkout` => Payback Time (partial): Checkout is real business-logic ground truth, but Payback Time is negative-order input tampering rather than a race condition.
- `IDOR - PUT /rest/basket/:id/coupon/:coupon` => View Basket (partial): The route can target a basket by id, but the YAML challenge closest to it is View Basket; coupon abuse is mainly coupon/crypto logic.
- `Mass_Assignment - PUT /api/Products/:id` => Product Tampering (partial): The endpoint is a real product-tampering ground truth, but the root cause is broken access control rather than classic mass assignment.
- `Auth_Bypass - POST /api/Feedbacks` => Forged Feedback (partial): Forged Feedback is solved by supplying another UserId when posting feedback; the generated label is broader than the challenge.
- `BFLA - POST /rest/user/data-export` => GDPR Data Theft (partial): The endpoint is a real access-control challenge surface, but the specific issue is object-level data theft.
- `Race_Condition - PUT /rest/wallet/balance` => Wallet Depletion (partial): Wallet balance is business-critical, but the Juice Shop Wallet Depletion challenge is Web3 logic, not this REST race condition.
- `Mass_Assignment - POST /rest/deluxe-membership` => Deluxe Fraud (partial): Deluxe Fraud is a real business/input logic challenge; the generated mass-assignment label is only approximate.
- `BFLA - POST /rest/products/reviews` => Multiple Likes (partial): The endpoint is a real ground-truth challenge surface, but the intended vulnerability is race condition, not BFLA.
- `Race_Condition - POST /b2b/v2/orders` => Deprecated Interface (partial): The B2B endpoint is real ground truth for Deprecated Interface, not a confirmed race condition.
- `BFLA - GET /rest/admin/application-version` => Admin Section (partial): This is an admin-labelled route, but the YAML Admin Section challenge is primarily UI route access.

## Manual No Challenge Mapping

- `BFLA - DELETE /api/Products/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - PUT /api/Recycles/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - DELETE /api/Recycles/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - DELETE /api/Quantitys/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - PUT /api/Cards/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - DELETE /api/Cards/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - PUT /api/Addresss/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - PUT /rest/order-history/:id/delivery-status` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - PUT /rest/products/:id/reviews` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - PUT /api/Recycles/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - DELETE /api/Quantitys/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - DELETE /api/Cards/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - PUT /api/Addresss/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - DELETE /api/Addresss/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - PUT /api/BasketItems/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - DELETE /api/Addresss/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - PUT /api/BasketItems/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - PUT /api/Feedbacks/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - DELETE /api/Recycles/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - POST /file-upload` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /profile/image/file` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /rest/memories` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - POST /rest/memories` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - POST /api/Products` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /api/Complaints` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - POST /api/Challenges` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - POST /api/Recycles` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - POST /api/SecurityQuestions` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /api/BasketItems` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /api/Quantitys` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /api/Cards` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /api/PrivacyRequests` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - POST /api/Addresss` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - PUT /rest/continue-code/apply/:continueCode` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /api/Addresss` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /rest/chat` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /rest/web3/submitKey` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - POST /rest/web3/walletNFTVerify` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - POST /rest/web3/walletExploitAddress` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /profile` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - POST /snippets/verdict` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /snippets/fixes` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /api/Products` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /api/Hints` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /api/Complaints` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /api/Recycles` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /api/SecurityQuestions` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - POST /api/BasketItems` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /api/Challenges` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - POST /api/Hints` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - POST /api/Cards` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - POST /api/Recycles` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - POST /api/Quantitys` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - POST /api/Addresss` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - GET /api/Recycles/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - GET /api/Cards/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - GET /api/Addresss/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Auth_Bypass - GET /api/Deliverys/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - POST /rest/2fa/verify` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - POST /rest/2fa/disable` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Mass_Assignment - POST /rest/user/login` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `Race_Condition - POST /rest/2fa/setup` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - GET /rest/track-order/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - GET /api/Deliverys/:id` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - GET /rest/2fa/status` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `BFLA - GET /rest/order-history/orders` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.
- `IDOR - GET /rest/order-history` => N/A: No corresponding Juice Shop ground-truth challenge found for this generated manual test.

## Ground Truth Categories

| Category | Challenges |
|---|---:|
| Sensitive Data Exposure | 16 |
| Injection | 13 |
| Broken Access Control | 12 |
| Improper Input Validation | 12 |
| Broken Authentication | 9 |
| XSS | 9 |
| Vulnerable Components | 8 |
| Miscellaneous | 6 |
| Cryptographic Issues | 5 |
| Broken Anti Automation | 4 |
| Observability Failures | 4 |
| Security Misconfiguration | 4 |
| Insecure Deserialization | 3 |
| Security through Obscurity | 3 |
| Unvalidated Redirects | 2 |
| XXE | 2 |

## Notes

- The YAML is challenge-level ground truth, not a scanner result file. Several scanner findings and generated manual tests can map to one challenge, and many challenges require solving sequences rather than single endpoint detection.
- Repeated manual test cards in HTML were de-duplicated by `vulnerability_type + method + endpoint` before calculating accuracy.
- `PARTIAL` means the generated test points at a real Juice Shop challenge surface but its vulnerability type or exploit model is broader than the official challenge.
