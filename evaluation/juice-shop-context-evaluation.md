# Juice Shop Context Evaluation

Báo cáo này đối chiếu theo **ngữ cảnh lỗ hổng/challenge** trong OWASP Juice Shop `challenges.yml`, không coi mọi kết quả ngoài YAML là false positive. YAML là ground truth cấp challenge, còn report của hệ thống gồm scanner findings và manual test candidates.

## Tóm tắt

| Metric | Value |
|---|---:|
| Juice Shop challenges trong YAML | 112 |
| Scanner findings trong JSON | 89 |
| Manual test cards trong HTML | 154 |
| Manual tests unique sau de-dup | 87 |
| Challenges có khớp exact từ scanner/manual | 27 / 112 |
| Challenges có ngữ cảnh runtime/manual exact+partial+supporting | 62 / 112 |
| Challenges có bất kỳ bằng chứng, gồm cả codefix | 62 / 112 |

## Cách hiểu nhãn

| Nhãn | Ý nghĩa |
|---|---|
| Khớp ngữ cảnh YAML | Endpoint/file/loại lỗi khớp rõ với mô tả YAML hoặc source solve challenge. |
| Khớp một phần | Đúng surface hoặc đúng challenge family, nhưng nhãn lỗi rộng/sai một phần. |
| Bằng chứng hỗ trợ challenge | Bằng chứng hỗ trợ việc khai thác challenge nhưng chưa phải exploit/challenge solution đầy đủ. |
| Khớp codefix/coding challenge | Khớp file codefix/coding challenge đi kèm Juice Shop, không phải runtime route chính. |
| Ngoài YAML/candidate mới | Candidate hoặc hardening issue không được YAML liệt kê. Không tính là FP nếu chưa chạy tay. |
| Không được YAML/source ủng hộ | Source/YAML không ủng hộ giả thuyết, ví dụ route bị denyAll hoặc challenge không tồn tại. |

## Manual Test Context Match

| Metric | Count | Rate |
|---|---:|---:|
| Unique manual tests | 87 | 100.0% |
| Khớp YAML exact | 6 | 6.9% |
| Khớp YAML một phần | 30 | 34.5% |
| Bằng chứng hỗ trợ YAML | 0 | 0.0% |
| Ngoài YAML/candidate mới | 9 | 10.3% |
| Không được YAML/source ủng hộ | 42 | 48.3% |
| Tổng có giá trị đối chiếu YAML exact+partial+supporting | 36 | 41.4% |

## Manual By Type

| Type | Tests | Exact | Partial | Supporting | Ngoài YAML | Unsupported |
|---|---:|---:|---:|---:|---:|---:|
| Auth_Bypass | 11 | 0 | 4 | 0 | 1 | 6 |
| BFLA | 27 | 2 | 9 | 0 | 5 | 11 |
| IDOR | 18 | 3 | 2 | 0 | 1 | 12 |
| Mass_Assignment | 17 | 1 | 7 | 0 | 0 | 9 |
| Race_Condition | 14 | 0 | 8 | 0 | 2 | 4 |

## Scanner Context Match

| Metric | Value |
|---|---:|
| Findings | 89 |
| Khớp YAML exact | 14 |
| Khớp YAML một phần | 5 |
| Bằng chứng hỗ trợ YAML | 46 |
| Codefix/coding challenge only | 4 |
| Ngoài YAML/hardening | 15 |
| Unsupported | 5 |
| Match rate gồm codefix | 77.5% |
| Runtime/supporting match không tính codefix | 73.0% |

## Scanner By Source

| Source | Findings | Exact | Partial | Supporting | Codefix | Ngoài YAML | Unsupported |
|---|---:|---:|---:|---:|---:|---:|---:|
| semgrep | 23 | 11 | 0 | 8 | 4 | 0 | 0 |
| zap | 66 | 3 | 5 | 38 | 0 | 15 | 5 |

## Manual Exact Matches

- `BFLA - PUT /api/Products/:id` -> Khớp ngữ cảnh YAML; YAML: Product Tampering. server.ts:367-370 để trống middleware authorize cho PUT /api/Products/:id; verify.ts kiểm tra sản phẩm O-Saft bị đổi URL.
- `IDOR - PUT /api/BasketItems/:id` -> Khớp ngữ cảnh YAML; YAML: Manipulate Basket, Payback Time; duplicates: 2. routes/basketItems.ts solve Manipulate Basket khi body.BasketId khác user.bid; Cypress basket.spec cũng dùng PUT quantity âm để giải Payback Time.
- `Mass_Assignment - POST /api/Users` -> Khớp ngữ cảnh YAML; YAML: Admin Registration. YAML Admin Registration nói "assign the unassignable"; finale tạo User từ body và verify.registerAdminChallenge() kiểm tra role=admin.
- `BFLA - PATCH /rest/products/reviews` -> Khớp ngữ cảnh YAML; YAML: Forged Review, NoSQL Manipulation. routes/updateProductReviews.ts cập nhật review theo req.body.id và solve Forged Review nếu sửa review của người khác; multi:true còn liên quan NoSQL Manipulation.
- `IDOR - POST /api/BasketItems` -> Khớp ngữ cảnh YAML; YAML: Manipulate Basket. routes/basketItems.ts parse raw body và solve Manipulate Basket khi BasketId cuối khác basket người dùng.
- `IDOR - GET /rest/basket/:id` -> Khớp ngữ cảnh YAML; YAML: View Basket. routes/basket.ts solve View Basket khi user.bid khác req.params.id.

## Manual Partial Matches

- `BFLA - POST /rest/basket/:id/checkout` -> Khớp một phần; YAML: Payback Time, Forged Coupon, Expired Coupon. routes/order.ts giải Payback Time khi totalPrice < 0 và xử lý forged/expired coupon; nhãn BFLA/race chỉ đúng ở mức surface thanh toán nhạy cảm.
- `Race_Condition - POST /rest/basket/:id/checkout` -> Khớp một phần; YAML: Payback Time, Forged Coupon, Expired Coupon. routes/order.ts giải Payback Time khi totalPrice < 0 và xử lý forged/expired coupon; nhãn BFLA/race chỉ đúng ở mức surface thanh toán nhạy cảm.
- `IDOR - PUT /rest/basket/:id/coupon/:coupon` -> Khớp một phần; YAML: Forged Coupon, Expired Coupon. routes/coupon.ts áp coupon theo basket id; challenge YAML liên quan coupon forged/expired, không phải View Basket IDOR.
- `BFLA - PUT /rest/order-history/:id/delivery-status` -> Khớp một phần; YAML: Ephemeral Accountant. Endpoint chỉ cho accounting; nếu chiếm/bypass role accounting thì có tác động. YAML không mô tả delivery-status là challenge độc lập.
- `Mass_Assignment - PUT /api/Products/:id` -> Khớp một phần; YAML: Product Tampering; duplicates: 2. Endpoint đúng với Product Tampering, nhưng YAML/source mô tả broken access control trên PUT product, không phải mass assignment thuần túy.
- `Race_Condition - PUT /rest/products/:id/reviews` -> Khớp một phần; YAML: Forged Review. Đúng endpoint review nhạy cảm, nhưng challenge trên endpoint này là forged author, không phải race.
- `Mass_Assignment - PUT /api/BasketItems/:id` -> Khớp một phần; YAML: Manipulate Basket, Payback Time; duplicates: 3. Endpoint thật sự liên quan basket manipulation/negative order, nhưng nhãn mass assignment/race rộng hơn mô tả YAML.
- `Race_Condition - PUT /api/BasketItems/:id` -> Khớp một phần; YAML: Manipulate Basket, Payback Time. Endpoint thật sự liên quan basket manipulation/negative order, nhưng nhãn mass assignment/race rộng hơn mô tả YAML.
- `Auth_Bypass - POST /file-upload` -> Khớp một phần; YAML: Upload Size, Upload Type, XXE Data Access, XXE DoS, Memory Bomb, Arbitrary File Write, Deprecated Interface. YAML có nhiều challenge trên /file-upload, nhưng root cause là input validation/vulnerable component/XXE, không phải auth bypass.
- `Mass_Assignment - POST /rest/memories` -> Khớp một phần; YAML: Meta Geo Stalking, Visual Geo Stalking, GDPR Data Theft. Photo Wall/memories liên quan các challenge geo-stalking và dữ liệu export, nhưng YAML không mô tả mass assignment/race trên POST /rest/memories.
- `Race_Condition - POST /rest/memories` -> Khớp một phần; YAML: Meta Geo Stalking, Visual Geo Stalking, GDPR Data Theft. Photo Wall/memories liên quan các challenge geo-stalking và dữ liệu export, nhưng YAML không mô tả mass assignment/race trên POST /rest/memories.
- `Auth_Bypass - POST /api/Feedbacks` -> Khớp một phần; YAML: Forged Feedback, CAPTCHA Bypass, Zero Stars. POST /api/Feedbacks là surface thật cho Forged Feedback/CAPTCHA Bypass/Zero Stars; nhãn auth bypass/BFLA chưa mô tả chính xác root cause.
- `BFLA - POST /api/BasketItems` -> Khớp một phần; YAML: Manipulate Basket; duplicates: 3. Đúng endpoint giỏ hàng nhạy cảm, nhưng YAML/source mô tả IDOR/body tampering qua BasketId, không phải BFLA/race.
- `BFLA - PUT /rest/continue-code/apply/:continueCode` -> Khớp một phần; YAML: Imaginary Challenge. Continue-code endpoint liên quan Imaginary Challenge/restore progress; YAML là crypto/progress-code logic, không phải BFLA.
- `BFLA - POST /rest/user/data-export` -> Khớp một phần; YAML: GDPR Data Theft. Endpoint khớp GDPR Data Theft, nhưng manual test đang nói thiếu authentication. Source thực tế dùng security.appendUserId() và bug nằm ở data export/object logic, nên chỉ tính partial nếu chưa có bước chứng minh export dữ liệu người khác.
- `Race_Condition - PUT /rest/wallet/balance` -> Khớp một phần; YAML: Wallet Depletion, Payback Time. Wallet là asset tiền trong source, nhưng YAML Wallet Depletion là Web3 withdraw logic; PUT /rest/wallet/balance không phải route được mô tả trong YAML.
- `Mass_Assignment - POST /rest/deluxe-membership` -> Khớp một phần; YAML: Deluxe Fraud. Endpoint khớp Deluxe Fraud, nhưng YAML/source mô tả business/input logic qua paymentMode không hợp lệ, không phải mass assignment/BFLA thuần túy.
- `BFLA - POST /rest/products/reviews` -> Khớp một phần; YAML: Multiple Likes. Endpoint đúng, nhưng YAML/source mô tả race/timing attack chứ không phải function-level authorization.
- `BFLA - POST /rest/chat` -> Khớp một phần; YAML: Chatbot Prompt Injection, Greedy Chatbot Manipulation, AI Debugging. Chat route là surface thật cho prompt injection/AI debugging; nhãn BFLA/Auth_Bypass chỉ đúng một phần.
- `Mass_Assignment - POST /rest/web3/submitKey` -> Khớp một phần; YAML: NFT Takeover. Web3 submitKey liên quan NFT Takeover/key submission, nhưng không phải mass assignment trong YAML.
- `Race_Condition - POST /rest/web3/walletNFTVerify` -> Khớp một phần; YAML: NFT Takeover. Web3 NFT verify thuộc ngữ cảnh NFT challenge, nhưng YAML không mô tả race/auth bypass ở endpoint này.
- `Auth_Bypass - POST /rest/web3/walletExploitAddress` -> Khớp một phần; YAML: Wallet Depletion. Endpoint Web3 exploit address liên quan Wallet Depletion, nhưng YAML mô tả withdraw more ETH chứ không phải auth bypass.
- `Race_Condition - POST /b2b/v2/orders` -> Khớp một phần; YAML: Deprecated Interface. B2B v2 là deprecated interface surface; YAML không mô tả race condition cho endpoint này.
- `Mass_Assignment - POST /profile` -> Khớp một phần; YAML: CSP Bypass, CSRF. Profile update liên quan CSP bypass/user profile và CSRF challenge, nhưng nhãn mass assignment chưa khớp mô tả YAML.
- `Race_Condition - POST /api/BasketItems` -> Khớp một phần; YAML: Manipulate Basket; duplicates: 3. Đúng endpoint giỏ hàng nhạy cảm, nhưng YAML/source mô tả IDOR/body tampering qua BasketId, không phải BFLA/race.
- `BFLA - GET /rest/admin/application-version` -> Khớp một phần; YAML: Admin Section. Endpoint mang ngữ cảnh admin, nhưng YAML Admin Section là truy cập UI /#/administration; route này không tự chứng minh bypass admin section.
- `Mass_Assignment - POST /rest/user/login` -> Khớp một phần; YAML: Login Admin, Login Bender, Login Jim, Ephemeral Accountant. routes/login.ts có SQL injection trong login. Nhãn trong manual test không đúng loại, nhưng endpoint là authentication challenge surface.
- `IDOR - GET /rest/track-order/:id` -> Khớp một phần; YAML: NoSQL Exfiltration, Reflected XSS. routes/trackOrder.ts query Mongo bằng orderId và có NoSQL/XSS challenge; không phải IDOR trong YAML.
- `BFLA - GET /rest/order-history/orders` -> Khớp một phần; YAML: Ephemeral Accountant. server.ts bảo vệ bằng security.isAccounting(); liên quan role accounting. YAML có Ephemeral Accountant là login thành role accounting qua SQLi, không phải bypass trực tiếp endpoint này.
- `Auth_Bypass - GET /rest/user/change-password` -> Khớp một phần; YAML: Change Bender's Password. Endpoint khớp Change Bender Password, nhưng manual test mô tả đổi mật khẩu không cần session. Source vẫn yêu cầu token; bug là thiếu currentPassword, nên nhãn Auth_Bypass chỉ đúng một phần.

## Manual Candidate Ngoài YAML

- `BFLA - POST /profile/image/file` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Endpoint upload ảnh profile tồn tại, nhưng YAML không mô tả challenge BFLA/auth bypass cho route file upload ảnh này.
- `Auth_Bypass - POST /snippets/verdict` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Đây là endpoint kiểm tra coding challenge/snippet, không phải lỗ hổng YAML độc lập.
- `BFLA - POST /snippets/fixes` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Endpoint phục vụ coding challenge/fix, không có challenge YAML tương ứng dạng BFLA.
- `BFLA - POST /` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Không tìm thấy challenge YAML mô tả endpoint/kiểu lỗi này. Không nên tính là FP nếu chưa chạy tay; nên ghi là candidate ngoài ground truth cần kiểm chứng.
- `Race_Condition - POST /rest/2fa/verify` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Không tìm thấy challenge YAML mô tả endpoint/kiểu lỗi này. Không nên tính là FP nếu chưa chạy tay; nên ghi là candidate ngoài ground truth cần kiểm chứng.
- `BFLA - POST /rest/2fa/disable` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Không tìm thấy challenge YAML mô tả endpoint/kiểu lỗi này. Không nên tính là FP nếu chưa chạy tay; nên ghi là candidate ngoài ground truth cần kiểm chứng.
- `Race_Condition - POST /rest/2fa/setup` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Không tìm thấy challenge YAML mô tả endpoint/kiểu lỗi này. Không nên tính là FP nếu chưa chạy tay; nên ghi là candidate ngoài ground truth cần kiểm chứng.
- `BFLA - GET /rest/2fa/status` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Không tìm thấy challenge YAML mô tả endpoint/kiểu lỗi này. Không nên tính là FP nếu chưa chạy tay; nên ghi là candidate ngoài ground truth cần kiểm chứng.
- `IDOR - GET /rest/order-history` -> Ngoài YAML/candidate mới; YAML: Không có challenge YAML trực tiếp. Không tìm thấy challenge YAML mô tả endpoint/kiểu lỗi này. Không nên tính là FP nếu chưa chạy tay; nên ghi là candidate ngoài ground truth cần kiểm chứng.

## Manual Unsupported / Source Không Ủng Hộ

- `BFLA - DELETE /api/Products/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 4. server.ts:370 dùng security.denyAll() cho DELETE /api/Products/:id; YAML Product Tampering nói đổi link sản phẩm, không nói xóa sản phẩm.
- `IDOR - PUT /api/Recycles/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.
- `BFLA - DELETE /api/Recycles/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.
- `BFLA - DELETE /api/Quantitys/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 3. server.ts dùng denyAll()/isAccounting() cho quantity APIs; không có challenge YAML cho race/BFLA quantity.
- `Mass_Assignment - PUT /api/Cards/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 3. server.ts dùng security.appendUserId() hoặc denyAll() và payment.ts lọc theo UserId.
- `BFLA - PUT /api/Feedbacks/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 4. server.ts:433 đặt security.denyAll(); API test xác nhận PUT feedback trả 401. Five-Star Feedback là xóa mọi feedback 5 sao qua admin flow, không phải PUT.
- `IDOR - DELETE /api/Cards/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng security.appendUserId() hoặc denyAll() và payment.ts lọc theo UserId.
- `Mass_Assignment - PUT /api/Addresss/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng security.appendUserId() và address.ts lọc theo UserId.
- `Mass_Assignment - PUT /api/Recycles/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.
- `IDOR - DELETE /api/Quantitys/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng denyAll()/isAccounting() cho quantity APIs; không có challenge YAML cho race/BFLA quantity.
- `Race_Condition - DELETE /api/Cards/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 3. server.ts dùng security.appendUserId() hoặc denyAll() và payment.ts lọc theo UserId.
- `IDOR - PUT /api/Addresss/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 3. server.ts dùng security.appendUserId() và address.ts lọc theo UserId.
- `BFLA - DELETE /api/Addresss/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts dùng security.appendUserId() và address.ts lọc theo UserId.
- `IDOR - DELETE /api/Addresss/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng security.appendUserId() và address.ts lọc theo UserId.
- `Mass_Assignment - PUT /api/Feedbacks/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts:433 đặt security.denyAll(); API test xác nhận PUT feedback trả 401. Five-Star Feedback là xóa mọi feedback 5 sao qua admin flow, không phải PUT.
- `IDOR - DELETE /api/Recycles/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.
- `Auth_Bypass - POST /api/Products` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts dùng security.isAuthorized() cho POST /api/Products; YAML Product Tampering nằm ở PUT /api/Products/:id.
- `Mass_Assignment - POST /api/Complaints` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng isAuthorized(); complaints có thể liên quan feedback/reporting workflow nhưng không có YAML BFLA/mass assignment riêng.
- `Auth_Bypass - POST /api/Challenges` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng denyAll() cho POST /api/Challenges.
- `Auth_Bypass - POST /api/Recycles` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.
- `Auth_Bypass - POST /api/SecurityQuestions` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts dùng denyAll() cho POST /api/SecurityQuestions.
- `BFLA - POST /api/Quantitys` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng denyAll()/isAccounting() cho quantity APIs; không có challenge YAML cho race/BFLA quantity.
- `Mass_Assignment - POST /api/Cards` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 4. server.ts dùng security.appendUserId() hoặc denyAll() và payment.ts lọc theo UserId.
- `BFLA - POST /api/PrivacyRequests` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 5. server.ts dùng isAuthorized()/denyAll(); không có YAML BFLA riêng.
- `Auth_Bypass - POST /api/Addresss` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 3. server.ts dùng security.appendUserId() và address.ts lọc theo UserId.
- `Mass_Assignment - POST /api/Addresss` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng security.appendUserId() và address.ts lọc theo UserId.
- `Mass_Assignment - POST /api/Products` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 3. server.ts dùng security.isAuthorized() cho POST /api/Products; YAML Product Tampering nằm ở PUT /api/Products/:id.
- `BFLA - POST /api/Hints` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng denyAll() cho POST /api/Hints.
- `BFLA - POST /api/Complaints` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 3. server.ts dùng isAuthorized(); complaints có thể liên quan feedback/reporting workflow nhưng không có YAML BFLA/mass assignment riêng.
- `Mass_Assignment - POST /api/Recycles` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.
- `BFLA - POST /api/SecurityQuestions` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 4. server.ts dùng denyAll() cho POST /api/SecurityQuestions.
- `BFLA - POST /api/Challenges` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts dùng denyAll() cho POST /api/Challenges.
- `Race_Condition - POST /api/Hints` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts dùng denyAll() cho POST /api/Hints.
- `IDOR - POST /api/Cards` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts dùng security.appendUserId() hoặc denyAll() và payment.ts lọc theo UserId.
- `Race_Condition - POST /api/Recycles` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 2. server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.
- `Race_Condition - POST /api/Quantitys` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts dùng denyAll()/isAccounting() cho quantity APIs; không có challenge YAML cho race/BFLA quantity.
- `IDOR - POST /api/Addresss` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. server.ts dùng security.appendUserId() và address.ts lọc theo UserId.
- `IDOR - GET /api/Recycles/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 5. server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.
- `IDOR - GET /api/Cards/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 5. server.ts dùng security.appendUserId() hoặc denyAll() và payment.ts lọc theo UserId.
- `IDOR - GET /api/Addresss/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 5. server.ts dùng security.appendUserId() và address.ts lọc theo UserId.
- `Auth_Bypass - GET /api/Deliverys/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp; duplicates: 4. Delivery methods là public catalog endpoint; không có challenge YAML IDOR/auth bypass tương ứng.
- `IDOR - GET /api/Deliverys/:id` -> Không được YAML/source ủng hộ; YAML: Không có challenge YAML trực tiếp. Delivery methods là public catalog endpoint; không có challenge YAML IDOR/auth bypass tương ứng.

## Scanner Exact Matches

- `F-005` [semgrep/critical/confirmed_vulnerability] `/src/routes/login.ts:34` -> Khớp ngữ cảnh YAML; YAML: Login Admin, Login Bender, Login Jim, Ephemeral Accountant. routes/login.ts nối trực tiếp email/password vào Sequelize raw query; YAML có nhiều login SQLi challenges.
- `F-006` [semgrep/critical/confirmed_vulnerability] `/src/routes/search.ts:23` -> Khớp ngữ cảnh YAML; YAML: User Credentials, Database Schema. routes/search.ts nối req.query.q vào SELECT; YAML User Credentials/Database Schema yêu cầu SQLi qua search.
- `F-007` [semgrep/critical/confirmed_vulnerability] `/src/routes/userProfile.ts:61` -> Khớp ngữ cảnh YAML; YAML: CSP Bypass, SSTi. routes/userProfile.ts eval username template expression và set CSP động; YAML có CSP Bypass và SSTi/RCE context.
- `F-011` [semgrep/high/confirmed_vulnerability] `/src/routes/fileServer.ts:33` -> Khớp ngữ cảnh YAML; YAML: Confidential Document, Forgotten Sales Backup, Forgotten Developer Backup, Misplaced Signature File, Easter Egg, Poison Null Byte. routes/fileServer.ts serve /ftp files và cắt poison null byte; YAML có confidential document/backup/null-byte challenges.
- `F-013` [semgrep/high/confirmed_vulnerability] `/src/routes/logfileServer.ts:14` -> Khớp ngữ cảnh YAML; YAML: Access Log, Leaked Access Logs. server.ts expose /support/logs và logfileServer.ts sendFile logs; YAML Access Log và leaked logs/password spraying liên quan trực tiếp.
- `F-015` [semgrep/high/likely_vulnerability] `/src/routes/redirect.ts:19` -> Khớp ngữ cảnh YAML; YAML: Allowlist Bypass, Outdated Allowlist. routes/redirect.ts redirect theo query.to và allowlist includes; YAML Allowlist Bypass/Outdated Allowlist.
- `F-016` [semgrep/high/likely_vulnerability] `/src/routes/redirect.ts:19` -> Khớp ngữ cảnh YAML; YAML: Allowlist Bypass, Outdated Allowlist. routes/redirect.ts redirect theo query.to và allowlist includes; YAML Allowlist Bypass/Outdated Allowlist.
- `F-017` [semgrep/high/needs_manual_review] `/src/routes/videoHandler.ts:57` -> Khớp ngữ cảnh YAML; YAML: Video XSS. routes/videoHandler.ts nhúng subtitles vào script tag; YAML Video XSS yêu cầu payload trong promo video subtitles.
- `F-018` [semgrep/high/needs_manual_review] `/src/routes/videoHandler.ts:71` -> Khớp ngữ cảnh YAML; YAML: Video XSS. routes/videoHandler.ts nhúng subtitles vào script tag; YAML Video XSS yêu cầu payload trong promo video subtitles.
- `F-019` [semgrep/high/confirmed_vulnerability] `/src/server.ts:269` -> Khớp ngữ cảnh YAML; YAML: Confidential Document, Forgotten Sales Backup, Forgotten Developer Backup, Misplaced Signature File. server.ts expose /ftp directory listing/file serving; khớp Confidential Document và các backup/signature-file challenges.
- `F-022` [semgrep/high/confirmed_vulnerability] `/src/server.ts:281` -> Khớp ngữ cảnh YAML; YAML: Access Log, Leaked Access Logs. server.ts expose /support/logs directory listing; khớp Access Log và leaked logs context.
- `F-055` [zap/medium/likely_vulnerability] `GET http://web:3000/%2e/ftp/coupons_2013.md.bak` -> Khớp ngữ cảnh YAML; YAML: Forgotten Sales Backup, Forged Coupon, Poison Null Byte. ZAP phát hiện bypass 403 với coupons_2013.md.bak; YAML Forgotten Sales Backup/Forged Coupon dùng file coupon backup.
- `F-056` [zap/medium/likely_vulnerability] `GET http://web:3000/%2e/ftp/eastere.gg` -> Khớp ngữ cảnh YAML; YAML: Easter Egg, Poison Null Byte. eastere.gg là hidden easter egg file trong YAML/source.
- `F-058` [zap/medium/likely_vulnerability] `GET http://web:3000/%2e/ftp/suspicious_errors.yml` -> Khớp ngữ cảnh YAML; YAML: Misplaced Signature File, Poison Null Byte. suspicious_errors.yml là misplaced SIEM signature file trong YAML/source.

## Scanner Partial/Supporting Matches

- `F-008` [semgrep/high/likely_vulnerability] `/src/frontend/src/app/navbar/navbar.component.html:17` -> Bằng chứng hỗ trợ challenge; YAML: DOM XSS, CSP Bypass, Client-side XSS Protection. Finding là template XSS sink ở frontend; YAML có nhiều XSS challenges, nhưng location này không phải challenge solution surface được mô tả trực tiếp.
- `F-009` [semgrep/high/likely_vulnerability] `/src/frontend/src/app/purchase-basket/purchase-basket.component.html:15` -> Bằng chứng hỗ trợ challenge; YAML: DOM XSS, CSP Bypass, Client-side XSS Protection. Template sink có liên quan lớp XSS, nhưng YAML không nêu purchase-basket component là challenge surface cụ thể.
- `F-010` [semgrep/high/confirmed_vulnerability] `/src/lib/insecurity.ts:56` -> Bằng chứng hỗ trợ challenge; YAML: Unsigned JWT, Forged Signed JWT. Finding là hard-coded RSA private key/JWT credential trong lib/insecurity.ts; đây là bằng chứng hỗ trợ JWT forged/unsigned challenge, nhưng scanner không tự chứng minh token exploit.
- `F-012` [semgrep/high/confirmed_vulnerability] `/src/routes/keyServer.ts:14` -> Bằng chứng hỗ trợ challenge; YAML: Forged Signed JWT, Unsigned JWT. server.ts expose /encryptionkeys và keyServer.ts sendFile key; đây là bằng chứng hỗ trợ JWT/key disclosure challenges, dù YAML không đặt tên riêng endpoint này.
- `F-014` [semgrep/high/confirmed_vulnerability] `/src/routes/quarantineServer.ts:14` -> Bằng chứng hỗ trợ challenge; YAML: SSTi. Quarantine files chứa URL juicy malware; YAML SSTi gợi ý tìm malware qua quarantine folder, nhưng bản thân endpoint chỉ là supporting evidence.
- `F-020` [semgrep/high/confirmed_vulnerability] `/src/server.ts:273` -> Bằng chứng hỗ trợ challenge; YAML: Forged Signed JWT, Unsigned JWT, Vulnerable Library. server.ts expose .well-known/encryptionkeys directory listing; đây là key/advisory disclosure context hỗ trợ JWT/component challenges, không phải challenge solution độc lập.
- `F-021` [semgrep/high/confirmed_vulnerability] `/src/server.ts:277` -> Bằng chứng hỗ trợ challenge; YAML: Forged Signed JWT, Unsigned JWT, Vulnerable Library. server.ts expose .well-known/encryptionkeys directory listing; đây là key/advisory disclosure context hỗ trợ JWT/component challenges, không phải challenge solution độc lập.
- `F-023` [semgrep/high/likely_vulnerability] `/src/views/dataErasureForm.hbs:38` -> Bằng chứng hỗ trợ challenge; YAML: CSRF, GDPR Data Erasure. Data erasure form thuộc workflow GDPR erasure; YAML có CSRF/GDPR erasure context, nhưng finding unquoted attribute chưa tự khẳng định challenge solution.
- `F-024` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-025` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(2)` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-026` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-027` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-028` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-029` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-030` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(3)` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-031` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-032` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-033` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-034` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-035` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-036` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-037` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-038` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-039` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.bac` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-040` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.backup` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-041` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.bak` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-042` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.jar` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-043` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.log` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-044` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.old` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-045` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.swp` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-046` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.tar` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-047` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.zip` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-048` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine.~bk` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-049` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantinebackup` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-050` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-051` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-052` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantinebackup/juicy_malware_macos_64.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-053` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-054` [zap/medium/likely_vulnerability] `GET http://web:3000/ftp/quarantine~` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Sales Backup, Forgotten Developer Backup, Confidential Document, SSTi. ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.
- `F-057` [zap/medium/likely_vulnerability] `GET http://web:3000/%2e/ftp/package-lock.json.bak` -> Bằng chứng hỗ trợ challenge; YAML: Forgotten Developer Backup, Vulnerable Library, Legacy Typosquatting. Backup package lock hỗ trợ dependency/vulnerable component challenges, nhưng YAML Forgotten Developer Backup exact hơn với package.json.bak.
- `F-059` [zap/medium/needs_manual_review] `GET http://web:3000/` -> Bằng chứng hỗ trợ challenge; YAML: CSP Bypass, DOM XSS, Client-side XSS Protection, Video XSS. Missing CSP làm tăng rủi ro XSS, nhưng Juice Shop còn có CSP-specific challenge; đây là signal hỗ trợ chứ không phải exploit evidence.
- `F-060` [zap/medium/needs_manual_review] `GET http://web:3000/file-upload` -> Bằng chứng hỗ trợ challenge; YAML: CSP Bypass, DOM XSS, Client-side XSS Protection, Video XSS. Missing CSP làm tăng rủi ro XSS, nhưng Juice Shop còn có CSP-specific challenge; đây là signal hỗ trợ chứ không phải exploit evidence.
- `F-061` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/coupons_2013.md.bak` -> Bằng chứng hỗ trợ challenge; YAML: CSP Bypass, DOM XSS, Client-side XSS Protection, Video XSS. Missing CSP làm tăng rủi ro XSS, nhưng Juice Shop còn có CSP-specific challenge; đây là signal hỗ trợ chứ không phải exploit evidence.
- `F-062` [zap/medium/confirmed_vulnerability] `GET http://web:3000/ftp/eastere.gg` -> Bằng chứng hỗ trợ challenge; YAML: CSP Bypass, DOM XSS, Client-side XSS Protection, Video XSS. Missing CSP làm tăng rủi ro XSS, nhưng Juice Shop còn có CSP-specific challenge; đây là signal hỗ trợ chứ không phải exploit evidence.
- `F-063` [zap/medium/confirmed_vulnerability] `GET http://web:3000/sitemap.xml` -> Bằng chứng hỗ trợ challenge; YAML: CSP Bypass, DOM XSS, Client-side XSS Protection, Video XSS. Missing CSP làm tăng rủi ro XSS, nhưng Juice Shop còn có CSP-specific challenge; đây là signal hỗ trợ chứ không phải exploit evidence.
- `F-064` [zap/medium/confirmed_vulnerability] `GET http://web:3000/` -> Khớp một phần; YAML: Email Leak. YAML Email Leak nói unwanted information disclosure cross-domain; ZAP CORS/cross-domain misconfiguration có cùng ngữ cảnh nhưng chưa chứng minh endpoint leak cụ thể.
- `F-065` [zap/medium/confirmed_vulnerability] `GET http://web:3000/chunk-KD3CNUZG.js` -> Khớp một phần; YAML: Email Leak. YAML Email Leak nói unwanted information disclosure cross-domain; ZAP CORS/cross-domain misconfiguration có cùng ngữ cảnh nhưng chưa chứng minh endpoint leak cụ thể.
- `F-066` [zap/medium/confirmed_vulnerability] `GET http://web:3000/file-upload` -> Khớp một phần; YAML: Email Leak. YAML Email Leak nói unwanted information disclosure cross-domain; ZAP CORS/cross-domain misconfiguration có cùng ngữ cảnh nhưng chưa chứng minh endpoint leak cụ thể.
- `F-067` [zap/medium/confirmed_vulnerability] `GET http://web:3000/robots.txt` -> Khớp một phần; YAML: Email Leak. YAML Email Leak nói unwanted information disclosure cross-domain; ZAP CORS/cross-domain misconfiguration có cùng ngữ cảnh nhưng chưa chứng minh endpoint leak cụ thể.
- `F-068` [zap/medium/confirmed_vulnerability] `GET http://web:3000/sitemap.xml` -> Khớp một phần; YAML: Email Leak. YAML Email Leak nói unwanted information disclosure cross-domain; ZAP CORS/cross-domain misconfiguration có cùng ngữ cảnh nhưng chưa chứng minh endpoint leak cụ thể.
- `F-079` [zap/low/needs_manual_review] `GET http://web:3000/main.js` -> Bằng chứng hỗ trợ challenge; YAML: DOM XSS, CSP Bypass. main.js dangerous functions là XSS-relevant signal, nhưng không chỉ ra payload/challenge cụ thể.

## Challenge Coverage

| Challenge | Category | Exact | Partial | Supporting | Codefix |
|---|---|---:|---:|---:|---:|
| Poison Null Byte | Improper Input Validation | 4 | 0 | 0 | 0 |
| Forgotten Sales Backup | Sensitive Data Exposure | 3 | 0 | 31 | 0 |
| Misplaced Signature File | Observability Failures | 3 | 0 | 0 | 0 |
| Manipulate Basket | Broken Access Control | 2 | 4 | 0 | 0 |
| Access Log | Observability Failures | 2 | 0 | 0 | 0 |
| Allowlist Bypass | Unvalidated Redirects | 2 | 0 | 0 | 0 |
| Confidential Document | Sensitive Data Exposure | 2 | 0 | 31 | 0 |
| Easter Egg | Broken Access Control | 2 | 0 | 0 | 0 |
| Forgotten Developer Backup | Sensitive Data Exposure | 2 | 0 | 32 | 0 |
| Leaked Access Logs | Observability Failures | 2 | 0 | 0 | 0 |
| Outdated Allowlist | Unvalidated Redirects | 2 | 0 | 0 | 0 |
| Video XSS | XSS | 2 | 0 | 5 | 0 |
| Payback Time | Improper Input Validation | 1 | 5 | 0 | 0 |
| Ephemeral Accountant | Injection | 1 | 3 | 0 | 0 |
| Forged Coupon | Cryptographic Issues | 1 | 3 | 0 | 0 |
| CSP Bypass | XSS | 1 | 1 | 8 | 0 |
| Forged Review | Broken Access Control | 1 | 1 | 0 | 0 |
| Login Admin | Injection | 1 | 1 | 0 | 0 |
| Login Bender | Injection | 1 | 1 | 0 | 0 |
| Login Jim | Injection | 1 | 1 | 0 | 0 |
| Product Tampering | Broken Access Control | 1 | 1 | 0 | 0 |
| Admin Registration | Improper Input Validation | 1 | 0 | 0 | 0 |
| Database Schema | Injection | 1 | 0 | 0 | 2 |
| NoSQL Manipulation | Injection | 1 | 0 | 0 | 0 |
| SSTi | Injection | 1 | 0 | 32 | 0 |
| User Credentials | Injection | 1 | 0 | 0 | 2 |
| View Basket | Broken Access Control | 1 | 0 | 0 | 0 |
| Email Leak | Sensitive Data Exposure | 0 | 5 | 0 | 0 |
| Expired Coupon | Improper Input Validation | 0 | 3 | 0 | 0 |
| GDPR Data Theft | Sensitive Data Exposure | 0 | 3 | 0 | 0 |
| Deprecated Interface | Security Misconfiguration | 0 | 2 | 0 | 0 |
| Meta Geo Stalking | Sensitive Data Exposure | 0 | 2 | 0 | 0 |
| NFT Takeover | Sensitive Data Exposure | 0 | 2 | 0 | 0 |
| Visual Geo Stalking | Sensitive Data Exposure | 0 | 2 | 0 | 0 |
| Wallet Depletion | Miscellaneous | 0 | 2 | 0 | 0 |
| Admin Section | Broken Access Control | 0 | 1 | 0 | 0 |
| AI Debugging | Broken Access Control | 0 | 1 | 0 | 0 |
| Arbitrary File Write | Vulnerable Components | 0 | 1 | 0 | 0 |
| CAPTCHA Bypass | Broken Anti Automation | 0 | 1 | 0 | 0 |
| Change Bender's Password | Broken Authentication | 0 | 1 | 0 | 0 |
| Chatbot Prompt Injection | Injection | 0 | 1 | 0 | 0 |
| CSRF | Broken Access Control | 0 | 1 | 1 | 0 |
| Deluxe Fraud | Improper Input Validation | 0 | 1 | 0 | 0 |
| Forged Feedback | Broken Access Control | 0 | 1 | 0 | 0 |
| Greedy Chatbot Manipulation | Injection | 0 | 1 | 0 | 0 |
| Imaginary Challenge | Cryptographic Issues | 0 | 1 | 0 | 0 |
| Memory Bomb | Insecure Deserialization | 0 | 1 | 0 | 0 |
| Multiple Likes | Broken Anti Automation | 0 | 1 | 0 | 0 |
| NoSQL Exfiltration | Injection | 0 | 1 | 0 | 0 |
| Reflected XSS | XSS | 0 | 1 | 0 | 0 |
| Upload Size | Improper Input Validation | 0 | 1 | 0 | 0 |
| Upload Type | Improper Input Validation | 0 | 1 | 0 | 0 |
| XXE Data Access | XXE | 0 | 1 | 0 | 0 |
| XXE DoS | XXE | 0 | 1 | 0 | 0 |
| Zero Stars | Improper Input Validation | 0 | 1 | 0 | 0 |
| Client-side XSS Protection | XSS | 0 | 0 | 7 | 0 |
| DOM XSS | XSS | 0 | 0 | 8 | 0 |
| Forged Signed JWT | Vulnerable Components | 0 | 0 | 4 | 0 |
| GDPR Data Erasure | Broken Authentication | 0 | 0 | 1 | 0 |
| Legacy Typosquatting | Vulnerable Components | 0 | 0 | 1 | 0 |
| Unsigned JWT | Vulnerable Components | 0 | 0 | 4 | 0 |
| Vulnerable Library | Vulnerable Components | 0 | 0 | 3 | 0 |

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

## Kết luận kỹ thuật

- Với test thủ công, con số công tâm không phải "precision = exact / all" theo kiểu scanner, vì nhiều dòng là test candidate chưa chạy. Nên báo cáo: exact YAML match, partial YAML match, candidate ngoài YAML, và unsupported riêng.
- Các candidate ngoài YAML là phần cải tiến hợp lệ ở mức sinh checklist, nhưng muốn gọi là vulnerability confirmed cần bằng chứng chạy tay: request/response, tài khoản dùng, dữ liệu trước-sau, mã trạng thái, và tác động.
- Các scanner như ZAP/Semgrep phát hiện tốt lớp injection/file exposure/header hardening, nhưng không bao phủ tốt multi-step business logic, JWT forging, IDOR cần session, race condition và BFLA cần role/context.
- Những finding trỏ vào `data/static/codefixes/*` khớp ngữ cảnh bài học Juice Shop, nhưng không nên tính ngang với lỗ hổng runtime đang khai thác.
