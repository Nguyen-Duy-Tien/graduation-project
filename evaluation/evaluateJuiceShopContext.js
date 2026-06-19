import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import yaml from 'js-yaml';

const DEFAULT_CHALLENGES = '../output/final-report Juice Shop/challenges.yml';
const DEFAULT_REPORT = '../output/final-report Juice Shop/security-report.json';
const DEFAULT_HTML = '../output/final-report Juice Shop/security-report.html';
const DEFAULT_OUTPUT = 'evaluation/juice-shop-context-evaluation.md';
const DEFAULT_JSON_OUTPUT = 'evaluation/juice-shop-context-evaluation.json';

const OUTCOMES = {
  YAML_EXACT: 'yaml_exact',
  YAML_PARTIAL: 'yaml_partial',
  YAML_SUPPORTING: 'yaml_supporting',
  CODEFIX_ONLY: 'codefix_only',
  OUT_OF_YAML: 'out_of_yaml',
  UNSUPPORTED: 'unsupported',
};

const OUTCOME_LABELS = {
  [OUTCOMES.YAML_EXACT]: 'Khớp ngữ cảnh YAML',
  [OUTCOMES.YAML_PARTIAL]: 'Khớp một phần',
  [OUTCOMES.YAML_SUPPORTING]: 'Bằng chứng hỗ trợ challenge',
  [OUTCOMES.CODEFIX_ONLY]: 'Khớp codefix/coding challenge',
  [OUTCOMES.OUT_OF_YAML]: 'Ngoài YAML/candidate mới',
  [OUTCOMES.UNSUPPORTED]: 'Không được YAML/source ủng hộ',
};

const ROUTE_RULES = [
  {
    type: ['BFLA', 'Auth_Bypass'],
    method: 'PUT',
    path: '/api/Products/:id',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['changeProductChallenge'],
    evidence: 'server.ts:367-370 để trống middleware authorize cho PUT /api/Products/:id; verify.ts kiểm tra sản phẩm O-Saft bị đổi URL.',
  },
  {
    type: ['Mass_Assignment'],
    method: 'PUT',
    path: '/api/Products/:id',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['changeProductChallenge'],
    evidence: 'Endpoint đúng với Product Tampering, nhưng YAML/source mô tả broken access control trên PUT product, không phải mass assignment thuần túy.',
  },
  {
    type: ['BFLA', 'Auth_Bypass'],
    method: 'DELETE',
    path: '/api/Products/:id',
    outcome: OUTCOMES.UNSUPPORTED,
    challenges: [],
    evidence: 'server.ts:370 dùng security.denyAll() cho DELETE /api/Products/:id; YAML Product Tampering nói đổi link sản phẩm, không nói xóa sản phẩm.',
  },
  {
    type: ['Mass_Assignment'],
    method: 'POST',
    path: '/api/Users',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['registerAdminChallenge'],
    evidence: 'YAML Admin Registration nói "assign the unassignable"; finale tạo User từ body và verify.registerAdminChallenge() kiểm tra role=admin.',
  },
  {
    type: ['IDOR', 'BFLA'],
    method: 'GET',
    path: '/rest/basket/:id',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['basketAccessChallenge'],
    evidence: 'routes/basket.ts solve View Basket khi user.bid khác req.params.id.',
  },
  {
    type: ['IDOR'],
    method: 'POST',
    path: '/api/BasketItems',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['basketManipulateChallenge'],
    evidence: 'routes/basketItems.ts parse raw body và solve Manipulate Basket khi BasketId cuối khác basket người dùng.',
  },
  {
    type: ['BFLA', 'Race_Condition'],
    method: 'POST',
    path: '/api/BasketItems',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['basketManipulateChallenge'],
    evidence: 'Đúng endpoint giỏ hàng nhạy cảm, nhưng YAML/source mô tả IDOR/body tampering qua BasketId, không phải BFLA/race.',
  },
  {
    type: ['IDOR'],
    method: 'PUT',
    path: '/api/BasketItems/:id',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['basketManipulateChallenge', 'negativeOrderChallenge'],
    evidence: 'routes/basketItems.ts solve Manipulate Basket khi body.BasketId khác user.bid; Cypress basket.spec cũng dùng PUT quantity âm để giải Payback Time.',
  },
  {
    type: ['Mass_Assignment', 'Race_Condition'],
    method: 'PUT',
    path: '/api/BasketItems/:id',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['basketManipulateChallenge', 'negativeOrderChallenge'],
    evidence: 'Endpoint thật sự liên quan basket manipulation/negative order, nhưng nhãn mass assignment/race rộng hơn mô tả YAML.',
  },
  {
    type: ['BFLA', 'Auth_Bypass'],
    method: 'POST',
    path: '/api/Feedbacks',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['forgedFeedbackChallenge', 'captchaBypassChallenge', 'zeroStarsChallenge'],
    evidence: 'POST /api/Feedbacks là surface thật cho Forged Feedback/CAPTCHA Bypass/Zero Stars; nhãn auth bypass/BFLA chưa mô tả chính xác root cause.',
  },
  {
    type: ['Mass_Assignment', 'IDOR'],
    method: 'POST',
    path: '/api/Feedbacks',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['forgedFeedbackChallenge'],
    evidence: 'verify.forgedFeedbackChallenge() solve khi người dùng gửi UserId của người khác hoặc anonymous gửi UserId.',
  },
  {
    type: ['BFLA', 'Mass_Assignment'],
    method: 'PUT',
    path: '/api/Feedbacks/:id',
    outcome: OUTCOMES.UNSUPPORTED,
    challenges: [],
    evidence: 'server.ts:433 đặt security.denyAll(); API test xác nhận PUT feedback trả 401. Five-Star Feedback là xóa mọi feedback 5 sao qua admin flow, không phải PUT.',
  },
  {
    type: ['BFLA', 'Auth_Bypass'],
    method: 'GET',
    path: '/rest/admin/application-version',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['adminSectionChallenge'],
    evidence: 'Endpoint mang ngữ cảnh admin, nhưng YAML Admin Section là truy cập UI /#/administration; route này không tự chứng minh bypass admin section.',
  },
  {
    type: ['BFLA'],
    method: 'GET',
    path: '/rest/order-history/orders',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['ephemeralAccountantChallenge'],
    evidence: 'server.ts bảo vệ bằng security.isAccounting(); liên quan role accounting. YAML có Ephemeral Accountant là login thành role accounting qua SQLi, không phải bypass trực tiếp endpoint này.',
  },
  {
    type: ['BFLA', 'IDOR'],
    method: 'PUT',
    path: '/rest/order-history/:id/delivery-status',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['ephemeralAccountantChallenge'],
    evidence: 'Endpoint chỉ cho accounting; nếu chiếm/bypass role accounting thì có tác động. YAML không mô tả delivery-status là challenge độc lập.',
  },
  {
    type: ['BFLA', 'Race_Condition'],
    method: 'POST',
    path: '/rest/basket/:id/checkout',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['negativeOrderChallenge', 'forgedCouponChallenge', 'manipulateClockChallenge'],
    evidence: 'routes/order.ts giải Payback Time khi totalPrice < 0 và xử lý forged/expired coupon; nhãn BFLA/race chỉ đúng ở mức surface thanh toán nhạy cảm.',
  },
  {
    type: ['IDOR'],
    method: 'PUT',
    path: '/rest/basket/:id/coupon/:param',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['forgedCouponChallenge', 'manipulateClockChallenge'],
    evidence: 'routes/coupon.ts áp coupon theo basket id; challenge YAML liên quan coupon forged/expired, không phải View Basket IDOR.',
  },
  {
    type: ['BFLA', 'IDOR'],
    method: 'POST',
    path: '/rest/user/data-export',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['dataExportChallenge'],
    evidence: 'Endpoint khớp GDPR Data Theft, nhưng manual test đang nói thiếu authentication. Source thực tế dùng security.appendUserId() và bug nằm ở data export/object logic, nên chỉ tính partial nếu chưa có bước chứng minh export dữ liệu người khác.',
  },
  {
    type: ['Race_Condition', 'Mass_Assignment'],
    method: 'POST',
    path: '/rest/user/data-export',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['dataExportChallenge'],
    evidence: 'Đúng surface GDPR Data Theft, nhưng YAML/source mô tả object/data export logic flaw, không phải race/mass assignment.',
  },
  {
    type: ['Mass_Assignment', 'BFLA'],
    method: 'POST',
    path: '/rest/deluxe-membership',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['freeDeluxeChallenge'],
    evidence: 'Endpoint khớp Deluxe Fraud, nhưng YAML/source mô tả business/input logic qua paymentMode không hợp lệ, không phải mass assignment/BFLA thuần túy.',
  },
  {
    type: ['Race_Condition'],
    method: 'PUT',
    path: '/rest/wallet/balance',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['web3WalletChallenge', 'negativeOrderChallenge'],
    evidence: 'Wallet là asset tiền trong source, nhưng YAML Wallet Depletion là Web3 withdraw logic; PUT /rest/wallet/balance không phải route được mô tả trong YAML.',
  },
  {
    type: ['BFLA'],
    method: 'PUT',
    path: '/rest/products/:id/reviews',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['forgedReviewChallenge'],
    evidence: 'routes/createProductReviews.ts solve Forged Review khi req.body.author khác email người dùng.',
  },
  {
    type: ['Race_Condition'],
    method: 'PUT',
    path: '/rest/products/:id/reviews',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['forgedReviewChallenge'],
    evidence: 'Đúng endpoint review nhạy cảm, nhưng challenge trên endpoint này là forged author, không phải race.',
  },
  {
    type: ['BFLA', 'IDOR'],
    method: 'PATCH',
    path: '/rest/products/reviews',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['forgedReviewChallenge', 'noSqlReviewsChallenge'],
    evidence: 'routes/updateProductReviews.ts cập nhật review theo req.body.id và solve Forged Review nếu sửa review của người khác; multi:true còn liên quan NoSQL Manipulation.',
  },
  {
    type: ['Race_Condition'],
    method: 'POST',
    path: '/rest/products/reviews',
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['timingAttackChallenge'],
    evidence: 'routes/likeProductReviews.ts có sleep trước khi cập nhật likedBy và solve Multiple Likes khi cùng user có hơn 2 like.',
  },
  {
    type: ['BFLA'],
    method: 'POST',
    path: '/rest/products/reviews',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['timingAttackChallenge'],
    evidence: 'Endpoint đúng, nhưng YAML/source mô tả race/timing attack chứ không phải function-level authorization.',
  },
  {
    type: ['Auth_Bypass'],
    method: 'GET',
    path: '/rest/user/change-password',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['changePasswordBenderChallenge'],
    evidence: 'Endpoint khớp Change Bender Password, nhưng manual test mô tả đổi mật khẩu không cần session. Source vẫn yêu cầu token; bug là thiếu currentPassword, nên nhãn Auth_Bypass chỉ đúng một phần.',
  },
  {
    type: ['Mass_Assignment', 'Auth_Bypass'],
    method: 'POST',
    path: '/rest/user/login',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['loginAdminChallenge', 'loginBenderChallenge', 'loginJimChallenge', 'ephemeralAccountantChallenge'],
    evidence: 'routes/login.ts có SQL injection trong login. Nhãn trong manual test không đúng loại, nhưng endpoint là authentication challenge surface.',
  },
  {
    type: ['IDOR'],
    method: 'GET',
    path: '/rest/track-order/:id',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['noSqlOrdersChallenge', 'reflectedXssChallenge'],
    evidence: 'routes/trackOrder.ts query Mongo bằng orderId và có NoSQL/XSS challenge; không phải IDOR trong YAML.',
  },
  {
    type: ['Auth_Bypass'],
    method: 'POST',
    path: '/file-upload',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['uploadSizeChallenge', 'uploadTypeChallenge', 'xxeFileDisclosureChallenge', 'xxeDosChallenge', 'yamlBombChallenge', 'fileWriteChallenge', 'deprecatedInterfaceChallenge'],
    evidence: 'YAML có nhiều challenge trên /file-upload, nhưng root cause là input validation/vulnerable component/XXE, không phải auth bypass.',
  },
  {
    type: ['BFLA', 'Auth_Bypass'],
    method: 'POST',
    path: '/profile/image/file',
    outcome: OUTCOMES.OUT_OF_YAML,
    challenges: [],
    evidence: 'Endpoint upload ảnh profile tồn tại, nhưng YAML không mô tả challenge BFLA/auth bypass cho route file upload ảnh này.',
  },
  {
    type: ['Mass_Assignment', 'Race_Condition'],
    method: 'POST',
    path: '/rest/memories',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['geoStalkingMetaChallenge', 'geoStalkingVisualChallenge', 'dataExportChallenge'],
    evidence: 'Photo Wall/memories liên quan các challenge geo-stalking và dữ liệu export, nhưng YAML không mô tả mass assignment/race trên POST /rest/memories.',
  },
  {
    type: ['Race_Condition'],
    method: 'POST',
    path: '/b2b/v2/orders',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['deprecatedInterfaceChallenge'],
    evidence: 'B2B v2 là deprecated interface surface; YAML không mô tả race condition cho endpoint này.',
  },
  {
    type: ['BFLA', 'Auth_Bypass'],
    method: 'POST',
    path: '/rest/chat',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['chatbotPromptInjectionChallenge', 'chatbotGreedyInjectionChallenge', 'aiDebuggingChallenge'],
    evidence: 'Chat route là surface thật cho prompt injection/AI debugging; nhãn BFLA/Auth_Bypass chỉ đúng một phần.',
  },
  {
    type: ['Mass_Assignment'],
    method: 'POST',
    path: '/rest/web3/submitKey',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['nftUnlockChallenge'],
    evidence: 'Web3 submitKey liên quan NFT Takeover/key submission, nhưng không phải mass assignment trong YAML.',
  },
  {
    type: ['Race_Condition', 'Auth_Bypass'],
    method: 'POST',
    path: '/rest/web3/walletNFTVerify',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['nftUnlockChallenge'],
    evidence: 'Web3 NFT verify thuộc ngữ cảnh NFT challenge, nhưng YAML không mô tả race/auth bypass ở endpoint này.',
  },
  {
    type: ['Auth_Bypass'],
    method: 'POST',
    path: '/rest/web3/walletExploitAddress',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['web3WalletChallenge'],
    evidence: 'Endpoint Web3 exploit address liên quan Wallet Depletion, nhưng YAML mô tả withdraw more ETH chứ không phải auth bypass.',
  },
  {
    type: ['Mass_Assignment'],
    method: 'POST',
    path: '/profile',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['usernameXssChallenge', 'csrfChallenge'],
    evidence: 'Profile update liên quan CSP bypass/user profile và CSRF challenge, nhưng nhãn mass assignment chưa khớp mô tả YAML.',
  },
  {
    type: ['Auth_Bypass', 'BFLA'],
    method: 'POST',
    path: '/snippets/verdict',
    outcome: OUTCOMES.OUT_OF_YAML,
    challenges: [],
    evidence: 'Đây là endpoint kiểm tra coding challenge/snippet, không phải lỗ hổng YAML độc lập.',
  },
  {
    type: ['BFLA'],
    method: 'POST',
    path: '/snippets/fixes',
    outcome: OUTCOMES.OUT_OF_YAML,
    challenges: [],
    evidence: 'Endpoint phục vụ coding challenge/fix, không có challenge YAML tương ứng dạng BFLA.',
  },
  {
    type: ['BFLA'],
    method: 'PUT',
    path: '/rest/continue-code/apply/:param',
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['continueCodeChallenge'],
    evidence: 'Continue-code endpoint liên quan Imaginary Challenge/restore progress; YAML là crypto/progress-code logic, không phải BFLA.',
  },
];

const GENERATED_REST_RULES = [
  {
    methods: ['PUT', 'DELETE', 'GET', 'POST'],
    pathPrefix: '/api/Cards',
    protectedBySource: 'server.ts dùng security.appendUserId() hoặc denyAll() và payment.ts lọc theo UserId.',
  },
  {
    methods: ['PUT', 'DELETE', 'GET', 'POST'],
    pathPrefix: '/api/Addresss',
    protectedBySource: 'server.ts dùng security.appendUserId() và address.ts lọc theo UserId.',
  },
  {
    methods: ['PUT', 'DELETE', 'GET', 'POST'],
    pathPrefix: '/api/Recycles',
    protectedBySource: 'server.ts bảo vệ POST bằng isAuthorized(), PUT/DELETE bằng denyAll(); không có challenge YAML cho IDOR recycle.',
  },
  {
    methods: ['POST', 'DELETE', 'GET'],
    pathPrefix: '/api/Quantitys',
    protectedBySource: 'server.ts dùng denyAll()/isAccounting() cho quantity APIs; không có challenge YAML cho race/BFLA quantity.',
  },
  {
    methods: ['POST'],
    pathPrefix: '/api/Products',
    protectedBySource: 'server.ts dùng security.isAuthorized() cho POST /api/Products; YAML Product Tampering nằm ở PUT /api/Products/:id.',
  },
  {
    methods: ['POST'],
    pathPrefix: '/api/Challenges',
    protectedBySource: 'server.ts dùng denyAll() cho POST /api/Challenges.',
  },
  {
    methods: ['POST'],
    pathPrefix: '/api/Hints',
    protectedBySource: 'server.ts dùng denyAll() cho POST /api/Hints.',
  },
  {
    methods: ['POST'],
    pathPrefix: '/api/Complaints',
    protectedBySource: 'server.ts dùng isAuthorized(); complaints có thể liên quan feedback/reporting workflow nhưng không có YAML BFLA/mass assignment riêng.',
  },
  {
    methods: ['POST'],
    pathPrefix: '/api/SecurityQuestions',
    protectedBySource: 'server.ts dùng denyAll() cho POST /api/SecurityQuestions.',
  },
  {
    methods: ['POST'],
    pathPrefix: '/api/PrivacyRequests',
    protectedBySource: 'server.ts dùng isAuthorized()/denyAll(); không có YAML BFLA riêng.',
  },
  {
    methods: ['GET'],
    pathPrefix: '/api/Deliverys',
    protectedBySource: 'Delivery methods là public catalog endpoint; không có challenge YAML IDOR/auth bypass tương ứng.',
  },
];

const SCANNER_RULES = [
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/login.ts'),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['loginAdminChallenge', 'loginBenderChallenge', 'loginJimChallenge', 'ephemeralAccountantChallenge'],
    evidence: 'routes/login.ts nối trực tiếp email/password vào Sequelize raw query; YAML có nhiều login SQLi challenges.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/search.ts'),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['unionSqlInjectionChallenge', 'dbSchemaChallenge'],
    evidence: 'routes/search.ts nối req.query.q vào SELECT; YAML User Credentials/Database Schema yêu cầu SQLi qua search.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/src/data/static/codefixes/dbSchemaChallenge'),
    outcome: OUTCOMES.CODEFIX_ONLY,
    challenges: ['dbSchemaChallenge'],
    evidence: 'Finding nằm trong data/static/codefixes của Juice Shop, khớp challenge DB Schema nhưng không phải route runtime chính.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/src/data/static/codefixes/unionSqlInjectionChallenge'),
    outcome: OUTCOMES.CODEFIX_ONLY,
    challenges: ['unionSqlInjectionChallenge'],
    evidence: 'Finding nằm trong codefix của challenge Union SQL Injection/User Credentials, không phải route runtime chính.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/userProfile.ts'),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['usernameXssChallenge', 'sstiChallenge'],
    evidence: 'routes/userProfile.ts eval username template expression và set CSP động; YAML có CSP Bypass và SSTi/RCE context.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/lib/insecurity.ts'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['jwtUnsignedChallenge', 'jwtForgedChallenge'],
    evidence: 'Finding là hard-coded RSA private key/JWT credential trong lib/insecurity.ts; đây là bằng chứng hỗ trợ JWT forged/unsigned challenge, nhưng scanner không tự chứng minh token exploit.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/fileServer.ts'),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['directoryListingChallenge', 'forgottenBackupChallenge', 'forgottenDevBackupChallenge', 'misplacedSignatureFileChallenge', 'easterEggLevelOneChallenge', 'nullByteChallenge'],
    evidence: 'routes/fileServer.ts serve /ftp files và cắt poison null byte; YAML có confidential document/backup/null-byte challenges.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/keyServer.ts'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['jwtForgedChallenge', 'jwtUnsignedChallenge'],
    evidence: 'server.ts expose /encryptionkeys và keyServer.ts sendFile key; đây là bằng chứng hỗ trợ JWT/key disclosure challenges, dù YAML không đặt tên riêng endpoint này.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/logfileServer.ts'),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['accessLogDisclosureChallenge', 'dlpPasswordSprayingChallenge'],
    evidence: 'server.ts expose /support/logs và logfileServer.ts sendFile logs; YAML Access Log và leaked logs/password spraying liên quan trực tiếp.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/quarantineServer.ts'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['sstiChallenge'],
    evidence: 'Quarantine files chứa URL juicy malware; YAML SSTi gợi ý tìm malware qua quarantine folder, nhưng bản thân endpoint chỉ là supporting evidence.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/redirect.ts'),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['redirectChallenge', 'redirectCryptoCurrencyChallenge'],
    evidence: 'routes/redirect.ts redirect theo query.to và allowlist includes; YAML Allowlist Bypass/Outdated Allowlist.',
  },
  {
    source: 'semgrep',
    when: allOf(findingLocationIncludes('/server.ts'), findingLineIn([269, 270])),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['directoryListingChallenge', 'forgottenBackupChallenge', 'forgottenDevBackupChallenge', 'misplacedSignatureFileChallenge'],
    evidence: 'server.ts expose /ftp directory listing/file serving; khớp Confidential Document và các backup/signature-file challenges.',
  },
  {
    source: 'semgrep',
    when: allOf(findingLocationIncludes('/server.ts'), findingLineIn([273, 277])),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['jwtForgedChallenge', 'jwtUnsignedChallenge', 'knownVulnerableComponentChallenge'],
    evidence: 'server.ts expose .well-known/encryptionkeys directory listing; đây là key/advisory disclosure context hỗ trợ JWT/component challenges, không phải challenge solution độc lập.',
  },
  {
    source: 'semgrep',
    when: allOf(findingLocationIncludes('/server.ts'), findingLineIn([281])),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['accessLogDisclosureChallenge', 'dlpPasswordSprayingChallenge'],
    evidence: 'server.ts expose /support/logs directory listing; khớp Access Log và leaked logs context.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/routes/videoHandler.ts'),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['videoXssChallenge'],
    evidence: 'routes/videoHandler.ts nhúng subtitles vào script tag; YAML Video XSS yêu cầu payload trong promo video subtitles.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/frontend/src/app/navbar/navbar.component.html'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['localXssChallenge', 'usernameXssChallenge', 'persistedXssUserChallenge'],
    evidence: 'Finding là template XSS sink ở frontend; YAML có nhiều XSS challenges, nhưng location này không phải challenge solution surface được mô tả trực tiếp.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/frontend/src/app/purchase-basket/purchase-basket.component.html'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['localXssChallenge', 'usernameXssChallenge', 'persistedXssUserChallenge'],
    evidence: 'Template sink có liên quan lớp XSS, nhưng YAML không nêu purchase-basket component là challenge surface cụ thể.',
  },
  {
    source: 'semgrep',
    when: findingLocationIncludes('/views/dataErasureForm.hbs'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['csrfChallenge', 'ghostLoginChallenge'],
    evidence: 'Data erasure form thuộc workflow GDPR erasure; YAML có CSRF/GDPR erasure context, nhưng finding unquoted attribute chưa tự khẳng định challenge solution.',
  },
  {
    source: 'zap',
    when: messageIncludes('Backup File Disclosure'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['forgottenBackupChallenge', 'forgottenDevBackupChallenge', 'directoryListingChallenge', 'sstiChallenge'],
    evidence: 'ZAP backup-file probes trên /ftp/quarantine* trúng directory/file exposure context; nếu là coupons_2013.md.bak hoặc package.json.bak thì khớp exact hơn, còn quarantine là supporting surface.',
  },
  {
    source: 'zap',
    when: allOf(messageIncludes('Bypassing 403'), locationIncludes('/ftp/coupons_2013.md.bak')),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['forgottenBackupChallenge', 'forgedCouponChallenge', 'nullByteChallenge'],
    evidence: 'ZAP phát hiện bypass 403 với coupons_2013.md.bak; YAML Forgotten Sales Backup/Forged Coupon dùng file coupon backup.',
  },
  {
    source: 'zap',
    when: allOf(messageIncludes('Bypassing 403'), locationIncludes('/ftp/package-lock.json.bak')),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['forgottenDevBackupChallenge', 'knownVulnerableComponentChallenge', 'typosquattingNpmChallenge'],
    evidence: 'Backup package lock hỗ trợ dependency/vulnerable component challenges, nhưng YAML Forgotten Developer Backup exact hơn với package.json.bak.',
  },
  {
    source: 'zap',
    when: allOf(messageIncludes('Bypassing 403'), locationIncludes('/ftp/suspicious_errors.yml')),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['misplacedSignatureFileChallenge', 'nullByteChallenge'],
    evidence: 'suspicious_errors.yml là misplaced SIEM signature file trong YAML/source.',
  },
  {
    source: 'zap',
    when: allOf(messageIncludes('Bypassing 403'), locationIncludes('/ftp/eastere.gg')),
    outcome: OUTCOMES.YAML_EXACT,
    challenges: ['easterEggLevelOneChallenge', 'nullByteChallenge'],
    evidence: 'eastere.gg là hidden easter egg file trong YAML/source.',
  },
  {
    source: 'zap',
    when: messageIncludes('Content Security Policy'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['usernameXssChallenge', 'localXssChallenge', 'persistedXssUserChallenge', 'videoXssChallenge'],
    evidence: 'Missing CSP làm tăng rủi ro XSS, nhưng Juice Shop còn có CSP-specific challenge; đây là signal hỗ trợ chứ không phải exploit evidence.',
  },
  {
    source: 'zap',
    when: messageIncludes('Dangerous JS Functions'),
    outcome: OUTCOMES.YAML_SUPPORTING,
    challenges: ['localXssChallenge', 'usernameXssChallenge'],
    evidence: 'main.js dangerous functions là XSS-relevant signal, nhưng không chỉ ra payload/challenge cụ thể.',
  },
  {
    source: 'zap',
    when: messageIncludes('Cross-Domain Misconfiguration'),
    outcome: OUTCOMES.YAML_PARTIAL,
    challenges: ['emailLeakChallenge'],
    evidence: 'YAML Email Leak nói unwanted information disclosure cross-domain; ZAP CORS/cross-domain misconfiguration có cùng ngữ cảnh nhưng chưa chứng minh endpoint leak cụ thể.',
  },
  {
    source: 'zap',
    when: anyOf(messageIncludes('Cross-Origin-Embedder-Policy'), messageIncludes('Cross-Origin-Opener-Policy'), messageIncludes('Deprecated Feature Policy')),
    outcome: OUTCOMES.OUT_OF_YAML,
    challenges: [],
    evidence: 'Đây là hardening/header misconfiguration hợp lệ để khuyến nghị, nhưng không có challenge YAML tương ứng.',
  },
  {
    source: 'zap',
    when: messageIncludes('Timestamp Disclosure'),
    outcome: OUTCOMES.UNSUPPORTED,
    challenges: [],
    evidence: 'YAML không có challenge timestamp disclosure. Finding này được giữ lại trong scanner output và xếp là no direct Juice Shop challenge mapping.',
  },
];

function parseArgs(argv) {
  const args = {
    challengesPath: DEFAULT_CHALLENGES,
    reportPath: DEFAULT_REPORT,
    htmlPath: DEFAULT_HTML,
    output: DEFAULT_OUTPUT,
    jsonOutput: DEFAULT_JSON_OUTPUT,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--challenges') args.challengesPath = argv[++i];
    else if (arg === '--report') args.reportPath = argv[++i];
    else if (arg === '--html') args.htmlPath = argv[++i];
    else if (arg === '--output') args.output = argv[++i];
    else if (arg === '--json-output') args.jsonOutput = argv[++i];
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node evaluation/evaluateJuiceShopContext.js [options]

Options:
  --challenges <yml>      OWASP Juice Shop challenges.yml ground truth
  --report <json>         security-report.json from this system
  --html <html>           security-report.html containing manual checklist
  --output <md>           Markdown output path
  --json-output <json>    JSON output path
`);
}

function readChallenges(path) {
  if (!existsSync(path)) throw new Error(`challenges.yml not found: ${path}`);
  const rows = yaml.load(readFileSync(path, 'utf8'));
  return {
    rows,
    byKey: new Map(rows.map(challenge => [challenge.key, challenge])),
  };
}

function readReport(path) {
  if (!existsSync(path)) throw new Error(`security-report.json not found: ${path}`);
  return JSON.parse(readFileSync(path, 'utf8'));
}

function readManualTestsFromHtml(path) {
  if (!existsSync(path)) return [];
  const html = readFileSync(path, 'utf8');
  const sectionMatch = html.match(/<h2 class="section-title">Manual Testing Checklist<\/h2>([\s\S]*?)<h2 class="section-title">Vulnerability Findings<\/h2>/);
  if (!sectionMatch) return [];

  return sectionMatch[1]
    .split('<div class="finding manual-test">')
    .slice(1)
    .map((block, index) => {
      const title = decodeHtml(extract(block, /<span class="finding-title">([\s\S]*?)<\/span>/));
      const [type, endpoint] = splitManualTitle(title);
      const method = endpoint.split(/\s+/)[0] ?? '';
      return {
        index: index + 1,
        id: decodeHtml(extract(block, /<strong class="finding-id">([\s\S]*?)<\/strong>/)),
        title,
        type,
        endpoint,
        method,
        path: normalizePath(endpoint.replace(/^\S+\s+/, '')),
        routeEvidence: decodeHtml(extractDetail(block, 'Route evidence')),
        classification: splitList(decodeHtml(extractDetail(block, 'Classification'))),
        middleware: splitList(decodeHtml(extractDetail(block, 'Middleware'))),
        riskSignals: splitList(decodeHtml(extractDetail(block, 'Risk signals'))),
        whyGenerated: decodeHtml(extract(block, /<div class="analysis-label">Why Generated<\/div><div class="analysis-text">([\s\S]*?)<\/div>/)),
        steps: decodeHtml(extract(block, /<div class="analysis-label">Steps<\/div><div class="analysis-text">([\s\S]*?)<\/div>/)),
        expectedResult: decodeHtml(extract(block, /<div class="analysis-label">Expected Result<\/div><div class="analysis-text">([\s\S]*?)<\/div>/)),
        confirmedIndicator: decodeHtml(extract(block, /<div class="triage-reason"><strong>Confirm:<\/strong>\s*([\s\S]*?)<\/div>/)),
      };
    });
}

function splitManualTitle(title) {
  const parts = title.split(' - ');
  return [parts[0] ?? '', parts.slice(1).join(' - ') || ''];
}

function extract(text, regex) {
  return (text.match(regex) ?? [])[1] ?? '';
}

function extractDetail(text, label) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return extract(text, new RegExp(`<dt>${escaped}<\\/dt>\\s*<dd>([\\s\\S]*?)<\\/dd>`));
}

function splitList(value) {
  return value ? value.split(',').map(item => item.trim()).filter(Boolean) : [];
}

function decodeHtml(value) {
  return String(value ?? '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

function dedupeManualTests(tests) {
  const grouped = new Map();
  for (const test of tests) {
    const key = `${test.type} ${test.method} ${test.path}`;
    const existing = grouped.get(key);
    if (existing) {
      existing.duplicates += 1;
      existing.duplicateRouteEvidence.push(test.routeEvidence);
    } else {
      grouped.set(key, { ...test, duplicates: 1, duplicateRouteEvidence: [test.routeEvidence] });
    }
  }
  return [...grouped.values()];
}

function normalizePath(path) {
  return String(path ?? '')
    .trim()
    .replace(/^https?:\/\/[^/]+/i, '')
    .replace(/\?.*$/, '')
    .replace(/\/+$/, '')
    .replace(/:continueCode\b/g, ':param')
    .replace(/:coupon\b/g, ':param')
    .replace(/:challenge\b/g, ':param')
    .replace(/:key\b/g, ':param')
    .replace(/:id\b/g, ':id') || '/';
}

function evaluateManualTests(tests, challengesByKey) {
  const rows = tests.map(test => {
    const rule = findManualRule(test);
    return decorateAssessment({
      ...test,
      kind: 'manual',
      outcome: rule?.outcome ?? OUTCOMES.OUT_OF_YAML,
      challenges: rule?.challenges ?? [],
      evidence: rule?.evidence ?? 'Không tìm thấy challenge YAML mô tả endpoint/kiểu lỗi này. Không nên tính là FP nếu chưa chạy tay; nên ghi là candidate ngoài ground truth cần kiểm chứng.',
    }, challengesByKey);
  });

  return {
    rows,
    summary: summarizeRows(rows),
    byType: summarizeBy(rows, row => row.type),
  };
}

function findManualRule(test) {
  const exact = ROUTE_RULES.find(rule => {
    return ruleMatchesType(rule, test.type) && rule.method === test.method && normalizePath(rule.path) === test.path;
  });
  if (exact) return exact;

  const generatedRest = GENERATED_REST_RULES.find(rule => {
    return rule.methods.includes(test.method) && test.path.startsWith(normalizePath(rule.pathPrefix));
  });
  if (generatedRest) {
    return {
      outcome: OUTCOMES.UNSUPPORTED,
      challenges: [],
      evidence: generatedRest.protectedBySource,
    };
  }

  return undefined;
}

function ruleMatchesType(rule, type) {
  if (!rule.type) return true;
  return Array.isArray(rule.type) ? rule.type.includes(type) : rule.type === type;
}

function evaluateScannerFindings(findings, challengesByKey) {
  const rows = findings.map(finding => {
    const original = finding.original_finding ?? {};
    const rule = SCANNER_RULES.find(candidate => {
      if (candidate.source && original.source !== candidate.source) return false;
      return candidate.when(original, finding);
    });

    return decorateAssessment({
      kind: 'scanner',
      id: finding.id,
      source: original.source,
      category: original.category,
      severity: original.severity,
      message: original.message,
      location: original.location,
      triageStatus: finding.triage_status,
      riskScore: finding.risk_score,
      outcome: rule?.outcome ?? OUTCOMES.OUT_OF_YAML,
      challenges: rule?.challenges ?? [],
      evidence: rule?.evidence ?? 'Không có challenge YAML trực tiếp. Có thể vẫn là hardening/security smell hợp lệ của tool, nhưng không nên tính là Juice Shop challenge match.',
    }, challengesByKey);
  });

  return {
    rows,
    summary: summarizeRows(rows),
    bySource: summarizeBy(rows, row => row.source),
  };
}

function decorateAssessment(row, challengesByKey) {
  const challengeDetails = (row.challenges ?? []).map(key => {
    const challenge = challengesByKey.get(key);
    return {
      key,
      name: challenge?.name ?? key,
      category: challenge?.category ?? '',
      description: stripHtml(challenge?.description ?? ''),
    };
  });
  return {
    ...row,
    outcomeLabel: OUTCOME_LABELS[row.outcome] ?? row.outcome,
    challenges: challengeDetails,
    challengeKeys: challengeDetails.map(challenge => challenge.key),
    challengeNames: challengeDetails.map(challenge => challenge.name),
  };
}

function stripHtml(value) {
  return String(value ?? '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function summarizeRows(rows) {
  const counts = countBy(rows, row => row.outcome);
  const yamlMatched = (counts[OUTCOMES.YAML_EXACT] ?? 0) + (counts[OUTCOMES.YAML_PARTIAL] ?? 0) + (counts[OUTCOMES.YAML_SUPPORTING] ?? 0) + (counts[OUTCOMES.CODEFIX_ONLY] ?? 0);
  const runtimeOrManualUseful = (counts[OUTCOMES.YAML_EXACT] ?? 0) + (counts[OUTCOMES.YAML_PARTIAL] ?? 0) + (counts[OUTCOMES.YAML_SUPPORTING] ?? 0);
  return {
    total: rows.length,
    yamlExact: counts[OUTCOMES.YAML_EXACT] ?? 0,
    yamlPartial: counts[OUTCOMES.YAML_PARTIAL] ?? 0,
    yamlSupporting: counts[OUTCOMES.YAML_SUPPORTING] ?? 0,
    codefixOnly: counts[OUTCOMES.CODEFIX_ONLY] ?? 0,
    outOfYaml: counts[OUTCOMES.OUT_OF_YAML] ?? 0,
    unsupported: counts[OUTCOMES.UNSUPPORTED] ?? 0,
    yamlMatched,
    runtimeOrManualUseful,
    yamlMatchRate: ratio(yamlMatched, rows.length),
    usefulRateExcludingCodefix: ratio(runtimeOrManualUseful, rows.length),
  };
}

function summarizeBy(rows, getKey) {
  const buckets = new Map();
  for (const row of rows) {
    const key = getKey(row) || 'unknown';
    const bucket = buckets.get(key) ?? [];
    bucket.push(row);
    buckets.set(key, bucket);
  }

  return [...buckets.entries()]
    .sort(([a], [b]) => String(a).localeCompare(String(b)))
    .map(([key, bucket]) => ({
      key,
      ...summarizeRows(bucket),
    }));
}

function countBy(rows, getKey) {
  const result = {};
  for (const row of rows) {
    const key = getKey(row);
    result[key] = (result[key] ?? 0) + 1;
  }
  return result;
}

function ratio(numerator, denominator) {
  if (!denominator) return 0;
  return Number((numerator / denominator).toFixed(4));
}

function percent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function challengeCoverage(manualRows, scannerRows, challenges) {
  const byChallenge = new Map();
  for (const challenge of challenges) {
    byChallenge.set(challenge.key, {
      key: challenge.key,
      name: challenge.name,
      category: challenge.category,
      exact: 0,
      partial: 0,
      supporting: 0,
      codefixOnly: 0,
      scannerIds: [],
      manualTitles: [],
    });
  }

  for (const row of [...manualRows, ...scannerRows]) {
    for (const key of row.challengeKeys ?? []) {
      const item = byChallenge.get(key);
      if (!item) continue;
      if (row.outcome === OUTCOMES.YAML_EXACT) item.exact += 1;
      if (row.outcome === OUTCOMES.YAML_PARTIAL) item.partial += 1;
      if (row.outcome === OUTCOMES.YAML_SUPPORTING) item.supporting += 1;
      if (row.outcome === OUTCOMES.CODEFIX_ONLY) item.codefixOnly += 1;
      if (row.kind === 'scanner') item.scannerIds.push(row.id);
      if (row.kind === 'manual') item.manualTitles.push(row.title);
    }
  }

  const rows = [...byChallenge.values()];
  const exact = rows.filter(row => row.exact > 0);
  const anyRuntimeOrManual = rows.filter(row => row.exact + row.partial + row.supporting > 0);
  const anyIncludingCodefix = rows.filter(row => row.exact + row.partial + row.supporting + row.codefixOnly > 0);

  return {
    exactCount: exact.length,
    runtimeOrManualContextCount: anyRuntimeOrManual.length,
    anyContextIncludingCodefixCount: anyIncludingCodefix.length,
    rows,
    matchedRows: anyIncludingCodefix,
  };
}

function challengeCategorySummary(challenges) {
  return summarizeBy(challenges, challenge => challenge.category).map(row => ({
    category: row.key,
    count: row.total,
  })).sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
}

function findingLocationIncludes(needle) {
  const lowered = normalizeSlashes(needle).toLowerCase();
  return finding => normalizeSlashes(String(finding.location ?? finding.file ?? '')).toLowerCase().includes(lowered);
}

function findingLineIn(lines) {
  const allowed = new Set(lines.map(line => Number(line)));
  return finding => allowed.has(Number(finding.line));
}

function locationIncludes(needle) {
  const lowered = normalizeSlashes(needle).toLowerCase();
  return finding => normalizeSlashes(String(finding.location ?? finding.file ?? '')).toLowerCase().includes(lowered);
}

function messageIncludes(needle) {
  const lowered = needle.toLowerCase();
  return finding => String(finding.message ?? '').toLowerCase().includes(lowered);
}

function allOf(...predicates) {
  return (finding, triaged) => predicates.every(predicate => predicate(finding, triaged));
}

function anyOf(...predicates) {
  return (finding, triaged) => predicates.some(predicate => predicate(finding, triaged));
}

function normalizeSlashes(value) {
  return String(value ?? '').replace(/\\/g, '/');
}

function buildMarkdown({ challenges, report, manualRawCount, manualEval, scannerEval, coverage }) {
  const manualSummary = manualEval.summary;
  const scannerSummary = scannerEval.summary;
  const verifiedManual = manualEval.rows.filter(row => row.outcome === OUTCOMES.YAML_EXACT);
  const partialManual = manualEval.rows.filter(row => row.outcome === OUTCOMES.YAML_PARTIAL);
  const outOfYamlManual = manualEval.rows.filter(row => row.outcome === OUTCOMES.OUT_OF_YAML);
  const unsupportedManual = manualEval.rows.filter(row => row.outcome === OUTCOMES.UNSUPPORTED);
  const scannerExact = scannerEval.rows.filter(row => row.outcome === OUTCOMES.YAML_EXACT);
  const scannerSupporting = scannerEval.rows.filter(row => row.outcome === OUTCOMES.YAML_SUPPORTING || row.outcome === OUTCOMES.YAML_PARTIAL);

  return `# Juice Shop Context Evaluation

Báo cáo này đối chiếu theo **ngữ cảnh lỗ hổng/challenge** trong OWASP Juice Shop \`challenges.yml\`, không coi mọi kết quả ngoài YAML là false positive. YAML là ground truth cấp challenge, còn report của hệ thống gồm scanner findings và manual test candidates.

## Tóm tắt

| Metric | Value |
|---|---:|
| Juice Shop challenges trong YAML | ${challenges.rows.length} |
| Scanner findings trong JSON | ${report.triaged_findings?.length ?? 0} |
| Manual test cards trong HTML | ${manualRawCount} |
| Manual tests unique sau de-dup | ${manualEval.rows.length} |
| Challenges có khớp exact từ scanner/manual | ${coverage.exactCount} / ${challenges.rows.length} |
| Challenges có ngữ cảnh runtime/manual exact+partial+supporting | ${coverage.runtimeOrManualContextCount} / ${challenges.rows.length} |
| Challenges có bất kỳ bằng chứng, gồm cả codefix | ${coverage.anyContextIncludingCodefixCount} / ${challenges.rows.length} |

## Cách hiểu nhãn

| Nhãn | Ý nghĩa |
|---|---|
| ${OUTCOME_LABELS[OUTCOMES.YAML_EXACT]} | Endpoint/file/loại lỗi khớp rõ với mô tả YAML hoặc source solve challenge. |
| ${OUTCOME_LABELS[OUTCOMES.YAML_PARTIAL]} | Đúng surface hoặc đúng challenge family, nhưng nhãn lỗi rộng/sai một phần. |
| ${OUTCOME_LABELS[OUTCOMES.YAML_SUPPORTING]} | Bằng chứng hỗ trợ việc khai thác challenge nhưng chưa phải exploit/challenge solution đầy đủ. |
| ${OUTCOME_LABELS[OUTCOMES.CODEFIX_ONLY]} | Khớp file codefix/coding challenge đi kèm Juice Shop, không phải runtime route chính. |
| ${OUTCOME_LABELS[OUTCOMES.OUT_OF_YAML]} | Candidate hoặc hardening issue không được YAML liệt kê. Không tính là FP nếu chưa chạy tay. |
| ${OUTCOME_LABELS[OUTCOMES.UNSUPPORTED]} | Source/YAML không ủng hộ giả thuyết, ví dụ route bị denyAll hoặc challenge không tồn tại. |

## Manual Test Context Match

| Metric | Count | Rate |
|---|---:|---:|
| Unique manual tests | ${manualSummary.total} | 100.0% |
| Khớp YAML exact | ${manualSummary.yamlExact} | ${percent(ratio(manualSummary.yamlExact, manualSummary.total))} |
| Khớp YAML một phần | ${manualSummary.yamlPartial} | ${percent(ratio(manualSummary.yamlPartial, manualSummary.total))} |
| Bằng chứng hỗ trợ YAML | ${manualSummary.yamlSupporting} | ${percent(ratio(manualSummary.yamlSupporting, manualSummary.total))} |
| Ngoài YAML/candidate mới | ${manualSummary.outOfYaml} | ${percent(ratio(manualSummary.outOfYaml, manualSummary.total))} |
| Không được YAML/source ủng hộ | ${manualSummary.unsupported} | ${percent(ratio(manualSummary.unsupported, manualSummary.total))} |
| Tổng có giá trị đối chiếu YAML exact+partial+supporting | ${manualSummary.runtimeOrManualUseful} | ${percent(manualSummary.usefulRateExcludingCodefix)} |

## Manual By Type

| Type | Tests | Exact | Partial | Supporting | Ngoài YAML | Unsupported |
|---|---:|---:|---:|---:|---:|---:|
${manualEval.byType.map(row => `| ${row.key} | ${row.total} | ${row.yamlExact} | ${row.yamlPartial} | ${row.yamlSupporting} | ${row.outOfYaml} | ${row.unsupported} |`).join('\n')}

## Scanner Context Match

| Metric | Value |
|---|---:|
| Findings | ${scannerSummary.total} |
| Khớp YAML exact | ${scannerSummary.yamlExact} |
| Khớp YAML một phần | ${scannerSummary.yamlPartial} |
| Bằng chứng hỗ trợ YAML | ${scannerSummary.yamlSupporting} |
| Codefix/coding challenge only | ${scannerSummary.codefixOnly} |
| Ngoài YAML/hardening | ${scannerSummary.outOfYaml} |
| Unsupported | ${scannerSummary.unsupported} |
| Match rate gồm codefix | ${percent(scannerSummary.yamlMatchRate)} |
| Runtime/supporting match không tính codefix | ${percent(scannerSummary.usefulRateExcludingCodefix)} |

## Scanner By Source

| Source | Findings | Exact | Partial | Supporting | Codefix | Ngoài YAML | Unsupported |
|---|---:|---:|---:|---:|---:|---:|---:|
${scannerEval.bySource.map(row => `| ${row.key} | ${row.total} | ${row.yamlExact} | ${row.yamlPartial} | ${row.yamlSupporting} | ${row.codefixOnly} | ${row.outOfYaml} | ${row.unsupported} |`).join('\n')}

## Manual Exact Matches

${formatManualRows(verifiedManual)}

## Manual Partial Matches

${formatManualRows(partialManual)}

## Manual Candidate Ngoài YAML

${formatManualRows(outOfYamlManual)}

## Manual Unsupported / Source Không Ủng Hộ

${formatManualRows(unsupportedManual)}

## Scanner Exact Matches

${formatScannerRows(scannerExact)}

## Scanner Partial/Supporting Matches

${formatScannerRows(scannerSupporting)}

## Challenge Coverage

${formatCoverageRows(coverage.matchedRows)}

## Ground Truth Categories

| Category | Challenges |
|---|---:|
${challengeCategorySummary(challenges.rows).map(row => `| ${row.category} | ${row.count} |`).join('\n')}

## Kết luận kỹ thuật

- Với test thủ công, con số công tâm không phải "precision = exact / all" theo kiểu scanner, vì nhiều dòng là test candidate chưa chạy. Nên báo cáo: exact YAML match, partial YAML match, candidate ngoài YAML, và unsupported riêng.
- Các candidate ngoài YAML là phần cải tiến hợp lệ ở mức sinh checklist, nhưng muốn gọi là vulnerability confirmed cần bằng chứng chạy tay: request/response, tài khoản dùng, dữ liệu trước-sau, mã trạng thái, và tác động.
- Các scanner như ZAP/Semgrep phát hiện tốt lớp injection/file exposure/header hardening, nhưng không bao phủ tốt multi-step business logic, JWT forging, IDOR cần session, race condition và BFLA cần role/context.
- Những finding trỏ vào \`data/static/codefixes/*\` khớp ngữ cảnh bài học Juice Shop, nhưng không nên tính ngang với lỗ hổng runtime đang khai thác.
`;
}

function formatManualRows(rows) {
  if (!rows.length) return 'None.';
  return rows
    .map(row => {
      const challenges = row.challengeNames.length ? row.challengeNames.join(', ') : 'Không có challenge YAML trực tiếp';
      const extra = row.duplicates > 1 ? `; duplicates: ${row.duplicates}` : '';
      return `- \`${row.title}\` -> ${row.outcomeLabel}; YAML: ${challenges}${extra}. ${row.evidence}`;
    })
    .join('\n');
}

function formatScannerRows(rows) {
  if (!rows.length) return 'None.';
  return rows
    .map(row => {
      const challenges = row.challengeNames.length ? row.challengeNames.join(', ') : 'Không có challenge YAML trực tiếp';
      return `- \`${row.id}\` [${row.source}/${row.severity}/${row.triageStatus}] \`${row.location}\` -> ${row.outcomeLabel}; YAML: ${challenges}. ${row.evidence}`;
    })
    .join('\n');
}

function formatCoverageRows(rows) {
  if (!rows.length) return 'None.';
  return `| Challenge | Category | Exact | Partial | Supporting | Codefix |
|---|---|---:|---:|---:|---:|
${rows
    .sort((a, b) => (b.exact - a.exact) || (b.partial - a.partial) || a.name.localeCompare(b.name))
    .map(row => `| ${row.name} | ${row.category} | ${row.exact} | ${row.partial} | ${row.supporting} | ${row.codefixOnly} |`)
    .join('\n')}`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const challengesPath = resolve(args.challengesPath);
  const reportPath = resolve(args.reportPath);
  const htmlPath = resolve(args.htmlPath);

  const challenges = readChallenges(challengesPath);
  const report = readReport(reportPath);
  const manualTests = readManualTestsFromHtml(htmlPath);
  const uniqueManualTests = dedupeManualTests(manualTests);
  const manualEval = evaluateManualTests(uniqueManualTests, challenges.byKey);
  const scannerEval = evaluateScannerFindings(report.triaged_findings ?? [], challenges.byKey);
  const coverage = challengeCoverage(manualEval.rows, scannerEval.rows, challenges.rows);

  const result = {
    inputs: {
      challengesPath,
      reportPath,
      htmlPath,
    },
    taxonomy: OUTCOME_LABELS,
    groundTruth: {
      challengeCount: challenges.rows.length,
      categories: challengeCategorySummary(challenges.rows),
    },
    scanner: scannerEval,
    manual: {
      rawCount: manualTests.length,
      uniqueCount: uniqueManualTests.length,
      ...manualEval,
    },
    challengeCoverage: coverage,
  };

  const jsonOut = resolve(args.jsonOutput);
  mkdirSync(dirname(jsonOut), { recursive: true });
  writeFileSync(jsonOut, JSON.stringify(result, null, 2), 'utf8');

  const markdown = buildMarkdown({
    challenges,
    report,
    manualRawCount: manualTests.length,
    manualEval,
    scannerEval,
    coverage,
  });

  const markdownOut = resolve(args.output);
  mkdirSync(dirname(markdownOut), { recursive: true });
  writeFileSync(markdownOut, markdown, 'utf8');

  console.log(markdown);
  console.log(`[OUTPUT] ${markdownOut}`);
  console.log(`[OUTPUT] ${jsonOut}`);
}

main();
