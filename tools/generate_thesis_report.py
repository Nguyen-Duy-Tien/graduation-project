import html
import json
import re
import zipfile
from copy import copy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DOCX = ROOT / "Nguyen Duy Tien - Bao cao hoan chinh.docx"


def find_source_docx():
    candidates = [
        path for path in ROOT.glob("*.docx")
        if path.resolve() != OUTPUT_DOCX.resolve()
    ]
    for path in candidates:
        if "Nguyễn" in path.name or "Tiến" in path.name:
            return path
    if candidates:
        return candidates[0]
    raise FileNotFoundError("No source .docx file found")


SOURCE_DOCX = find_source_docx()


def esc(text):
    return html.escape(str(text), quote=True)


def r(text, bold=False, italic=False, size=26):
    props = [
        '<w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" '
        'w:eastAsia="Times New Roman" w:cs="Times New Roman"/>',
        f'<w:sz w:val="{size}"/>',
        f'<w:szCs w:val="{size}"/>',
    ]
    if bold:
        props.insert(0, "<w:b/><w:bCs/>")
    if italic:
        props.insert(0, "<w:i/><w:iCs/>")
    return f"<w:r><w:rPr>{''.join(props)}</w:rPr><w:t>{esc(text)}</w:t></w:r>"


def p(text="", style=None, bold=False, italic=False, align=None, size=26, before=0, after=100):
    ppr = []
    if style:
        ppr.append(f'<w:pStyle w:val="{style}"/>')
    if align:
        ppr.append(f'<w:jc w:val="{align}"/>')
    ppr.append(f'<w:spacing w:before="{before}" w:after="{after}" w:line="360" w:lineRule="auto"/>')
    return f"<w:p><w:pPr>{''.join(ppr)}</w:pPr>{r(text, bold=bold, italic=italic, size=size)}</w:p>"


def page_break():
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def heading(text, level=1):
    styles = {1: "Heading1", 2: "Heading2", 3: "Heading3", 4: "Heading4"}
    sizes = {1: 32, 2: 30, 3: 28, 4: 26}
    return p(text, style=styles.get(level, "Heading3"), bold=True, size=sizes.get(level, 26), before=160, after=120)


def bullet(text):
    return p("- " + text, after=60)


def caption(text):
    return p(text, italic=True, align="center", size=24, after=120)


def cell(text, bold=False):
    shading = '<w:shd w:fill="D9EAF7"/>' if bold else ""
    return (
        "<w:tc><w:tcPr>"
        '<w:tcW w:w="2400" w:type="dxa"/>'
        f"{shading}</w:tcPr>"
        f"{p(text, bold=bold, after=40)}"
        "</w:tc>"
    )


def table(rows, header=True):
    borders = (
        "<w:tblBorders>"
        '<w:top w:val="single" w:sz="6" w:space="0" w:color="000000"/>'
        '<w:left w:val="single" w:sz="6" w:space="0" w:color="000000"/>'
        '<w:bottom w:val="single" w:sz="6" w:space="0" w:color="000000"/>'
        '<w:right w:val="single" w:sz="6" w:space="0" w:color="000000"/>'
        '<w:insideH w:val="single" w:sz="6" w:space="0" w:color="000000"/>'
        '<w:insideV w:val="single" w:sz="6" w:space="0" w:color="000000"/>'
        "</w:tblBorders>"
    )
    xml = ['<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>' + borders + "</w:tblPr>"]
    for i, row in enumerate(rows):
        xml.append("<w:tr>")
        for value in row:
            xml.append(cell(value, bold=(header and i == 0)))
        xml.append("</w:tr>")
    xml.append("</w:tbl>")
    return "".join(xml)


def read_json(path):
    with open(ROOT / path, encoding="utf-8") as f:
        return json.load(f)


def pct(num, den):
    if not den:
        return "0,0%"
    return f"{num / den * 100:.1f}%".replace(".", ",")


def image_para_map(document_xml):
    paras = re.findall(r"<w:p[\s\S]*?</w:p>", document_xml)
    result = {}
    for para in paras:
        for rid in re.findall(r'r:embed="([^"]+)"', para):
            result[rid] = para
    return result


def image(rid, image_paras):
    return image_paras.get(rid, "")


def source_summary():
    juice = read_json("security-context-output-juice/context.json")
    sqli = read_json("security-context-output-sqli/context.json")
    crapi = read_json("security-context-output-crapi/context.json")
    bench = read_json("security-context-output-benchmark/context.json")
    eval_ctx = read_json("evaluation/juice-shop-context-evaluation.json")
    return juice, sqli, crapi, bench, eval_ctx


def build_body(image_paras, sect_pr):
    juice, sqli, crapi, bench, eval_ctx = source_summary()
    j_sum = juice["attackSurfaceSummary"]
    j_routes = juice["routes"]
    j_patterns = juice["codePatterns"]
    j_schemas = juice["schemas"]
    scanner = eval_ctx["scanner"]
    manual = eval_ctx["manual"]
    gt = eval_ctx["groundTruth"]

    parts = []

    # Cover
    parts += [
        p("BỘ GIÁO DỤC VÀ ĐÀO TẠO", bold=True, align="center"),
        p("BỘ NÔNG NGHIỆP VÀ PHÁT TRIỂN NÔNG THÔN", bold=True, align="center"),
        p("TRƯỜNG ĐẠI HỌC THỦY LỢI", bold=True, align="center"),
        image("rId8", image_paras),
        p("NGUYỄN DUY TIẾN", bold=True, align="center", size=30, before=240),
        p(
            "XÂY DỰNG QUY TRÌNH DEVSECOPS TÍCH HỢP KIỂM THỬ BẢO MẬT TỰ ĐỘNG "
            "TRONG PIPELINE CI/CD CHO ỨNG DỤNG WEB VỚI CƠ CHẾ HỖ TRỢ LỰA CHỌN "
            "CÔNG CỤ DỰA TRÊN NGỮ CẢNH",
            bold=True,
            align="center",
            size=30,
            before=220,
        ),
        p("ĐỒ ÁN TỐT NGHIỆP", bold=True, align="center", size=30, before=220),
        p("Ngành: An ninh mạng", align="center", before=120),
        p("Người hướng dẫn: TS. Đoàn Thị Quế", align="center"),
        p("HÀ NỘI, NĂM 2026", bold=True, align="center", before=520),
        page_break(),
        heading("LỜI CAM ĐOAN", 1),
        p(
            "Tác giả xin cam đoan đồ án tốt nghiệp này là kết quả nghiên cứu và triển khai của bản thân. "
            "Các nội dung mô tả hệ thống, số liệu thực nghiệm và đánh giá trong báo cáo được tổng hợp từ mã nguồn, "
            "file cấu hình, artifact và báo cáo đánh giá hiện có trong thư mục đồ án. Những nội dung tham khảo bên ngoài "
            "được liệt kê trong phần tài liệu tham khảo. Báo cáo không cố ý bổ sung chức năng hoặc kết quả không tồn tại "
            "trong hệ thống đã triển khai.",
        ),
        p("Tác giả đồ án", align="right", before=360),
        p("Nguyễn Duy Tiến", bold=True, align="right"),
        page_break(),
        heading("LỜI CẢM ƠN", 1),
        p(
            "Tác giả xin trân trọng cảm ơn TS. Đoàn Thị Quế đã định hướng, góp ý và hỗ trợ trong quá trình thực hiện "
            "đề tài. Tác giả cũng xin cảm ơn các thầy cô trong Khoa Công nghệ thông tin, Trường Đại học Thủy lợi đã "
            "truyền đạt kiến thức nền tảng về công nghệ phần mềm, hệ thống và an toàn thông tin. Những kiến thức đó là "
            "cơ sở để tác giả xây dựng, thử nghiệm và đánh giá quy trình DevSecOps trong đồ án này.",
        ),
        p(
            "Do phạm vi đề tài rộng, kết quả triển khai vẫn còn những giới hạn nhất định, đặc biệt ở kiểm thử có xác thực "
            "và xác nhận thủ công các lỗ hổng logic nghiệp vụ. Tác giả mong nhận được góp ý của hội đồng để tiếp tục "
            "hoàn thiện hệ thống trong các hướng phát triển tiếp theo.",
        ),
        page_break(),
    ]

    # TOC and lists
    parts += [
        heading("MỤC LỤC KHÁI QUÁT", 1),
        p("MỞ ĐẦU"),
        p("CHƯƠNG 1. CƠ SỞ LÝ THUYẾT"),
        p("CHƯƠNG 2. PHÂN TÍCH, THIẾT KẾ VÀ XÂY DỰNG HỆ THỐNG"),
        p("CHƯƠNG 3. TRIỂN KHAI THỬ NGHIỆM VÀ ĐÁNH GIÁ"),
        p("KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN"),
        p("TÀI LIỆU THAM KHẢO"),
        p("PHỤ LỤC"),
        page_break(),
        heading("DANH MỤC HÌNH", 1),
        table([
            ["Ký hiệu", "Tên hình"],
            ["Hình 1", "Mô hình cải tiến đề xuất cho DevSecOps"],
            ["Hình 2", "Luồng pipeline được xây dựng trong đề tài"],
            ["Hình 3", "Sơ đồ luồng thu thập ngữ cảnh"],
            ["Hình 4", "Cấu trúc file context.json"],
            ["Hình 5", "Sơ đồ luồng xử lý báo cáo"],
            ["Hình 6", "Kết quả pipeline trên Jenkins"],
            ["Hình 7", "Log thu thập ngữ cảnh"],
            ["Hình 8", "Log chạy SAST/SCA"],
            ["Hình 9", "Log deploy và DAST"],
        ]),
        heading("DANH MỤC BẢNG", 1),
        table([
            ["Ký hiệu", "Tên bảng"],
            ["Bảng 1", "So sánh SAST, DAST và SCA"],
            ["Bảng 2", "Yêu cầu chức năng của hệ thống"],
            ["Bảng 3", "Yêu cầu phi chức năng"],
            ["Bảng 4", "Các collector trong module thu thập ngữ cảnh"],
            ["Bảng 5", "Các adapter công cụ kiểm thử"],
            ["Bảng 6", "Thông tin ngữ cảnh thu được trên OWASP Juice Shop"],
            ["Bảng 7", "Kết quả đánh giá scanner theo ground truth Juice Shop"],
            ["Bảng 8", "Kết quả đánh giá checklist thủ công"],
            ["Bảng 9", "Các giới hạn đã xác định từ source"],
        ]),
        heading("DANH MỤC TỪ VIẾT TẮT", 1),
        table([
            ["Từ viết tắt", "Tiếng Anh", "Ý nghĩa trong đồ án"],
            ["AI", "Artificial Intelligence", "Mô hình Gemini dùng để lựa chọn công cụ, sinh checklist và triage báo cáo"],
            ["CI/CD", "Continuous Integration / Continuous Delivery", "Quy trình tích hợp, kiểm thử và triển khai tự động"],
            ["DAST", "Dynamic Application Security Testing", "Kiểm thử bảo mật trên ứng dụng đang chạy"],
            ["DevSecOps", "Development, Security, Operations", "Tích hợp bảo mật vào quy trình DevOps"],
            ["IDOR/BOLA", "Insecure Direct Object Reference / Broken Object Level Authorization", "Lỗi truy cập đối tượng không đúng quyền"],
            ["SAST", "Static Application Security Testing", "Kiểm thử bảo mật mã nguồn tĩnh"],
            ["SCA", "Software Composition Analysis", "Phân tích thư viện phụ thuộc và CVE"],
            ["JWT", "JSON Web Token", "Token JSON dùng trong xác thực không trạng thái"],
            ["BFLA", "Broken Function Level Authorization", "Lỗi phân quyền ở mức chức năng"],
        ]),
        page_break(),
    ]

    # Introduction
    parts += [
        heading("MỞ ĐẦU", 1),
        heading("1. Lý do chọn đề tài", 2),
        p(
            "Ứng dụng web hiện đại thường được phát triển theo nhịp phát hành nhanh, nhiều lần thay đổi nhỏ và phụ thuộc "
            "lớn vào thư viện mã nguồn mở. Nếu bảo mật chỉ được kiểm tra ở cuối chu kỳ phát triển, lỗ hổng thường bị phát hiện "
            "muộn, chi phí sửa cao và khó truy vết nguyên nhân. DevSecOps giải quyết vấn đề này bằng cách đưa hoạt động bảo mật "
            "vào pipeline CI/CD, nhưng trong thực tế việc tích hợp công cụ bảo mật vẫn gặp ba khó khăn chính: chọn công cụ chưa "
            "phù hợp với công nghệ của dự án, báo cáo thô khó ưu tiên xử lý, và các lỗ hổng logic như IDOR/BFLA/race condition "
            "khó được scanner tự động kết luận.",
        ),
        p(
            "Đề tài xây dựng một module DevSecOps có hỗ trợ AI nhằm thu thập ngữ cảnh dự án, đề xuất cấu hình công cụ kiểm thử, "
            "sinh checklist kiểm thử thủ công và tổng hợp báo cáo bảo mật. Điểm cốt lõi của đề tài không phải thay thế công cụ "
            "SAST/DAST/SCA, mà là tạo một lớp điều phối dựa trên ngữ cảnh để pipeline biết nên chạy công cụ nào, ưu tiên bề mặt "
            "tấn công nào và trình bày kết quả ra sao cho người phát triển.",
        ),
        heading("2. Mục tiêu nghiên cứu", 2),
        bullet("Xây dựng pipeline DevSecOps có thể chạy trên Jenkins, nhận target project thông qua tham số thay vì hardcode một ứng dụng duy nhất."),
        bullet("Tự động thu thập ngữ cảnh dự án gồm tech stack, endpoint, pattern nguy hiểm, schema/model, OpenAPI, git diff và container."),
        bullet("Sử dụng Gemini API để sinh cấu hình công cụ kiểm thử và checklist thủ công dựa trên endpoint/pattern/schema thực tế."),
        bullet("Tích hợp các adapter Semgrep, Bandit, Trivy, OWASP ZAP, Nuclei và Nikto theo cơ chế bật/tắt từ file cấu hình."),
        bullet("Chuẩn hóa, gộp trùng và triage kết quả scanner thành báo cáo HTML/JSON có executive summary và hướng khắc phục."),
        bullet("Đánh giá thực nghiệm trên OWASP Juice Shop và một số target phụ có sẵn trong workspace."),
        heading("3. Phạm vi và giới hạn", 2),
        p(
            "Đề tài tập trung vào kiểm thử bảo mật ứng dụng web trong pipeline CI/CD. Hệ thống hiện triển khai ở mức module Node.js, "
            "không xây dựng giao diện quản trị riêng. DAST được triển khai khi target có Docker Compose và service có port mapping. "
            "ZAP hiện chạy ở chế độ chưa đăng nhập tự động theo form-based authentication. Trivy adapter hiện thực thi quét filesystem "
            "(`fs`); các target `image` và `config` được sanitize và ghi log bỏ qua trong phiên bản hiện tại. AI không được phép chạy "
            "lệnh shell trực tiếp; mọi output AI phải đi qua schema, whitelist và bước sinh script an toàn.",
        ),
        heading("4. Phương pháp thực hiện", 2),
        bullet("Đọc và phân tích source code hiện có trong các thư mục `collector`, `ai`, `tools`, `runtime`, `evaluation`, `examples` và `Jenkinsfile`."),
        bullet("Thiết kế pipeline theo các stage rõ ràng: init, install, collect context, AI analyze, generate scripts, SAST/SCA, deploy/DAST, AI report và manual gate."),
        bullet("Đánh giá kết quả bằng artifact `context.json` và các file đánh giá Juice Shop trong thư mục `evaluation`."),
        bullet("Đối chiếu ground truth Juice Shop theo `challenges.yml` ở cấp challenge, phân biệt exact, partial, supporting, codefix-only, out-of-yaml và unsupported."),
        heading("5. Đóng góp chính của đề tài", 2),
        bullet("Một module thu thập ngữ cảnh không phụ thuộc Swagger, có thể suy ra attack surface từ route pattern và source code."),
        bullet("Một cơ chế chọn công cụ dựa trên ngữ cảnh, có fallback theo profile nếu AI hoặc file cấu hình gặp lỗi."),
        bullet("Một lớp an toàn cho output AI bằng whitelist/sanitize trước khi đưa tham số vào shell script."),
        bullet("Một bộ adapter công cụ theo registry, giúp mở rộng công cụ mới bằng cách thêm module adapter thay vì sửa toàn bộ Jenkinsfile."),
        bullet("Một cơ chế báo cáo hợp nhất nhiều nguồn scanner, sinh HTML/JSON và checklist kiểm thử thủ công có evidence."),
        page_break(),
    ]

    # Chapter 1
    parts += [
        heading("CHƯƠNG 1. CƠ SỞ LÝ THUYẾT", 1),
        heading("1.1. DevOps và DevSecOps", 2),
        p(
            "DevOps là phương pháp kết hợp phát triển phần mềm và vận hành hệ thống nhằm tăng tốc độ phát hành, giảm lỗi thao tác "
            "thủ công và cải thiện khả năng phản hồi. DevOps nhấn mạnh tự động hóa, hạ tầng nhất quán, giám sát và sự phối hợp giữa "
            "nhóm phát triển với nhóm vận hành. Trong một vòng đời DevOps điển hình, mã nguồn được lập kế hoạch, phát triển, build, "
            "test, release, deploy, operate và monitor theo vòng lặp liên tục.",
        ),
        p(
            "DevSecOps mở rộng DevOps bằng cách tích hợp bảo mật vào từng giai đoạn của vòng đời phát triển. Thay vì chờ tới giai đoạn "
            "kiểm thử cuối cùng, các hoạt động như kiểm tra mã nguồn, kiểm tra dependency, kiểm thử động và đánh giá cấu hình được đưa "
            "vào pipeline. Tư tưởng này thường được gọi là shift-left security: phát hiện và xử lý rủi ro càng sớm càng tốt.",
        ),
        heading("1.2. CI/CD trong phát triển phần mềm", 2),
        p(
            "Continuous Integration (CI) là quy trình tự động build và test mỗi khi có thay đổi mã nguồn. Continuous Delivery/Deployment "
            "(CD) tiếp tục đưa artifact đã qua kiểm tra tới môi trường staging hoặc production. Pipeline CI/CD giúp các thay đổi nhỏ được "
            "đánh giá nhanh, phát hiện lỗi sớm và giảm rủi ro phát hành. Trong bối cảnh an toàn thông tin, pipeline còn là nơi phù hợp để "
            "tích hợp security gate, báo cáo bảo mật và lưu artifact phục vụ truy vết.",
        ),
        heading("1.3. Các kỹ thuật kiểm thử bảo mật trong pipeline", 2),
        table([
            ["Kỹ thuật", "Đối tượng kiểm thử", "Ưu điểm", "Giới hạn chính"],
            ["SAST", "Mã nguồn, bytecode hoặc cấu trúc code", "Phát hiện sớm, không cần chạy ứng dụng", "Dễ nhiễu nếu rule không khớp framework; khó xác nhận runtime impact"],
            ["DAST", "Ứng dụng đang chạy qua HTTP", "Có evidence request/response thực tế", "Cần deploy target; khó kiểm thử endpoint cần đăng nhập hoặc logic nhiều bước"],
            ["SCA", "Thư viện, package, lockfile, image", "Phát hiện CVE trong dependency", "Không phát hiện lỗi logic trong code tự viết"],
            ["Manual test", "Luồng nghiệp vụ, role, session, token", "Phù hợp IDOR/BFLA/race/business logic", "Cần người kiểm thử xác nhận, không nên coi candidate là lỗ hổng đã chắc chắn"],
        ]),
        heading("1.4. Một số nhóm lỗ hổng web liên quan đến đề tài", 2),
        heading("1.4.1. Broken Authentication và JWT misuse", 3),
        p(
            "Broken Authentication xảy ra khi cơ chế xác thực cho phép kẻ tấn công mạo danh người dùng hợp lệ, ví dụ qua brute-force, "
            "logic reset mật khẩu sai hoặc quản lý session yếu. Với JWT, lỗi thường gặp gồm dùng thuật toán không phù hợp, xác minh chữ ký "
            "không đầy đủ, hardcoded secret hoặc tin tưởng dữ liệu trong payload mà không kiểm tra quyền ở server.",
        ),
        heading("1.4.2. Broken Access Control, IDOR và BFLA", 3),
        p(
            "Broken Access Control là nhóm lỗi cho phép người dùng truy cập tài nguyên hoặc chức năng ngoài quyền hạn. IDOR/BOLA xuất hiện "
            "khi API cho phép đổi định danh đối tượng như `id`, `userId`, `basketId` để xem hoặc sửa dữ liệu của người khác. BFLA xảy ra khi "
            "một chức năng đáng lẽ chỉ dành cho role nhất định lại có thể gọi trực tiếp bằng API. Các lỗi này thường cần nhiều tài khoản và "
            "nhiều vai trò để kiểm chứng, do đó scanner tự động khó kết luận chính xác.",
        ),
        heading("1.4.3. Injection và file upload", 3),
        p(
            "Injection là nhóm lỗi đưa dữ liệu không tin cậy vào câu lệnh SQL, NoSQL, shell command, template hoặc đoạn mã thực thi. File upload "
            "lại mở ra bề mặt tấn công liên quan MIME type, phần mở rộng, path traversal, XXE, decompression bomb hoặc ghi đè file. Đây là các nhóm "
            "được đề tài quan tâm vì vừa có thể phát hiện bằng SAST/DAST, vừa cần ngữ cảnh endpoint để ưu tiên kiểm thử.",
        ),
        heading("1.4.4. Mass assignment, race condition và business logic", 3),
        p(
            "Mass assignment xảy ra khi server nhận toàn bộ request body và ghi trực tiếp vào model, làm người dùng có thể chèn field nhạy cảm "
            "như `role`, `balance`, `permission`. Race condition xuất hiện khi nhiều request đồng thời làm thay đổi trạng thái như giỏ hàng, ví, "
            "quota hoặc coupon. Business logic flaw là các lỗi phụ thuộc nghiệp vụ nên khó phát hiện nếu chỉ quét payload tuần tự.",
        ),
        heading("1.5. Công cụ và công nghệ sử dụng trong đề tài", 2),
        p(
            "Hệ thống được viết bằng Node.js dạng ES Module, dùng `glob` để quét file và `js-yaml` để đọc YAML. Jenkinsfile định nghĩa pipeline "
            "theo Groovy DSL. Gemini API được gọi trực tiếp bằng `fetch` native của Node.js, không dùng SDK. Các scanner được chạy bằng Docker "
            "container trong script runtime, gồm Semgrep, Bandit, Trivy, OWASP ZAP, Nuclei và Nikto.",
        ),
        table([
            ["Thành phần", "Vai trò trong hệ thống", "Bằng chứng trong source"],
            ["Jenkins", "Điều phối các stage pipeline và publish HTML report", "`Jenkinsfile`"],
            ["Gemini API", "Tool selection, manual tests, triage report", "`ai/geminiClient.js`, `ai/aiAnalyzer.js`, `ai/reportGenerator.js`"],
            ["Semgrep", "SAST đa ngôn ngữ, trọng tâm Node/Python/Java/PHP...", "`tools/semgrep.js`"],
            ["Bandit", "SAST cho Python, chỉ chạy khi target là Python", "`tools/bandit.js`"],
            ["Trivy", "SCA filesystem dependency scan", "`tools/trivy.js`"],
            ["OWASP ZAP", "DAST baseline/api/full scan chưa đăng nhập tự động", "`tools/zap.js`"],
            ["Nuclei", "DAST template-based scan theo tag/severity", "`tools/nuclei.js`"],
            ["Nikto", "Web server scanner, thường bật cho PHP/generic web", "`tools/nikto.js`"],
        ]),
        page_break(),
    ]

    # Chapter 2
    parts += [
        heading("CHƯƠNG 2. PHÂN TÍCH, THIẾT KẾ VÀ XÂY DỰNG HỆ THỐNG", 1),
        heading("2.1. Bối cảnh vấn đề", 2),
        p(
            "Các pipeline DevSecOps truyền thống thường gắn công cụ theo cấu hình cố định. Cách làm này đơn giản nhưng dễ chạy thừa công cụ, "
            "bỏ sót rule quan trọng hoặc tạo báo cáo khó đọc. Ví dụ, Bandit chỉ có ý nghĩa với Python; Nikto phù hợp hơn với web server/PHP; "
            "ZAP API scan cần API spec; còn IDOR/BFLA thường không thể được kết luận nếu scanner không có hai session người dùng. Vì vậy, đề tài "
            "xây dựng một lớp thu thập ngữ cảnh và AI analyzer trước khi chạy scanner.",
        ),
    ]
    parts += [
        image("rId21", image_paras),
        caption("Hình 1. Mô hình cải tiến đề xuất cho DevSecOps"),
        heading("2.2. Yêu cầu hệ thống", 2),
        table([
            ["Mã", "Yêu cầu chức năng", "Hiện thực trong source"],
            ["FR-01", "Nhận target project qua tham số Jenkins, kiểm tra không được thoát workspace", "`TARGET_PROJECT_DIR`, `validateTargetProjectDir()` trong Jenkinsfile"],
            ["FR-02", "Thu thập tech stack, route, schema, code pattern, OpenAPI, git diff và container", "`collector/contextCollector.js`"],
            ["FR-03", "Dùng AI sinh `tool_config.json` theo schema cố định", "`ai/aiAnalyzer.js`"],
            ["FR-04", "Sinh checklist kiểm thử thủ công dựa trên endpoint/pattern/schema", "`generateManualTestCases()` trong `ai/aiAnalyzer.js`"],
            ["FR-05", "Sinh script runtime thay vì hardcode toàn bộ scanner trong Jenkinsfile", "`ai/pipelineGenerator.js`"],
            ["FR-06", "Chạy SAST/SCA bằng adapter Semgrep, Bandit, Trivy", "`tools/index.js`, `tools/semgrep.js`, `tools/bandit.js`, `tools/trivy.js`"],
            ["FR-07", "Deploy target bằng Docker Compose và chạy DAST nếu có service phù hợp", "`runtime/servicePicker.js`, `deploy-target.sh`, `run-dast.sh` được sinh ra"],
            ["FR-08", "Chuẩn hóa, gộp trùng và triage finding từ nhiều tool", "`ai/reportGenerator.js`"],
            ["FR-09", "Xuất báo cáo HTML/JSON và publish qua Jenkins", "`security-report.html`, `security-report.json`, `publishHTML` trong Jenkinsfile"],
            ["FR-10", "Quality gate dựa trên số critical finding", "`critical_count > 20` trong post stage của Jenkinsfile"],
        ]),
        table([
            ["Mã", "Yêu cầu phi chức năng", "Cách đáp ứng hiện tại"],
            ["NFR-01", "Bảo mật secret", "Gemini API key lấy từ Jenkins Credentials; collector chỉ lưu tên biến môi trường, không lưu giá trị"],
            ["NFR-02", "An toàn khi dùng output AI", "Whitelist/sanitize ruleset, tag, mode, service, network, port, path trước khi sinh shell"],
            ["NFR-03", "Khả năng mở rộng công cụ", "Registry adapter trong `tools/index.js`; thêm tool mới bằng module adapter"],
            ["NFR-04", "Khả năng chịu lỗi", "Collector có fallback; scanner dùng `|| true`; report fallback `needs_manual_review` khi AI parse lỗi"],
            ["NFR-05", "Tính di động", "Scanner chạy bằng Docker container, target deploy bằng Docker Compose nếu có"],
            ["NFR-06", "Tối ưu dữ liệu gửi AI", "Chỉ gửi high-risk routes, top findings, schema liên quan và xử lý manual tests theo batch"],
        ]),
        heading("2.3. Kiến trúc tổng thể", 2),
        image("rId22", image_paras),
        caption("Hình 2. Luồng pipeline được xây dựng trong đề tài"),
        p(
            "Luồng pipeline gồm chín stage: Init, Install deps, Collect context, AI analyze, Generate pipeline scripts, SAST+SCA, Deploy+DAST, "
            "AI Report và Manual Test Gate. Jenkinsfile giữ vai trò điều phối mỏng; logic chọn công cụ và sinh script nằm trong module Node.js. "
            "Cách tách này giúp thay đổi tool hoặc target mà không phải sửa toàn bộ pipeline.",
        ),
        table([
            ["Thư mục/File", "Vai trò"],
            ["`collector/`", "Thu thập ngữ cảnh bảo mật từ source target"],
            ["`ai/`", "Gọi Gemini, sinh tool config, manual tests, pipeline scripts và báo cáo"],
            ["`tools/`", "Adapter tạo shell command cho từng công cụ scanner"],
            ["`runtime/`", "Lớp sanitize và chọn service; nơi chứa script được sinh trong mỗi lần chạy"],
            ["`evaluation/`", "Script và kết quả đánh giá trên OWASP Juice Shop/benchmark"],
            ["`examples/sqli/`", "Ứng dụng Flask/MySQL cố ý có SQL Injection để thử nghiệm"],
            ["`benchmarks/`", "Các target benchmark: OWASP Benchmark, OWASP Juice Shop, crAPI"],
            ["`Jenkinsfile`", "Pipeline Jenkins end-to-end"],
        ]),
        heading("2.4. Module thu thập ngữ cảnh", 2),
        image("rId23", image_paras),
        caption("Hình 3. Sơ đồ luồng thu thập ngữ cảnh"),
        p(
            "Module `contextCollector.js` chạy `collectTechStack()` trước vì kết quả tech stack ảnh hưởng tới tập file và route pattern cần quét. "
            "Sau đó sáu nhóm collector còn lại chạy song song bằng `Promise.all`: route scanner, code pattern scanner, schema scanner, API surface, "
            "git diff và container info. Kết quả được hợp nhất thành `context.json` cùng `attackSurfaceSummary` để AI có dữ liệu gọn nhưng đủ ý nghĩa.",
        ),
        table([
            ["Collector", "Dữ liệu thu được", "Chi tiết hiện thực"],
            ["TechStack", "Ngôn ngữ, framework, package manager, feature jwt/orm/fileUpload, profile tool", "Đọc package.json, requirements.txt, pom.xml, composer.json, go.mod, Gemfile; hỗ trợ compose/monorepo"],
            ["RouteScanner", "Endpoint, method, file, line, classification, middleware/security signal", "Regex cho Express/NestJS/Flask/Django/Spring/Laravel/Gin/Rails; phân tích Express mount"],
            ["CodePattern", "Finding pattern nguy hiểm theo severity/category", "Các nhóm sqli, nosqli, rce, jwt, mass_assign, ssrf, xss, secret, path_traversal, auth_bypass, info_leak, redos"],
            ["SchemaScanner", "Model, field nhạy cảm, ownership field, mass assignment target", "Nhận Mongoose schema, Prisma model và class model"],
            ["ApiSurface", "OpenAPI/Swagger summary nếu có", "Tìm openapi/swagger/api YAML/JSON trong các vị trí phổ biến"],
            ["GitDiff", "File thay đổi, file nhạy cảm, khuyến nghị full/incremental", "Dùng `git rev-parse` và `git diff --name-only HEAD~1 HEAD`"],
            ["ContainerInfo", "Dockerfile, Docker Compose, image, port, env key, service detail", "Chỉ lưu tên biến môi trường, không lưu secret value"],
        ]),
        image("rId24", image_paras),
        caption("Hình 4. Cấu trúc file context.json"),
        p(
            "Route scanner không chỉ dựa trên tên đường dẫn mà còn tạo tín hiệu bảo mật. Với các route POST/PUT/PATCH/DELETE không phải endpoint "
            "xác thực, nếu không thấy middleware xác thực thì gắn `missing_auth`; nếu endpoint admin không thấy role check thì gắn `missing_admin`; "
            "nếu route có định danh đối tượng và có auth nhưng không thấy ownership check thì gắn `missing_ownership_check`. Các flag này là input chính "
            "để AI sinh checklist IDOR/BFLA/Auth_Bypass.",
        ),
        heading("2.5. Module AI analyzer", 2),
        p(
            "`aiAnalyzer.js` thực hiện hai nhóm chức năng. Thứ nhất, `analyzeAndSelectTools()` gửi payload đã rút gọn gồm tech stack, high-risk routes, "
            "top dangerous patterns, Swagger summary, git diff và container info lên Gemini để sinh `tool_config.json`. Thứ hai, `generateManualTestCases()` "
            "lọc endpoint có flag liên quan, chia batch, ghép thêm code evidence/schema liên quan và sinh `manual_tests.json`.",
        ),
        p(
            "Gemini client hiện gọi endpoint `generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent`, đặt "
            "`responseMimeType` là `application/json`, có retry cho HTTP 429/5xx và có hàm `parseJson()` để xử lý trường hợp model trả thêm text hoặc JSON fragment. "
            "Đây là cơ chế giúp pipeline vẫn nhận được JSON hợp lệ hoặc fail rõ ràng khi API trả lỗi không thể phục hồi.",
        ),
        table([
            ["Lời gọi AI", "Đầu vào", "Đầu ra", "Điểm kiểm soát"],
            ["Tool selection", "Tech stack, high-risk routes, top patterns, Swagger, git diff, container", "`tool_config.json`", "Schema nghiêm ngặt; fallback theo PROFILE_TOOL_MAP nếu config thiếu/sai"],
            ["Manual tests", "Endpoint relevant, risk signals, schema sensitive fields, code evidence", "`manual_tests.json`", "Không được invent endpoint; test case là giả thuyết kiểm thử, không phải kết luận lỗ hổng"],
            ["Report triage", "Finding đã normalize/dedup và context project", "`security-report.html/json`", "Map-reduce theo chunk; fallback `needs_manual_review` khi parse lỗi"],
        ]),
        heading("2.6. Sinh pipeline runtime và lớp an toàn", 2),
        p(
            "`pipelineGenerator.js` đọc `context.json` và `tool_config.json`, sau đó sinh `runtime-info.json`, `run-sast.sh`, `deploy-target.sh`, "
            "`run-dast.sh` và `teardown.sh`. Nếu `tool_config.json` không hợp lệ hoặc không có tool nào enabled, hệ thống fallback sang `PROFILE_TOOL_MAP` "
            "tương ứng với profile tech stack. Runtime dùng `servicePicker.js` để chọn service phù hợp từ Docker Compose, ưu tiên backend/API có port mapping "
            "và loại trừ database/cache/queue như mongo, postgres, mysql, redis.",
        ),
        p(
            "Vì AI có thể tạo cấu hình không an toàn hoặc không hợp lệ, mọi tham số động đều đi qua `runtime/sanitize.js`. Các ruleset Semgrep chỉ chấp nhận "
            "mẫu `p/...`, tag Nuclei chỉ nhận ký tự an toàn, ZAP mode chỉ thuộc `baseline|api-scan|full-scan`, service/network/port/focus path đều có whitelist. "
            "Đường dẫn được đưa vào shell bằng `shellQuote()` để giảm nguy cơ command injection.",
        ),
        heading("2.7. Adapter công cụ kiểm thử", 2),
        table([
            ["Adapter", "Điều kiện chạy", "Hiện thực thực tế"],
            ["Semgrep", "`cfg.semgrep.enabled` và có ruleset hợp lệ", "Chạy Docker `returntocorp/semgrep`, mount target read-only, output `semgrep-report.json`"],
            ["Bandit", "`cfg.bandit.enabled` và target language là Python", "Chạy Docker `ghcr.io/pycqa/bandit/bandit`, output `bandit-report.json`"],
            ["Trivy", "`cfg.trivy.enabled`", "Hiện chạy `trivy fs`; target `image`/`config` được ghi log chưa implement ở Phase 1"],
            ["ZAP", "`cfg.zap.enabled` và DAST không skip", "Chạy `zap-baseline.py`, `zap-api-scan.py` hoặc `zap-full-scan.py`; chưa có form-based auth tự động"],
            ["Nuclei", "`cfg.nuclei.enabled` và DAST không skip", "Chạy theo URL target, severity và tag đã sanitize, output JSONL"],
            ["Nikto", "`cfg.nikto.enabled` và DAST không skip", "Chạy Docker `alpine/nikto`, output JSON"],
        ]),
        heading("2.8. Module tổng hợp báo cáo", 2),
        image("rId25", image_paras),
        caption("Hình 5. Sơ đồ luồng xử lý báo cáo"),
        p(
            "`reportGenerator.js` đọc các file kết quả Semgrep, Bandit, Trivy, ZAP, Nuclei và Nikto nếu tồn tại. Mỗi reader ánh xạ output gốc về schema chung "
            "gồm source, ruleId, category, severity, location, file, line, message, snippet, CWE/OWASP nếu có. Sau đó `deduplicate()` gộp finding theo key "
            "`category:ruleId:location`, với cách normalize riêng cho ZAP/Nuclei/Nikto.",
        ),
        p(
            "Bước triage dùng cơ chế map-reduce. Findings sau dedup được chia chunk, AI phân loại từng finding thành `confirmed_vulnerability`, "
            "`likely_vulnerability` hoặc `needs_manual_review`, sinh risk score và remediation summary. Sau đó AI tổng hợp executive summary. Báo cáo HTML "
            "hiển thị thống kê severity, tool runs, checklist thủ công và từng finding; báo cáo JSON phục vụ tích hợp tiếp theo.",
        ),
        heading("2.9. Những điểm không được triển khai và không nên mô tả quá mức", 2),
        table([
            ["Nội dung", "Trạng thái thực tế trong source"],
            ["ZAP tự đăng nhập form-based auth", "Chưa triển khai; `authRequired` chỉ được ghi nhận trong cấu hình/checklist"],
            ["Trivy image scan và config/IaC scan", "Chưa triển khai trong adapter; chỉ `fs` chạy thật"],
            ["AI gắn nhãn `false_positive`", "Schema hiện chỉ có confirmed/likely/needs_manual_review"],
            ["Scanner tự xác nhận IDOR/BFLA", "Không có; hệ thống sinh manual test candidate để người kiểm thử xác minh"],
            ["DAST cho project không có Docker Compose/service port", "Pipeline sinh skip reason và bỏ qua DAST"],
            ["AI output chạy trực tiếp như lệnh shell", "Không có; output phải qua JSON schema, sanitize và pipelineGenerator"],
        ]),
        page_break(),
    ]

    # Chapter 3
    parts += [
        heading("CHƯƠNG 3. TRIỂN KHAI THỬ NGHIỆM VÀ ĐÁNH GIÁ", 1),
        heading("3.1. Môi trường và target thử nghiệm", 2),
        p(
            "Đề tài triển khai thử nghiệm với Jenkins, Docker/Docker Compose, Node.js và Gemini API key lưu trong Jenkins Credentials. Trong workspace hiện có "
            "các target: OWASP Juice Shop, crAPI, OWASP Benchmark và ứng dụng Flask/MySQL SQLi tự xây dựng. Phần đánh giá định lượng tập trung vào OWASP Juice Shop "
            "vì có ground truth `challenges.yml` và artifact đánh giá trong thư mục `evaluation`.",
        ),
        table([
            ["Target", "Ngữ cảnh thu được", "Mục đích sử dụng"],
            ["OWASP Juice Shop", "Node.js fullstack, Docker Compose, có Swagger, 239 endpoint", "Đánh giá end-to-end và so khớp ground truth challenge"],
            ["examples/sqli", "Python Flask, MySQL, Docker Compose, 16 endpoint, 6 SQLi pattern", "Kiểm thử collector và ví dụ sửa SQLi bằng parameterized query"],
            ["crAPI", "Containerized microservice, 47 endpoint, nhiều secret/pattern", "Kiểm thử khả năng đọc Docker Compose phức tạp"],
            ["OWASP Benchmark", "Java Spring, số lượng model/pattern lớn", "Kiểm thử collector trên benchmark Java lớn"],
        ]),
        heading("3.2. Cấu hình Jenkins", 2),
        p(
            "Jenkinsfile nhận tham số `TARGET_PROJECT_DIR` với giá trị mặc định `benchmarks/juice-shop`. Hàm `validateTargetProjectDir()` chỉ chấp nhận đường dẫn "
            "tương đối trong workspace, không cho đường dẫn tuyệt đối hoặc `..`. Các thư mục artifact gồm `security-context-output`, `scan-reports`, "
            "`final-report` và `runtime`. Gemini API key được lấy bằng `credentials('GEMINI_API_KEY')`, vì vậy Jenkins cần credential có ID tương ứng.",
        ),
        p(
            "Pipeline xóa artifact cũ trong `security-context-output`, chỉ xóa các script/runtime-info sinh động trong thư mục `runtime` để không làm mất source "
            "`sanitize.js` và `servicePicker.js`. Sau khi chạy xong, Jenkins archive artifact và publish `security-report.html`. Quality gate hiện đánh dấu build "
            "FAILURE nếu `critical_count > 20` trong `security-report.json`.",
        ),
        heading("3.3. Kết quả thu thập ngữ cảnh trên OWASP Juice Shop", 2),
        image("rId44", image_paras),
        caption("Hình 6. Kết quả pipeline trên Jenkins"),
        image("rId45", image_paras),
        caption("Hình 7. Log thu thập ngữ cảnh"),
        table([
            ["Chỉ số", "Giá trị từ `security-context-output-juice/context.json`"],
            ["Ngôn ngữ/framework", f"{juice['techStack']['language']} / {juice['techStack']['framework']}"],
            ["Feature phát hiện", f"jwt={juice['techStack']['features']['jwt']}, orm={juice['techStack']['features']['orm']}, fileUpload={juice['techStack']['features']['fileUpload']}"],
            ["Endpoint phát hiện", str(j_sum["totalEndpoints"])],
            ["Endpoint rủi ro cao", str(j_sum["highRiskEndpoints"])],
            ["Route classification", json.dumps(j_routes["classificationStats"], ensure_ascii=False)],
            ["Dangerous patterns", f"{j_patterns['totalFindings']} findings; critical={j_patterns['bySeverity']['critical']}, medium={j_patterns['bySeverity']['medium']}"],
            ["Schema/model", f"{j_schemas['totalModels']} models; {j_schemas['sensitiveFieldCount']} sensitive fields trong {len(j_schemas['modelsWithSensitiveFields'])} models"],
            ["OpenAPI/Swagger", "Có" if juice["apiSurface"]["specFound"] else "Không"],
            ["Container", f"Dockerfile={juice['containerInfo']['hasDockerfile']}, Docker Compose={juice['containerInfo']['hasDockerCompose']}"],
            ["Scan recommendation", juice["gitDiff"]["recommendation"]],
        ]),
        p(
            "Kết quả trên cho thấy collector không chỉ đọc package manifest mà còn quét được bề mặt API lớn của Juice Shop. Các nhóm endpoint rủi ro cao chủ yếu "
            "liên quan `authz`, `missing_auth`, `idor_candidate`, `fileUpload`, `payment` và `admin`. Đây là dữ liệu đầu vào trực tiếp cho bước AI sinh cấu hình "
            "công cụ và checklist thủ công.",
        ),
        heading("3.4. Kết quả chạy SAST/SCA/DAST và sinh báo cáo", 2),
        image("rId46", image_paras),
        caption("Hình 8. Log chạy SAST/SCA"),
        image("rId48", image_paras),
        caption("Hình 9. Log deploy và DAST"),
        p(
            "Artifact đánh giá Juice Shop hiện có ghi nhận 89 scanner findings trong `security-report.json` và 154 manual test cards trong HTML report. Sau khi "
            "de-duplication manual tests theo `vulnerability_type + method + endpoint`, còn 87 test thủ công duy nhất. Trong file đánh giá, scanner findings được "
            "phân theo nguồn Semgrep và ZAP; các tool khác nếu không có file report hoặc không có finding thì không được tính vào bảng đánh giá này.",
        ),
        table([
            ["Nguồn scanner", "Findings", "Exact", "Partial", "Supporting", "Codefix", "Ngoài YAML", "Unsupported"],
            ["Semgrep", "23", "11", "0", "8", "4", "0", "0"],
            ["ZAP", "66", "3", "5", "38", "0", "15", "5"],
            ["Tổng", str(scanner["summary"]["total"]), str(scanner["summary"]["yamlExact"]), str(scanner["summary"]["yamlPartial"]), str(scanner["summary"]["yamlSupporting"]), str(scanner["summary"]["codefixOnly"]), str(scanner["summary"]["outOfYaml"]), str(scanner["summary"]["unsupported"])],
        ]),
        p(
            f"Tỷ lệ scanner có khớp YAML/challenge bao gồm codefix đạt {scanner['summary']['yamlMatchRate'] * 100:.1f}% "
            f"và tỷ lệ hữu ích khi loại codefix đạt {scanner['summary']['usefulRateExcludingCodefix'] * 100:.1f}%. "
            "Semgrep có tỷ lệ match cao vì nhiều finding nằm trực tiếp trong source hoặc codefix của Juice Shop; ZAP tạo nhiều tín hiệu supporting như backup file, "
            "directory exposure, CSP/header hardening và CORS, nhưng một số finding không ánh xạ trực tiếp tới challenge YAML.",
        ),
        heading("3.5. Đánh giá checklist kiểm thử thủ công", 2),
        table([
            ["Loại test", "Số test", "Exact", "Partial", "Ngoài YAML", "Unsupported"],
            ["Auth_Bypass", "11", "0", "4", "1", "6"],
            ["BFLA", "27", "2", "9", "5", "11"],
            ["IDOR", "18", "3", "2", "1", "12"],
            ["Mass_Assignment", "17", "1", "7", "0", "9"],
            ["Race_Condition", "14", "0", "8", "2", "4"],
            ["Tổng", str(manual["summary"]["total"]), str(manual["summary"]["yamlExact"]), str(manual["summary"]["yamlPartial"]), str(manual["summary"]["outOfYaml"]), str(manual["summary"]["unsupported"])],
        ]),
        p(
            f"Manual checklist có {manual['summary']['yamlMatched']} test khớp exact hoặc partial với ground truth, tương ứng "
            f"{manual['summary']['yamlMatchRate'] * 100:.1f}% trên 87 test duy nhất. Con số này cần được hiểu đúng: checklist là danh sách giả thuyết kiểm thử "
            "được sinh từ evidence, không phải danh sách lỗ hổng đã xác nhận. Những test `unsupported` cho thấy AI vẫn có xu hướng sinh candidate rộng khi route có "
            "flag rủi ro nhưng source/YAML không ủng hộ exploit tương ứng. Đây là điểm cần cải tiến bằng cách bổ sung bước xác minh tự động hoặc rule lọc sau AI.",
        ),
        heading("3.6. Mức bao phủ theo ground truth Juice Shop", 2),
        p(
            f"Ground truth Juice Shop trong artifact đánh giá có {gt['challengeCount']} challenge thuộc 16 nhóm. Khi đánh giá theo ngữ cảnh, hệ thống có "
            "27/112 challenge có khớp exact từ scanner hoặc manual, và 62/112 challenge có bằng chứng exact, partial hoặc supporting ở runtime/manual. "
            f"Nếu coi exact+partial+supporting là phạm vi kiểm thử bảo mật có giá trị, Security Test Coverage đạt {pct(62, 112)}. "
            f"Nếu chỉ tính exact match, tỷ lệ là {pct(27, 112)}. Hai con số này phản ánh hai mức nhìn khác nhau: mức nghiêm ngặt và mức hỗ trợ kiểm thử.",
        ),
        table([
            ["Nhóm challenge", "Số lượng"],
            *[[item["category"], str(item["count"])] for item in gt["categories"]],
        ]),
        heading("3.7. Kết quả trên ví dụ SQL Injection tự xây dựng", 2),
        p(
            "Ứng dụng `examples/sqli` là target Flask/MySQL có chủ đích chứa SQL Injection. Collector nhận diện target backend ở thư mục `web`, framework "
            "Python Flask, Docker Compose gồm `db` và `web`, service `web` expose port 5000. Context thu được 16 endpoint, 2 endpoint high-risk và 6 pattern "
            "SQLi critical. File `examples/sqli/web/fix-sqli-app.py` thể hiện hướng khắc phục bằng parameterized query, tắt multi statements và không trả raw query "
            "lỗi chi tiết cho người dùng.",
        ),
        table([
            ["Chỉ số SQLi example", "Giá trị"],
            ["Tech stack", f"{sqli['techStack']['language']} / {sqli['techStack']['framework']}"],
            ["Endpoint", str(sqli["attackSurfaceSummary"]["totalEndpoints"])],
            ["High-risk endpoint", str(sqli["attackSurfaceSummary"]["highRiskEndpoints"])],
            ["Dangerous patterns", json.dumps(sqli["attackSurfaceSummary"]["dangerousPatterns"], ensure_ascii=False)],
            ["Containerized", str(sqli["attackSurfaceSummary"]["isContainerized"])],
        ]),
        heading("3.8. Nhận xét đánh giá", 2),
        bullet("Collector hoạt động tốt với Juice Shop khi phát hiện được 239 endpoint, 186 pattern nguy hiểm và 187 field nhạy cảm."),
        bullet("Scanner tự động, đặc biệt Semgrep và ZAP, phù hợp để phát hiện injection, file exposure, header/config hardening và một phần XSS/open redirect."),
        bullet("Checklist thủ công tạo thêm coverage cho IDOR/BFLA/mass assignment/race, nhưng chất lượng phụ thuộc vào evidence và cần người kiểm thử xác nhận."),
        bullet("Các finding nằm trong `data/static/codefixes/*` của Juice Shop nên được tách riêng với lỗ hổng runtime chính; artifact đánh giá đã có nhãn `codefixOnly`."),
        bullet("Ground truth `challenges.yml` là ground truth cấp challenge, không phải oracle đầy đủ cho mọi hardening issue; vì vậy `outOfYaml` không nên tự động coi là false positive."),
        heading("3.9. Giới hạn thực nghiệm", 2),
        table([
            ["Giới hạn", "Tác động", "Hướng xử lý"],
            ["DAST chưa đăng nhập tự động", "ZAP khó bao phủ endpoint yêu cầu session/role", "Bổ sung auth script, session injection hoặc ZAP context"],
            ["Manual tests chưa được replay tự động", "Nhiều candidate chưa thể gọi là confirmed", "Sinh request collection và chạy kiểm chứng có trạng thái trước/sau"],
            ["Trivy chỉ chạy fs", "Chưa đánh giá image/config/IaC đầy đủ", "Mở rộng adapter cho `trivy image` và `trivy config`"],
            ["AI sinh candidate rộng", "Có unsupported manual tests", "Bổ sung post-filter dựa trên route middleware/source evidence và ground truth nếu có"],
            ["Ground truth Juice Shop đặc thù CTF", "Một số kết quả supporting khó quy đổi thành precision truyền thống", "Tách exact, partial, supporting, codefix-only trong đánh giá"],
        ]),
        page_break(),
    ]

    # Conclusion, references, appendix
    parts += [
        heading("KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN", 1),
        p(
            "Đề tài đã xây dựng được một module DevSecOps hỗ trợ AI cho ứng dụng web trong pipeline CI/CD. Hệ thống có khả năng thu thập ngữ cảnh từ source code, "
            "nhận diện công nghệ và bề mặt tấn công, dùng AI để sinh cấu hình công cụ và checklist thủ công, chạy scanner qua adapter Docker, sau đó tổng hợp báo cáo "
            "HTML/JSON. Điểm quan trọng của giải pháp là không để AI thay thế scanner hoặc người kiểm thử, mà dùng AI như lớp hỗ trợ quyết định và diễn giải dựa trên "
            "ngữ cảnh đã được collector rút trích.",
        ),
        p(
            "Kết quả trên OWASP Juice Shop cho thấy hệ thống tạo được dữ liệu ngữ cảnh lớn và có giá trị: 239 endpoint, 159 endpoint high-risk, 186 pattern nguy hiểm, "
            "187 field nhạy cảm và báo cáo scanner/manual có thể đối chiếu với ground truth. Theo đánh giá ngữ cảnh, 62/112 challenge có bằng chứng exact, partial hoặc "
            "supporting. Kết quả này cho thấy hướng tiếp cận có giá trị trong việc tăng coverage kiểm thử và hỗ trợ ưu tiên xử lý, đồng thời cũng chỉ ra giới hạn rõ ràng "
            "ở xác thực tự động, kiểm chứng manual test và giảm unsupported candidate.",
        ),
        heading("Hướng phát triển", 2),
        bullet("Bổ sung kiểm thử DAST có xác thực: ZAP context, login script, token injection và kiểm thử theo role."),
        bullet("Tự động replay một phần manual tests bằng Postman/Newman hoặc Playwright API để chuyển candidate thành evidence xác nhận."),
        bullet("Mở rộng Trivy cho image/config/IaC và sinh SBOM CycloneDX/SPDX."),
        bullet("Thay route/pattern regex bằng parser/AST cho một số framework chính để giảm false signal."),
        bullet("Thêm cơ chế so sánh báo cáo giữa các build, theo dõi xu hướng risk score và regression security."),
        bullet("Cải thiện evaluation để phân biệt rõ confirmed vulnerability, hardening issue, challenge evidence và codefix-only finding."),
        page_break(),
        heading("TÀI LIỆU THAM KHẢO", 1),
        p("[1] IBM, What is DevOps, https://www.ibm.com/think/topics/devops"),
        p("[2] Dynatrace, What is DevSecOps, https://www.dynatrace.com/news/blog/what-is-devsecops/"),
        p("[3] Jenkins Documentation, https://www.jenkins.io/doc/"),
        p("[4] OWASP, OWASP Juice Shop, https://owasp.org/www-project-juice-shop/"),
        p("[5] OWASP, OWASP Benchmark, https://owasp.org/www-project-benchmark/"),
        p("[6] OWASP, crAPI, https://owasp.org/www-project-crapi/"),
        p("[7] Semgrep, https://github.com/semgrep/semgrep"),
        p("[8] Bandit, https://github.com/pycqa/bandit"),
        p("[9] PortSwigger Web Security Academy - Authentication, https://portswigger.net/web-security/authentication"),
        p("[10] PortSwigger Web Security Academy - Access Control, https://portswigger.net/web-security/access-control"),
        p("[11] PortSwigger Web Security Academy - JWT, https://portswigger.net/web-security/jwt"),
        p("[12] PortSwigger Web Security Academy - File Upload, https://portswigger.net/web-security/file-upload"),
        p("[13] OWASP Top 10 Injection, https://owasp.org/Top10/2025/A05_2025-Injection/"),
        p("[14] Splunk, Software Composition Analysis, https://www.splunk.com/en_us/blog/learn/software-composition-analysis-sca.html"),
        page_break(),
        heading("PHỤ LỤC A. CẤU TRÚC MÃ NGUỒN CHÍNH", 1),
        table([
            ["Nhóm", "File tiêu biểu", "Mục đích"],
            ["Collector", "contextCollector.js, techStack.js, routeScanner.js, codePattern.js, schemaScanner.js, apiSurface.js", "Sinh context.json"],
            ["AI", "geminiClient.js, aiAnalyzer.js, pipelineGenerator.js, reportGenerator.js", "Gọi Gemini, sinh cấu hình, script và báo cáo"],
            ["Runtime", "sanitize.js, servicePicker.js", "Kiểm soát input động và chọn service target"],
            ["Tool adapters", "semgrep.js, bandit.js, trivy.js, zap.js, nuclei.js, nikto.js", "Sinh command scanner"],
            ["Evaluation", "evaluateJuiceShop*.js, *.json, *.md", "Đối chiếu kết quả với ground truth Juice Shop"],
        ]),
        heading("PHỤ LỤC B. ARTIFACT ĐẦU RA", 1),
        table([
            ["File", "Mô tả"],
            ["context.json", "Ngữ cảnh dự án: tech stack, routes, patterns, schemas, API surface, git diff, container"],
            ["tool_config.json", "Cấu hình tool do AI sinh hoặc fallback profile"],
            ["manual_tests.json", "Checklist thủ công cho endpoint có tín hiệu rủi ro"],
            ["runtime-info.json", "Service/port/network target cho DAST và metadata runtime"],
            ["semgrep-report.json, bandit-report.json, trivy-report.json", "Output SAST/SCA nếu tool chạy"],
            ["zap-report.json, nuclei-report.jsonl, nikto-report.json", "Output DAST nếu target deploy được"],
            ["security-report.html", "Báo cáo HTML xem trong Jenkins"],
            ["security-report.json", "Báo cáo JSON phục vụ tích hợp/đánh giá"],
        ]),
        heading("PHỤ LỤC C. LỆNH CHẠY CỤC BỘ", 1),
        p("node collector/contextCollector.js <target-dir> --output ./security-context-output"),
        p("GEMINI_API_KEY=<key> node ai/aiAnalyzer.js ./security-context-output/context.json ./security-context-output"),
        p("node ai/pipelineGenerator.js ./security-context-output ./runtime <target-dir>"),
        p("./runtime/run-sast.sh"),
        p("./runtime/deploy-target.sh"),
        p("./runtime/run-dast.sh"),
        p("GEMINI_API_KEY=<key> node ai/reportGenerator.js ./security-context-output/scan-reports ./security-context-output/context.json ./security-context-output/final-report"),
        sect_pr,
    ]
    return "".join(parts)


def main():
    with zipfile.ZipFile(SOURCE_DOCX, "r") as zin:
        document_xml = zin.read("word/document.xml").decode("utf-8")
        image_paras = image_para_map(document_xml)
        prefix = document_xml.split("<w:body>")[0] + "<w:body>"
        sect_match = re.search(r"<w:sectPr[\s\S]*?</w:sectPr>", document_xml)
        sect_pr = sect_match.group(0) if sect_match else ""
        new_document = prefix + build_body(image_paras, sect_pr) + "</w:body></w:document>"

        with zipfile.ZipFile(OUTPUT_DOCX, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                info = copy(item)
                if item.filename == "word/document.xml":
                    data = new_document.encode("utf-8")
                zout.writestr(info, data)

    print(f"Wrote {OUTPUT_DOCX}")


if __name__ == "__main__":
    main()
