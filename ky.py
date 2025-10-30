import io
import datetime
import os
from PyPDF2 import PdfReader, PdfWriter
from endesive import pdf
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Cấu hình
THU_MUC = os.getcwd()
# Ký file phiếu nhận hàng do taoPdf.py tạo
TEN_PDF_GOC = os.path.join(THU_MUC, 'goc.pdf')
TEN_PFX = os.path.join(THU_MUC, 'cert.pfx')
MAT_KHAU_PFX = b'1234'

# Đọc file gốc
with open(TEN_PDF_GOC, 'rb') as f:
    orig_pdf_bytes = f.read()

reader = PdfReader(io.BytesIO(orig_pdf_bytes))
print("Số trang PDF gốc:", len(reader.pages))

# Thông tin hiển thị chữ ký
dct = {
    'sigflags': 3,
    'sigflagsft': 132,
    'page': 5,  # page 6 (0-based index)
    'location': 'Thái Nguyên, Vietnam',
    'contact': '0981597907',
    'signingdate': datetime.datetime.now().strftime("D:%Y%m%d%H%M%S+07'00'"),
    'reason': 'Nộp bài tập',
    'name': 'Hứa Thị Thanh Hiền',
}

# Load PFX
p12_data = open(TEN_PFX, 'rb').read()
privkey_obj, cert_obj, add_cert_objs = load_key_and_certificates(p12_data, MAT_KHAU_PFX)
if privkey_obj is None or cert_obj is None:
    raise SystemExit("Không load được private key hoặc certificate từ cert.pfx. Kiểm tra mật khẩu.")

othercerts = add_cert_objs if add_cert_objs else []

# Tạo overlay (ảnh chữ ký + thời gian ở trên + tên dưới) và ghép lên trang gốc trước khi ký
page_width, page_height = A4
img_path = os.path.join(THU_MUC, 'ky.png')
sign_name_display = dct.get('name')

# Try to register Times New Roman (Windows). Nếu không tìm thấy, dùng Times-Roman
font_name = 'TimesNewRoman'
font_registered = False
win_fonts = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Fonts')
candidates = [
    os.path.join(win_fonts, 'times.ttf'),
    os.path.join(win_fonts, 'Times New Roman.ttf'),
    os.path.join(win_fonts, 'times new roman.ttf'),
    os.path.join(win_fonts, 'timesbd.ttf'),
    os.path.join(win_fonts, 'Times.ttf'),
]
for p in candidates:
    if os.path.exists(p):
        try:
            pdfmetrics.registerFont(TTFont(font_name, p))
            font_registered = True
            break
        except Exception:
            font_registered = False
if not font_registered:
    font_name = 'Times-Roman'

# Vị trí: đặt chữ ký ở góc phải dưới của trang (page 6), ngay bên dưới
# nhãn "Sinh viên ký" trong goc.pdf. Điều này đặt overlay vào trang chỉ
# hiển thị (không phải annotation), chính xác ở góc phải dưới.
# Khoảng cách từ mép phải/bottom có thể điều chỉnh nếu cần.
img_w = 50 * mm
img_h = 12 * mm
margin_right = 20 * mm
# Đặt ảnh sao cho mép phải ảnh cách mép phải trang margin_right
img_x = page_width - margin_right - img_w
# Đặt ảnh ở gần đáy trang; khoảng cách này nên nằm ngay dưới nhãn "Sinh viên ký".
# Nếu cần tinh chỉnh, thay đổi giá trị của img_y.
img_y = page_height - 245 * mm

# Prepare overlay canvas
from reportlab.lib.utils import ImageReader
overlay_buf = io.BytesIO()
oc = canvas.Canvas(overlay_buf, pagesize=A4)

# Thêm số điện thoại và ngày ký ngay dưới dòng "Sinh viên ký"
sign_date_display = datetime.datetime.now().strftime('%d/%m/%Y')
sign_phone_display = '0981597907'
oc.setFont(font_name, 10)
# Vẽ số điện thoại và ngày ký ở vị trí phù hợp (ngay dưới "Sinh viên ký", trên chữ ký)
oc.drawString(img_x, img_y + 26 * mm, f'SĐT: {sign_phone_display}')
oc.drawString(img_x, img_y + 22 * mm, f'Ngày ký: {sign_date_display}')

# Vẽ ảnh chữ ký, giữ transparency nếu có
if os.path.exists(img_path):
    try:
        img_reader = ImageReader(img_path)
        oc.drawImage(img_reader, img_x, img_y, width=img_w, height=img_h, mask='auto')
    except Exception as e:
        print("Không thể chèn ảnh chữ ký bằng ImageReader:", e)
else:
    print("Ảnh chữ ký không tìm thấy:", img_path)
# Xóa chữ "Hien" và thay bằng ảnh chữ ký (đã vẽ ở trên);
# hiển thị họ tên đầy đủ ngay phía trên đường kẻ, dưới ảnh chữ ký.
text_center_x = img_x + img_w / 2
oc.setFont(font_name, 10)
# Hiển thị họ tên ngay dưới ảnh chữ ký (dưới chỗ ký), căn giữa theo ảnh
oc.drawCentredString(text_center_x, img_y - (4 * mm), sign_name_display)
oc.save()
overlay_buf.seek(0)

# Ghép overlay lên trang đầu
overlay_pdf = PdfReader(overlay_buf)
writer = PdfWriter()
for i, page in enumerate(reader.pages):
    if i == dct.get('page', 0):
        page.merge_page(overlay_pdf.pages[0])
    writer.add_page(page)

new_pdf_buf = io.BytesIO()
writer.write(new_pdf_buf)
new_pdf_bytes = new_pdf_buf.getvalue()

# Dùng PDF đã ghép overlay làm dữ liệu để ký
datau = new_pdf_bytes

# Chuẩn bị thông tin ký (ẩn annotation, vì phần hiển thị đã được ghép vào nội dung)
page_count = len(reader.pages)
requested_page = dct.get('page', 0)
sigpage = requested_page if 0 <= requested_page < page_count else max(0, page_count - 1)

udct = {
    'sigpage': sigpage,
    'signaturebox': None,  # invisible signature annotation
    'contact': dct.get('contact'),
    'location': dct.get('location'),
    'signingdate': dct.get('signingdate'),
    'reason': dct.get('reason'),
    'sigflags': dct.get('sigflags', 3),
    'sigflagsft': dct.get('sigflagsft', 132),
    'name': dct.get('name'),
}

# Ký bằng endesive với timestamp
# Thử nhiều TSA server khác nhau
tsa_servers = [
    'http://timestamp.digicert.com',
    'http://timestamp.globalsign.com/tsa/r6advanced1',
    'http://tsa.starfieldtech.com',
    'http://timestamp.sectigo.com',
    'http://timestamp.apple.com/ts01'
]

signed_pdf_append = None
for tsa_url in tsa_servers:
    try:
        print(f"Đang thử TSA: {tsa_url}...")
        signed_pdf_append = pdf.cms.sign(
            datau, 
            udct, 
            privkey_obj, 
            cert_obj, 
            othercerts, 
            algomd='sha256',
            timestampurl=tsa_url
        )
        print(f"✓ Đã thêm timestamp từ {tsa_url}")
        break
    except Exception as e:
        print(f"✗ Lỗi với {tsa_url}: {e}")
        continue

if signed_pdf_append is None:
    print("\n⚠ Không thể kết nối TSA server nào. Ký không có timestamp...")
    signed_pdf_append = pdf.cms.sign(datau, udct, privkey_obj, cert_obj, othercerts, algomd='sha256')

TEN_DAU_RA = os.path.join(THU_MUC, 'goc_da_ky.pdf')
# Ghi file một lần để tránh incremental updates
final_pdf = datau + signed_pdf_append
with open(TEN_DAU_RA, 'wb') as f:
    f.write(final_pdf)

print("Đã ký thành công! File:", TEN_DAU_RA)

try:
    test_reader = PdfReader(open(TEN_DAU_RA, 'rb'))
    print("PDF hợp lệ! Số trang:", len(test_reader.pages))
    
    # Hiển thị thông tin về chữ ký
    if '/AcroForm' in test_reader.trailer['/Root']:
        acroform = test_reader.trailer['/Root']['/AcroForm']
        if '/Fields' in acroform:
            print("Số trường chữ ký:", len(acroform['/Fields']))
except Exception as e:
    print("PDF không hợp lệ:", e)
