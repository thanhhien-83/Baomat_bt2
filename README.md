# Baomat_bt2

 
# 1. Catalog (Root Object)  
Là điểm khởi đầu của toàn bộ cấu trúc PDF, định danh bằng /Type /Catalog.  
Giữ các tham chiếu (reference) đến:  
/Pages – cây trang của tài liệu.  
/AcroForm – chứa các trường biểu mẫu, bao gồm cả trường chữ ký.  
/DSS (nếu có) – nơi lưu chứng chỉ, OCSP, CRL để xác thực dài hạn (PAdES).  
Khi trình xem PDF cần tìm chữ ký, nó bắt đầu từ Catalog → /AcroForm.  
# 2. Pages tree  
Pages tree (/Type /Pages) quản lý danh sách các trang, cho phép trình đọc PDF xác định trang chứa chữ ký hiển thị.  
# 3. Page object  
Chứa nội dung, annotation (bao gồm widget của chữ ký).  
/Contents: nội dung trang (văn bản, hình ảnh…)  
/Annots: danh sách annotation trên trang, trong đó có widget annotation của chữ ký.  
Khi hiển thị chữ ký, PDF Reader lấy từ /Annots → SigField (Widget).  
# 4. Resources  
Resources: chứa các định nghĩa font, hình ảnh, và đối tượng đồ họa (XObject) được sử dụng trên trang.  
# 5. Content stream:   
Dòng lệnh mô tả nội dung hiển thị trên trang. Nơi lưu các lệnh vẽ, chữ, hoặc hình ảnh, định nghĩa bố cục trang.  
Dù không trực tiếp liên quan đến dữ liệu chữ ký, chúng giúp hiển thị khung chữ ký hoặc chèn ảnh “chữ ký tay” (nếu có XObject hình ảnh).  
# 6. XObject (External Object)  
Là một đối tượng đồ họa hoặc hình ảnh có thể được chèn nhiều lần vào các trang.  
Khi người ký chọn “hiển thị ảnh chữ ký”, PDF sẽ lưu ảnh đó như một Image XObject.  
Khi hiển thị chữ ký, viewer đọc SigField → appearance stream → XObject.  
# 7. AcroForm  
Là biểu mẫu (form) tổng hợp các trường tương tác của tài liệu PDF, gồm textbox, checkbox, và signature field.  
Định danh: /Type /AcroForm.  
Chứa mảng /Fields → danh sách các trường, mỗi trường là một annotation object (widget).  
Khi ký, phần mềm thêm vào /AcroForm một SigField mới (nếu chưa có).  
# 8. Signature Field (Widget Annotation)  
Là field tương tác đại diện cho vùng hiển thị chữ ký trên trang.  
Có /Subtype /Widget, /FT /Sig, và /V trỏ tới Signature Dictionary chứa dữ liệu chữ ký thực.  
Khi ký xong, /V được gán vào đây.   
# 9. Signature Dictionary (/Sig)  
Nơi lưu dữ liệu chữ ký thực tế (PKCS#7, hash, thời gian, tên người ký...). Đây là nơi quan trọng nhất để lưu và truy xuất.  
# 10. ByteRange  
Chỉ định vùng dữ liệu được băm và ký, loại trừ vùng /Contents.  
Mảng 4 số xác định phần dữ liệu được ký trong file:  
[start1, length1, start2, length2]  
Các vùng này bao quanh phần /Contents, nghĩa là hash toàn bộ PDF trừ dữ liệu chữ ký.  
Trình xác minh sẽ:  
Đọc file gốc theo ByteRange.  
Tính hash (SHA256/512).  
So sánh với giá trị trong PKCS#7.  
# 11. Contents  
Chứa blob chữ ký PKCS#7/CMS (ở dạng hex hoặc binary DER).  
Bên trong gồm:  
MessageDigest (hash vùng ByteRange)  
Certificate chain  
SigningTime (và có thể có timestamp RFC3161)  
Khi trình đọc PDF xác minh, nó trích phần này ra, giải mã PKCS#7 và so sánh hash.  
# 12. Incremental Updates  
PDF khi được ký không bị ghi đè. Thay vào đó, phần mới (chữ ký, annotation, cross-reference, trailer) được ghi thêm cuối file.  
Điều này giúp:  
Giữ nguyên toàn bộ dữ liệu trước khi ký.  
Dễ dàng phát hiện mọi thay đổi sau chữ ký (vì ByteRange chỉ bao phủ phần cũ).  
Khi có nhiều chữ ký, mỗi chữ ký là một incremental update mới.  
# 13. DSS (Document Security Store)  
Chỉ xuất hiện trong PAdES-LTV.  
Dùng để lưu trữ:  
/Certs – chứng chỉ (CA, intermediate, signer)  
/OCSPs, /CRLs – kết quả xác minh online  
/VRI – thông tin xác minh theo từng chữ ký  
Giúp người nhận xác thực chữ ký lâu dài (LTV) mà không cần mạng Internet.  
2. Thời gian ký được lưu ở đâu?  
Trong file PDF có chữ ký số, thông tin thời gian ký có thể được lưu ở nhiều vị trí khác nhau, tùy mức độ tin cậy và chuẩn sử dụng.  
- /M trong Signature Dictionary  
Nằm trong object chữ ký /Sig.  
Dạng text: (D:YYYYMMDDHHmmSS+TZ) → ví dụ: (D:20251024T114053+07'00').  
Do phần mềm ký tự ghi vào.  
Không có giá trị pháp lý, vì không được ký bảo vệ, có thể bị chỉnh sửa.  
- signingTime trong PKCS#7 (signedAttributes)  
Bên trong dữ liệu /Contents (PKCS#7).  
Được bảo vệ bởi chữ ký → không sửa được nếu không phá chữ ký.  
Do người ký cung cấp, độ tin cậy trung bình.  
- Timestamp token (RFC 3161)  
Là token do máy chủ TSA cấp, lưu trong PKCS#7 (attribute timeStampToken).  
Chứa genTime – thời gian được TSA xác nhận và ký.  
Có giá trị pháp lý cao vì là bằng chứng thời gian độc lập, không phụ thuộc người ký.  
- Document Timestamp (PAdES)  
Là chữ ký đặc biệt /Type /DocTimeStamp.  
Dùng để đóng dấu thời gian cho toàn bộ tài liệu.  
Thường xuất hiện trong các PDF chuẩn PAdES-B-T hoặc PAdES-LTV.  
Được TSA ký, nên có giá trị pháp lý cao.  
- DSS (Document Security Store)  
Lưu trữ các dữ liệu xác minh như:  
/Certs (chứng chỉ)  
/OCSPs, /CRLs (kiểm tra trạng thái),  
Timestamp tokens (nếu có).  
Dùng để xác minh lâu dài (LTV) khi không còn kết nối mạng.  




































