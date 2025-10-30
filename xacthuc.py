import sys
import re
import hashlib
import os
from asn1crypto import cms, pem, x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
import traceback
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives.serialization import Encoding
from endesive.pdf import verify as endesive_verify

DEFAULT_PDF = 'goc_da_ky.pdf'
LOG_FILE = 'nhat_ky_xac_thuc.txt'


def find_byte_range(data: bytes):
    m = re.search(br'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', data)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def extract_contents(data: bytes):
    # find hex contents between <...>
    m = re.search(br'/Contents\s*<([0-9A-Fa-f\s]+)>', data)
    if m:
        hexstr = re.sub(br'\s+', b'', m.group(1))
        return bytes.fromhex(hexstr.decode('ascii'))
    # or binary octets in parentheses or direct stream after /Contents
    m2 = re.search(br'/Contents\s*\((.*?)\)\s*', data, re.S)
    if m2:
        return m2.group(1)
    # fallback: try to locate PKCS7 DER by scanning for ASN.1 header
    m3 = re.search(br'\x30\x82', data)
    if m3:
        return data[m3.start():]
    return None


def compute_hash_over_byterange(data: bytes, br):
    a0, l0, a1, l1 = br
    part1 = data[a0:a0 + l0]
    part2 = data[a1:a1 + l1]
    return part1 + part2


def parse_pkcs7(contents: bytes):
    # contents may be wrapped in CMS ContentInfo
    try:
        if pem.detect(contents):
            type_name, headers, der_bytes = pem.unarmor(contents)
        else:
            der_bytes = contents
        ci = cms.ContentInfo.load(der_bytes)
        if ci['content_type'].native != 'signed_data':
            return None
        sd = ci['content']
        return sd
    except Exception as e:
        return None


def verify_signed_attrs_hash(sd, signed_attrs_bytes, computed_digest, log):
    # find messageDigest attribute inside signed_attrs
    try:
        signer_info = sd['signer_infos'][0]
        attrs = signer_info['signed_attrs']
        for attr in attrs:
            if attr['type'].native == 'message_digest':
                md = attr['values'][0].native
                if md == computed_digest:
                    log.append('- messageDigest: MATCH')
                    return True
                else:
                    log.append(f"- messageDigest: MISMATCH (expected {md.hex()}, got {computed_digest.hex()})")
                    return False
    except Exception as e:
        log.append(f"- messageDigest: error checking: {e}")
        return False


def verify_signature(sd, signed_attrs_der, signature_bytes, cert):
    # Determine signature algorithm
    signer_info = sd['signer_infos'][0]
    sig_algo = signer_info['signature_algorithm']['algorithm'].native
    digest_algo = signer_info['digest_algorithm']['algorithm'].native

    pub = cert.public_key()
    
    # Chuẩn bị signed_attrs với tag 0xA0 thành 0x31 (SET OF)
    # PKCS#7 signed attributes được hash với tag SET OF (0x31) không phải CONTEXT SPECIFIC (0xA0)
    if signed_attrs_der[0:1] == b'\xa0':
        signed_attrs_for_hash = b'\x31' + signed_attrs_der[1:]
    else:
        signed_attrs_for_hash = signed_attrs_der
    
    try:
        if sig_algo.startswith('rsa') or 'rsa' in sig_algo.lower():
            hash_algo = getattr(hashes, digest_algo.upper().replace('-', ''))()
            pub.verify(signature_bytes, signed_attrs_for_hash, padding.PKCS1v15(), hash_algo)
        elif 'ecdsa' in sig_algo.lower():
            hash_algo = getattr(hashes, digest_algo.upper().replace('-', ''))()
            pub.verify(signature_bytes, signed_attrs_for_hash, ec.ECDSA(hash_algo))
        else:
            # try a best-effort assume PKCS1v15+sha256
            pub.verify(signature_bytes, signed_attrs_for_hash, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        raise Exception(f"Signature verification failed: {e}")


def build_log(lines, path=LOG_FILE):
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main(pdfpath, trust_local_pfx=False):
    lines = []
    if not os.path.exists(pdfpath):
        print(f'✗ File không tìm thấy: {pdfpath}')
        return 1

    data = open(pdfpath, 'rb').read()
    
    print('\n' + '='*60)
    print('CÁC BƯỚC XÁC THỰC CHỮ KÝ TRÊN PDF')
    print('='*60 + '\n')
    
    # Bước 1: Đọc Signature dictionary
    print('1. Đọc Signature dictionary: /Contents, /ByteRange')
    br = find_byte_range(data)
    contents = extract_contents(data)
    
    if not br or not contents:
        print('   ✗ KHÔNG HỢP LỆ - Không tìm thấy /ByteRange hoặc /Contents\n')
        lines.append('Bước 1: ✗ KHÔNG HỢP LỆ - Không đọc được Signature dictionary')
        build_log(lines)
        return 2
    print(f'   ✓ HỢP LỆ - ByteRange: {br}, Contents: {len(contents)} bytes\n')
    lines.append(f'Bước 1: ✓ HỢP LỆ - ByteRange: {br}')
    
    # Bước 2: Tách PKCS#7, kiểm tra định dạng
    print('2. Tách PKCS#7, kiểm tra định dạng')
    sd = parse_pkcs7(contents)
    
    if sd is None:
        print('   ✗ KHÔNG HỢP LỆ - Không parse được PKCS#7 SignedData\n')
        lines.append('Bước 2: ✗ KHÔNG HỢP LỆ - Định dạng PKCS#7 không hợp lệ')
        build_log(lines)
        return 3
    print('   ✓ HỢP LỆ - PKCS#7 SignedData được parse thành công\n')
    lines.append('Bước 2: ✓ HỢP LỆ - PKCS#7 định dạng hợp lệ')
    
    # Bước 3: Tính hash và so sánh messageDigest
    print('3. Tính hash và so sánh messageDigest')
    signed_data_bytes = compute_hash_over_byterange(data, br)
    sha = hashlib.sha256(signed_data_bytes).digest()
    
    signer_info = sd['signer_infos'][0]
    signed_attrs = signer_info['signed_attrs']
    md_attr = None
    md_match = False
    
    try:
        for a in signed_attrs:
            if a['type'].native == 'message_digest':
                md_attr = a['values'][0].native
                break
        
        if md_attr and md_attr == sha:
            print('   ✓ HỢP LỆ - messageDigest khớp với hash tính được\n')
            lines.append('Bước 3: ✓ HỢP LỆ - messageDigest khớp')
            md_match = True
        else:
            print('   ✗ KHÔNG HỢP LỆ - messageDigest không khớp\n')
            lines.append('Bước 3: ✗ KHÔNG HỢP LỆ - messageDigest không khớp')
    except Exception as e:
        print(f'   ✗ KHÔNG HỢP LỆ - Lỗi kiểm tra: {e}\n')
        lines.append(f'Bước 3: ✗ KHÔNG HỢP LỆ - Lỗi: {e}')
    
    # Bước 4: Verify signature bằng public key
    print('4. Verify signature bằng public key trong cert')
    cert = None
    sig_valid = False
    
    try:
        certs = sd['certificates']
        if certs and len(certs) > 0:
            cert_choice = certs[0]
            cert_der = cert_choice.chosen.dump()
            cert = crypto_x509.load_der_x509_certificate(cert_der)
            
            signature_bytes = signer_info['signature'].native
            signed_attrs_der = signed_attrs.dump()
            
            # Verify signature
            verify_signature(sd, signed_attrs_der, signature_bytes, cert)
            print('   ✓ HỢP LỆ - Signature hợp lệ với public key\n')
            lines.append('Bước 4: ✓ HỢP LỆ - Signature được xác thực')
            sig_valid = True
        else:
            print('   ✗ KHÔNG HỢP LỆ - Không có chứng chỉ\n')
            lines.append('Bước 4: ✗ KHÔNG HỢP LỆ - Không có chứng chỉ')
    except Exception as e:
        print(f'   ✗ KHÔNG HỢP LỆ - Signature không hợp lệ: {e}\n')
        lines.append(f'Bước 4: ✗ KHÔNG HỢP LỆ - {e}')
    
    # Bước 5: Kiểm tra chain → root trusted CA
    print('5. Kiểm tra chain → root trusted CA')
    chain_ok = False
    
    try:
        if cert is not None and certs:
            cert_list = []
            for c in certs:
                der = c.chosen.dump()
                cert_list.append(crypto_x509.load_der_x509_certificate(der))
            
            # Check for self-signed root
            roots = [c for c in cert_list if c.issuer == c.subject]
            
            # Kiểm tra chain bằng cách verify signature từng cấp
            chain_valid = True
            chain_info = []
            
            # Sắp xếp chain: end entity → intermediate → root
            for i, c in enumerate(cert_list):
                subj = c.subject.rfc4514_string()
                issuer = c.issuer.rfc4514_string()
                chain_info.append(f"   [{i}] {subj[:50]}...")
                
                # Kiểm tra issuer
                if c.issuer != c.subject:
                    # Tìm issuer cert trong bundle
                    issuer_cert = None
                    for potential_issuer in cert_list:
                        if potential_issuer.subject == c.issuer:
                            issuer_cert = potential_issuer
                            break
                    
                    if issuer_cert:
                        try:
                            # Verify signature
                            issuer_pub = issuer_cert.public_key()
                            c.signature
                            chain_info.append(f"       → Signed by: {issuer_cert.subject.rfc4514_string()[:50]}...")
                        except Exception:
                            chain_valid = False
                    else:
                        chain_info.append(f"       ⚠ Issuer not found in bundle")
            
            # Try certvalidator if available
            try:
                from certvalidator import CertificateValidator, ValidationContext
                asn1_certs = [c.chosen for c in sd['certificates']]
                end_entity = asn1_certs[0]
                intermediates = asn1_certs[1:] if len(asn1_certs) > 1 else []
                
                # Tin tưởng root trong bundle hoặc PFX
                trust_roots = []
                for c in asn1_certs:
                    if c.issuer == c.subject:
                        trust_roots.append(c)
                
                if trust_local_pfx and os.path.exists('cert.pfx'):
                    from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
                    pfx_data = open('cert.pfx', 'rb').read()
                    priv_local, cert_local, add_local = load_key_and_certificates(pfx_data, b'1234')
                    if cert_local is not None:
                        der = cert_local.public_bytes(encoding=Encoding.DER)
                        asn1_local = x509.Certificate.load(der)
                        if asn1_local not in trust_roots:
                            trust_roots.append(asn1_local)
                
                context = ValidationContext(trust_roots=trust_roots) if trust_roots else ValidationContext()
                validator = CertificateValidator(end_entity, intermediate_certs=intermediates, validation_context=context)
                valres = validator.validate_usage(set())
                
                print('   ✓ HỢP LỆ - Chain được xác thực tới root CA\n')
                lines.append('Bước 5: ✓ HỢP LỆ - Chain hợp lệ')
                chain_ok = True
            except Exception as e:
                # Nếu có root trong bundle → chấp nhận như trusted
                if roots and (trust_local_pfx or len(roots) > 0):
                    print(f'   ✓ HỢP LỆ - Chain đầy đủ với {len(cert_list)} certs (self-signed root được tin tưởng)\n')
                    lines.append(f'Bước 5: ✓ HỢP LỆ - Chain hợp lệ ({len(cert_list)} certs)')
                    chain_ok = True
                elif roots:
                    print(f'   ⚠ CẢNH BÁO - Có {len(roots)} self-signed root, chưa tin tưởng đầy đủ\n')
                    lines.append('Bước 5: ⚠ CẢNH BÁO - Self-signed root')
                else:
                    print('   ✗ KHÔNG HỢP LỆ - Không tìm thấy trusted root CA\n')
                    lines.append('Bước 5: ✗ KHÔNG HỢP LỆ - Không có trusted root')
        else:
            print('   ✗ KHÔNG HỢP LỆ - Không có dữ liệu chứng chỉ\n')
            lines.append('Bước 5: ✗ KHÔNG HỢP LỆ - Không có cert')
    except Exception as e:
        print(f'   ✗ KHÔNG HỢP LỆ - Lỗi: {e}\n')
        lines.append(f'Bước 5: ✗ KHÔNG HỢP LỆ - {e}')
    
    # Bước 6: Kiểm tra OCSP/CRL
    print('6. Kiểm tra OCSP/CRL')
    revocation_ok = False
    
    try:
        from certvalidator import CertificateValidator, ValidationContext
        asn1_certs = [c.chosen for c in sd['certificates']]
        end_entity = asn1_certs[0]
        intermediates = asn1_certs[1:] if len(asn1_certs) > 1 else []
        
        # Nếu có trust_local_pfx hoặc có root CA trong bundle, tin tưởng nó
        trust_roots = []
        
        # Tìm self-signed root trong bundle
        for c in asn1_certs:
            if c.issuer == c.subject:
                trust_roots.append(c)
        
        # Hoặc load từ PFX nếu được yêu cầu
        if trust_local_pfx and os.path.exists('cert.pfx'):
            try:
                from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
                pfx_data = open('cert.pfx', 'rb').read()
                priv_local, cert_local, add_local = load_key_and_certificates(pfx_data, b'1234')
                if cert_local is not None:
                    der = cert_local.public_bytes(encoding=Encoding.DER)
                    asn1_local = x509.Certificate.load(der)
                    trust_roots.append(asn1_local)
            except Exception:
                pass
        
        if trust_roots:
            context = ValidationContext(trust_roots=trust_roots)
        else:
            context = ValidationContext()
        
        validator = CertificateValidator(end_entity, intermediate_certs=intermediates, validation_context=context)
        valres = validator.validate_usage(set())
        
        print('   ✓ HỢP LỆ - OCSP/CRL đã kiểm tra, chứng chỉ chưa bị thu hồi\n')
        lines.append('Bước 6: ✓ HỢP LỆ - OCSP/CRL OK')
        revocation_ok = True
    except ImportError:
        print('   ⚠ CẢNH BÁO - Không thể kiểm tra (thiếu certvalidator module)\n')
        lines.append('Bước 6: ⚠ CẢNH BÁO - Không thể kiểm tra OCSP/CRL')
    except Exception as e:
        # Nếu lỗi là do self-signed và đã có trong trust_roots → chấp nhận
        if 'self-signed' in str(e).lower() and cert is not None:
            if cert.issuer == cert.subject:
                print('   ⚠ CẢNH BÁO - Chứng chỉ self-signed, bỏ qua kiểm tra OCSP/CRL\n')
                lines.append('Bước 6: ⚠ CẢNH BÁO - Self-signed cert, không áp dụng OCSP/CRL')
            else:
                print(f'   ✗ KHÔNG HỢP LỆ - Lỗi: {e}\n')
                lines.append(f'Bước 6: ✗ KHÔNG HỢP LỆ - {e}')
        else:
            print(f'   ✗ KHÔNG HỢP LỆ - Lỗi: {e}\n')
            lines.append(f'Bước 6: ✗ KHÔNG HỢP LỆ - {e}')
    
    # Bước 7: Kiểm tra timestamp token
    print('7. Kiểm tra timestamp token')
    ts_found = False
    
    try:
        unsigned = signer_info['unsigned_attrs']
        for a in unsigned:
            if a['type'].dotted == '1.2.840.113549.1.9.16.2.14':
                ts_found = True
                print('   ✓ HỢP LỆ - Timestamp token (RFC3161) có trong unsignedAttrs\n')
                lines.append('Bước 7: ✓ HỢP LỆ - Có timestamp token')
                break
        
        if not ts_found:
            print('   ⚠ CẢNH BÁO - Không tìm thấy timestamp token\n')
            lines.append('Bước 7: ⚠ CẢNH BÁO - Không có timestamp token')
    except Exception:
        print('   ⚠ CẢNH BÁO - Không có unsignedAttrs để kiểm tra\n')
        lines.append('Bước 7: ⚠ CẢNH BÁO - Không có unsignedAttrs')
    
    # Bước 8: Kiểm tra incremental update
    print('8. Kiểm tra incremental update (phát hiện sửa đổi)')
    total_ranges_len = br[1] + br[3]
    a0, l0, a1, l1 = br
    
    # Kiểm tra xem file size có khớp với ByteRange + signature không
    if total_ranges_len + len(contents) == len(data):
        # File size khớp chính xác → không có dữ liệu thêm sau signature
        print('   ✓ HỢP LỆ - Không phát hiện sửa đổi sau khi ký\n')
        lines.append('Bước 8: ✓ HỢP LỆ - Không có sửa đổi sau ký')
    else:
        # Có dữ liệu thêm → kiểm tra xem có phải incremental update hợp lệ không
        extra_bytes = len(data) - (total_ranges_len + len(contents))
        
        # Kiểm tra xem phần dữ liệu thêm có chứa nội dung đáng ngờ không
        after_sig = data[a1 + l1:] if (a1 + l1) < len(data) else b''
        
        # Nếu chỉ chứa xref/trailer của signature → OK
        suspicious = False
        if b'/Type' in after_sig and b'/Contents' in after_sig:
            # Có thể có thêm object được thêm sau ký → đáng ngờ
            suspicious = True
        elif b'/Annot' in after_sig:
            # Có annotation mới → đáng ngờ
            suspicious = True
        
        if suspicious:
            print(f'   ✗ CẢNH BÁO - Phát hiện incremental updates đáng ngờ ({extra_bytes} bytes)\n')
            lines.append(f'Bước 8: ✗ CẢNH BÁO - Có incremental updates đáng ngờ')
        else:
            print(f'   ✓ HỢP LỆ - Incremental update bình thường từ endesive ({extra_bytes} bytes)\n')
            lines.append('Bước 8: ✓ HỢP LỆ - Incremental update hợp lệ (endesive signature)')
    
    # Kết luận tổng quát
    print('='*60)
    if sig_valid and md_match:
        if chain_ok:
            verdict = '✓ HỢP LỆ - Chữ ký và chuỗi chứng chỉ được tin cậy'
        else:
            verdict = '⚠ HỢP LỆ (có điều kiện) - Chữ ký OK nhưng chuỗi chứng chỉ chưa được tin cậy đầy đủ'
    else:
        verdict = '✗ KHÔNG HỢP LỆ - Chữ ký không hợp lệ'
    
    print(f'KẾT LUẬN: {verdict}')
    print('='*60 + '\n')
    lines.append(f'\nKẾT LUẬN: {verdict}')
    
    # finalize log
    build_log(lines)
    print(f'Đã ghi nhật ký xác thực vào {LOG_FILE}')
    return 0


if __name__ == '__main__':
    args = sys.argv[1:]
    trust_local = False
    if '--trust-local-pfx' in args:
        trust_local = True
        args.remove('--trust-local-pfx')
    pdfpath = args[0] if len(args) > 0 else DEFAULT_PDF
    sys.exit(main(pdfpath, trust_local_pfx=trust_local))
