"""
PurgeProof Certificate Generation System
NIST SP 800-88 Rev.1 Compliant Documentation and Verification

This module generates machine-verifiable JSON certificates and human-readable
PDF certificates with digital signatures for data sanitization compliance.
"""

import json
import hashlib
import base64
import qrcode
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from dataclasses import dataclass, asdict
from io import BytesIO

# Cryptographic libraries
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature

# PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


@dataclass
class DeviceInfo:
    """Device information for certificate"""
    path: str
    serial_number: str
    model: str
    manufacturer: str
    size_bytes: int
    interface_type: str  # SATA, NVMe, USB, etc.
    device_type: str     # SSD, HDD, USB, etc.
    firmware_version: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SanitizationMethod:
    """Sanitization method information"""
    method_name: str
    nist_category: str  # Clear, Purge, Destroy
    passes: int
    patterns: List[str]
    verification_method: str
    compliance_level: str  # Confidential, Secret, Top Secret
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    """Verification results"""
    method: str
    verified: bool
    sample_rate: float
    confidence_level: float
    entropy_score: float
    verification_hash: str
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WipeCertificate:
    """Complete wipe certificate data structure"""
    # Certificate metadata
    certificate_id: str
    version: str
    issued_date: str
    operator_id: str
    organization: str
    
    # Device information
    device: DeviceInfo
    
    # Sanitization details
    sanitization_method: SanitizationMethod
    start_timestamp: str
    end_timestamp: str
    duration_seconds: float
    
    # Verification results
    verification: VerificationResult
    
    # Compliance information
    nist_compliance: str
    security_classification: str
    
    # Digital signature
    signature: Optional[str] = None
    signature_algorithm: str = "RSA-PSS-SHA256"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'certificate_metadata': {
                'certificate_id': self.certificate_id,
                'version': self.version,
                'issued_date': self.issued_date,
                'operator_id': self.operator_id,
                'organization': self.organization
            },
            'device_information': self.device.to_dict(),
            'sanitization_details': {
                'method': self.sanitization_method.to_dict(),
                'start_timestamp': self.start_timestamp,
                'end_timestamp': self.end_timestamp,
                'duration_seconds': self.duration_seconds
            },
            'verification_results': self.verification.to_dict(),
            'compliance_information': {
                'nist_compliance': self.nist_compliance,
                'security_classification': self.security_classification
            },
            'digital_signature': {
                'signature': self.signature,
                'algorithm': self.signature_algorithm
            }
        }


class CertificateSigner:
    """Digital certificate signing and verification"""
    
    def __init__(self, private_key_path: Optional[str] = None, public_key_path: Optional[str] = None):
        self.private_key = None
        self.public_key = None
        
        if private_key_path and Path(private_key_path).exists():
            self.load_private_key(private_key_path)
        
        if public_key_path and Path(public_key_path).exists():
            self.load_public_key(public_key_path)
    
    def generate_key_pair(self, key_size: int = 2048) -> tuple:
        """Generate RSA key pair for certificate signing"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        
        self.private_key = private_key
        self.public_key = public_key
        
        return private_key, public_key
    
    def save_keys(self, private_key_path: str, public_key_path: str, password: Optional[bytes] = None):
        """Save key pair to files"""
        if not self.private_key:
            raise ValueError("No private key to save")
        
        # Save private key
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
    
    def load_private_key(self, key_path: str, password: Optional[bytes] = None):
        """Load private key from file"""
        with open(key_path, 'rb') as f:
            self.private_key = load_pem_private_key(f.read(), password=password)
        self.public_key = self.private_key.public_key()
    
    def load_public_key(self, key_path: str):
        """Load public key from file"""
        with open(key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())
    
    def sign_certificate(self, certificate: WipeCertificate) -> str:
        """Sign certificate with private key"""
        if not self.private_key:
            raise ValueError("No private key available for signing")
        
        # Create canonical representation for signing
        cert_dict = certificate.to_dict()
        cert_dict['digital_signature']['signature'] = None  # Remove signature for signing
        
        # Convert to canonical JSON
        canonical_json = json.dumps(cert_dict, sort_keys=True, separators=(',', ':'))
        message = canonical_json.encode('utf-8')
        
        # Sign with RSA-PSS
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encode signature as base64
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        certificate.signature = signature_b64
        
        return signature_b64
    
    def verify_certificate(self, certificate: WipeCertificate) -> bool:
        """Verify certificate signature"""
        if not self.public_key:
            raise ValueError("No public key available for verification")
        
        if not certificate.signature:
            raise ValueError("Certificate has no signature to verify")
        
        # Recreate canonical representation
        cert_dict = certificate.to_dict()
        original_signature = cert_dict['digital_signature']['signature']
        cert_dict['digital_signature']['signature'] = None
        
        canonical_json = json.dumps(cert_dict, sort_keys=True, separators=(',', ':'))
        message = canonical_json.encode('utf-8')
        
        # Decode signature
        try:
            signature = base64.b64decode(original_signature)
        except Exception:
            return False
        
        # Verify signature
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


class CertificateManager:
    """Main certificate management class"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.signer = CertificateSigner()
        
        # Load signing keys if configured
        if 'private_key_path' in self.config:
            try:
                self.signer.load_private_key(self.config['private_key_path'])
            except Exception as e:
                print(f"Warning: Could not load private key: {e}")
    
    def create_certificate(
        self,
        device_info: DeviceInfo,
        sanitization_method: SanitizationMethod,
        verification_result: VerificationResult,
        operator_id: str = "unknown",
        organization: str = "PurgeProof User",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> WipeCertificate:
        """Create a new wipe certificate"""
        
        if not start_time:
            start_time = datetime.now(timezone.utc)
        if not end_time:
            end_time = datetime.now(timezone.utc)
        
        duration = (end_time - start_time).total_seconds()
        
        # Generate unique certificate ID
        cert_id = self._generate_certificate_id(device_info, start_time)
        
        certificate = WipeCertificate(
            certificate_id=cert_id,
            version="1.0",
            issued_date=datetime.now(timezone.utc).isoformat(),
            operator_id=operator_id,
            organization=organization,
            device=device_info,
            sanitization_method=sanitization_method,
            start_timestamp=start_time.isoformat(),
            end_timestamp=end_time.isoformat(),
            duration_seconds=duration,
            verification=verification_result,
            nist_compliance=self._determine_nist_compliance(sanitization_method),
            security_classification=sanitization_method.compliance_level
        )
        
        # Sign certificate if signer available
        if self.signer.private_key:
            self.signer.sign_certificate(certificate)
        
        return certificate
    
    def _generate_certificate_id(self, device_info: DeviceInfo, timestamp: datetime) -> str:
        """Generate unique certificate ID"""
        data = f"{device_info.serial_number}:{device_info.path}:{timestamp.isoformat()}"
        hash_digest = hashlib.sha256(data.encode()).hexdigest()
        return f"PURGE-{hash_digest[:16].upper()}"
    
    def _determine_nist_compliance(self, method: SanitizationMethod) -> str:
        """Determine NIST compliance level"""
        if method.nist_category == "Destroy":
            return "NIST SP 800-88 Rev.1 - DESTROY"
        elif method.nist_category == "Purge":
            return "NIST SP 800-88 Rev.1 - PURGE"
        elif method.nist_category == "Clear":
            return "NIST SP 800-88 Rev.1 - CLEAR"
        else:
            return "NIST SP 800-88 Rev.1 - CUSTOM"
    
    def save_json_certificate(self, certificate: WipeCertificate, file_path: str):
        """Save certificate as JSON file"""
        cert_dict = certificate.to_dict()
        
        with open(file_path, 'w') as f:
            json.dump(cert_dict, f, indent=2)
    
    def load_json_certificate(self, file_path: str) -> WipeCertificate:
        """Load certificate from JSON file"""
        with open(file_path, 'r') as f:
            cert_dict = json.load(f)
        
        # Reconstruct certificate object
        return self._dict_to_certificate(cert_dict)
    
    def _dict_to_certificate(self, cert_dict: Dict[str, Any]) -> WipeCertificate:
        """Convert dictionary back to WipeCertificate object"""
        metadata = cert_dict['certificate_metadata']
        device_data = cert_dict['device_information']
        sanitization_data = cert_dict['sanitization_details']
        verification_data = cert_dict['verification_results']
        compliance_data = cert_dict['compliance_information']
        signature_data = cert_dict['digital_signature']
        
        device = DeviceInfo(**device_data)
        method = SanitizationMethod(**sanitization_data['method'])
        verification = VerificationResult(**verification_data)
        
        return WipeCertificate(
            certificate_id=metadata['certificate_id'],
            version=metadata['version'],
            issued_date=metadata['issued_date'],
            operator_id=metadata['operator_id'],
            organization=metadata['organization'],
            device=device,
            sanitization_method=method,
            start_timestamp=sanitization_data['start_timestamp'],
            end_timestamp=sanitization_data['end_timestamp'],
            duration_seconds=sanitization_data['duration_seconds'],
            verification=verification,
            nist_compliance=compliance_data['nist_compliance'],
            security_classification=compliance_data['security_classification'],
            signature=signature_data['signature'],
            signature_algorithm=signature_data['algorithm']
        )
    
    def verify_json_certificate(self, file_path: str) -> Dict[str, Any]:
        """Verify JSON certificate signature and integrity"""
        try:
            certificate = self.load_json_certificate(file_path)
            
            result = {
                'valid': False,
                'certificate_id': certificate.certificate_id,
                'errors': []
            }
            
            # Check if certificate has signature
            if not certificate.signature:
                result['errors'].append("Certificate has no digital signature")
                return result
            
            # Verify signature if public key available
            if self.signer.public_key:
                try:
                    if self.signer.verify_certificate(certificate):
                        result['valid'] = True
                    else:
                        result['errors'].append("Digital signature verification failed")
                except Exception as e:
                    result['errors'].append(f"Signature verification error: {e}")
            else:
                result['errors'].append("No public key available for verification")
            
            return result
            
        except Exception as e:
            return {
                'valid': False,
                'certificate_id': 'unknown',
                'errors': [f"Certificate loading error: {e}"]
            }
    
    def generate_pdf_certificate(self, certificate: WipeCertificate, file_path: str):
        """Generate human-readable PDF certificate"""
        if not PDF_AVAILABLE:
            raise ImportError("reportlab library required for PDF generation")
        
        doc = SimpleDocTemplate(file_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        story.append(Paragraph("DATA SANITIZATION CERTIFICATE", title_style))
        story.append(Paragraph("NIST SP 800-88 Rev.1 Compliant", 
                              ParagraphStyle('Subtitle', parent=styles['Normal'], 
                                           alignment=TA_CENTER, fontSize=12)))
        story.append(Spacer(1, 20))
        
        # Certificate information table
        cert_data = [
            ['Certificate ID:', certificate.certificate_id],
            ['Issue Date:', certificate.issued_date],
            ['Operator:', certificate.operator_id],
            ['Organization:', certificate.organization],
            ['NIST Compliance:', certificate.nist_compliance],
            ['Security Classification:', certificate.security_classification]
        ]
        
        cert_table = Table(cert_data, colWidths=[2*inch, 4*inch])
        cert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(cert_table)
        story.append(Spacer(1, 20))
        
        # Device information
        story.append(Paragraph("DEVICE INFORMATION", styles['Heading2']))
        
        device_data = [
            ['Device Path:', certificate.device.path],
            ['Serial Number:', certificate.device.serial_number],
            ['Model:', certificate.device.model],
            ['Manufacturer:', certificate.device.manufacturer],
            ['Size:', f"{certificate.device.size_bytes:,} bytes"],
            ['Interface:', certificate.device.interface_type],
            ['Type:', certificate.device.device_type]
        ]
        
        device_table = Table(device_data, colWidths=[2*inch, 4*inch])
        device_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(device_table)
        story.append(Spacer(1, 20))
        
        # Sanitization details
        story.append(Paragraph("SANITIZATION DETAILS", styles['Heading2']))
        
        sanitization_data = [
            ['Method:', certificate.sanitization_method.method_name],
            ['NIST Category:', certificate.sanitization_method.nist_category],
            ['Passes:', str(certificate.sanitization_method.passes)],
            ['Verification Method:', certificate.sanitization_method.verification_method],
            ['Start Time:', certificate.start_timestamp],
            ['End Time:', certificate.end_timestamp],
            ['Duration:', f"{certificate.duration_seconds:.2f} seconds"]
        ]
        
        sanitization_table = Table(sanitization_data, colWidths=[2*inch, 4*inch])
        sanitization_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(sanitization_table)
        story.append(Spacer(1, 20))
        
        # Verification results
        story.append(Paragraph("VERIFICATION RESULTS", styles['Heading2']))
        
        verification_data = [
            ['Verification Status:', "VERIFIED" if certificate.verification.verified else "FAILED"],
            ['Method:', certificate.verification.method],
            ['Sample Rate:', f"{certificate.verification.sample_rate:.1%}"],
            ['Confidence Level:', f"{certificate.verification.confidence_level:.1%}"],
            ['Entropy Score:', f"{certificate.verification.entropy_score:.3f}"],
            ['Verification Hash:', certificate.verification.verification_hash[:32] + "..."]
        ]
        
        verification_table = Table(verification_data, colWidths=[2*inch, 4*inch])
        verification_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(verification_table)
        story.append(Spacer(1, 20))
        
        # QR Code with certificate ID
        qr_img = self._generate_qr_code(certificate.certificate_id)
        story.append(Paragraph("CERTIFICATE QR CODE", styles['Heading2']))
        story.append(qr_img)
        
        # Digital signature info
        if certificate.signature:
            story.append(Spacer(1, 20))
            story.append(Paragraph("DIGITAL SIGNATURE", styles['Heading2']))
            story.append(Paragraph(f"Algorithm: {certificate.signature_algorithm}", styles['Normal']))
            story.append(Paragraph(f"Signature: {certificate.signature[:64]}...", styles['Normal']))
        
        # Build PDF
        doc.build(story)
    
    def _generate_qr_code(self, data: str) -> Image:
        """Generate QR code for certificate"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to reportlab Image
        buffer = BytesIO()
        qr_img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return Image(buffer, width=2*inch, height=2*inch)


# Factory functions for common certificate types
def create_crypto_erase_certificate(
    device_path: str,
    device_serial: str,
    device_model: str,
    verification_hash: str,
    operator_id: str = "system",
    organization: str = "PurgeProof"
) -> WipeCertificate:
    """Factory function for crypto erase certificates"""
    
    device = DeviceInfo(
        path=device_path,
        serial_number=device_serial,
        model=device_model,
        manufacturer="Unknown",
        size_bytes=0,
        interface_type="Unknown",
        device_type="Unknown"
    )
    
    method = SanitizationMethod(
        method_name="Cryptographic Erase",
        nist_category="Purge",
        passes=1,
        patterns=["AES-256 Key Destruction"],
        verification_method="Key Verification",
        compliance_level="Secret"
    )
    
    verification = VerificationResult(
        method="crypto_key_verification",
        verified=True,
        sample_rate=1.0,
        confidence_level=0.99,
        entropy_score=0.0,
        verification_hash=verification_hash
    )
    
    manager = CertificateManager()
    return manager.create_certificate(device, method, verification, operator_id, organization)


def create_overwrite_certificate(
    device_path: str,
    device_serial: str,
    device_model: str,
    passes: int,
    patterns: List[str],
    verification_result: bool,
    verification_hash: str,
    operator_id: str = "system",
    organization: str = "PurgeProof"
) -> WipeCertificate:
    """Factory function for overwrite certificates"""
    
    device = DeviceInfo(
        path=device_path,
        serial_number=device_serial,
        model=device_model,
        manufacturer="Unknown",
        size_bytes=0,
        interface_type="Unknown",
        device_type="Unknown"
    )
    
    method = SanitizationMethod(
        method_name=f"{passes}-Pass Overwrite",
        nist_category="Clear" if passes < 3 else "Purge",
        passes=passes,
        patterns=patterns,
        verification_method="Pattern Verification",
        compliance_level="Confidential" if passes < 3 else "Secret"
    )
    
    verification = VerificationResult(
        method="pattern_verification",
        verified=verification_result,
        sample_rate=0.1,
        confidence_level=0.95,
        entropy_score=0.1,
        verification_hash=verification_hash
    )
    
    manager = CertificateManager()
    return manager.create_certificate(device, method, verification, operator_id, organization)