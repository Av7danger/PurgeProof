"""
Digital Certificate Generation for PurgeProof Compliance Reports.

This module provides RSA/ECDSA digital certificate generation and verification 
for compliance reports as claimed in the README, enabling enterprise-grade 
audit trails with cryptographic proof.
"""

import json
import hashlib
import base64
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class CertificateType:
    """Certificate types for different purposes."""
    COMPLIANCE_REPORT = "compliance_report"
    AUDIT_TRAIL = "audit_trail" 
    SANITIZATION_PROOF = "sanitization_proof"
    VERIFICATION_CERTIFICATE = "verification_certificate"

class SignatureAlgorithm:
    """Supported signature algorithms."""
    RSA_PSS_SHA256 = "RSA-PSS-SHA256"
    RSA_PKCS1_SHA256 = "RSA-PKCS1-SHA256"
    ECDSA_SHA256 = "ECDSA-SHA256"
    ECDSA_SHA384 = "ECDSA-SHA384"

@dataclass
class CertificateSubject:
    """Certificate subject information."""
    organization: str = "PurgeProof Enterprise"
    organizational_unit: str = "Data Sanitization"
    common_name: str = "PurgeProof Compliance Certificate"
    country: str = "US"
    state: str = "CA"
    locality: str = "San Francisco"
    email: Optional[str] = None

@dataclass
class DigitalSignature:
    """Digital signature with metadata."""
    signature_data: str  # Base64 encoded signature
    algorithm: str
    public_key_fingerprint: str
    timestamp: str
    signer_info: Dict[str, Any]
    verification_info: Dict[str, Any]

@dataclass
class ComplianceCertificate:
    """Complete compliance certificate structure."""
    certificate_id: str
    certificate_type: str
    issue_date: str
    expiry_date: str
    subject: Dict[str, Any]
    issuer: Dict[str, Any]
    compliance_data: Dict[str, Any]
    digital_signature: DigitalSignature
    public_key_pem: str
    certificate_chain: List[str]
    
class CertificationEngine:
    """Digital certification engine for PurgeProof compliance."""
    
    def __init__(self, key_size: int = 2048, curve_name: str = "secp256r1"):
        """Initialize certification engine.
        
        Args:
            key_size: RSA key size (2048, 3072, or 4096)
            curve_name: EC curve name (secp256r1, secp384r1, secp521r1)
        """
        self.key_size = key_size
        self.curve_name = curve_name
        self.backend = default_backend()
        
        # Store keys in memory (in production, use HSM or secure storage)
        self._private_keys: Dict[str, Any] = {}
        self._certificates: Dict[str, x509.Certificate] = {}
        
        # Initialize CA if not exists
        self._initialize_ca()
    
    def _initialize_ca(self):
        """Initialize Certificate Authority for self-signed certificates."""
        try:
            ca_key_path = Path("purgeproof_ca_key.pem")
            ca_cert_path = Path("purgeproof_ca_cert.pem")
            
            if ca_key_path.exists() and ca_cert_path.exists():
                # Load existing CA
                with open(ca_key_path, 'rb') as f:
                    self.ca_private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=self.backend
                    )
                
                with open(ca_cert_path, 'rb') as f:
                    self.ca_certificate = x509.load_pem_x509_certificate(
                        f.read(), backend=self.backend
                    )
                
                logger.info("Loaded existing PurgeProof CA certificate")
            else:
                # Create new CA
                self._create_ca()
                logger.info("Created new PurgeProof CA certificate")
                
        except Exception as e:
            logger.warning(f"Failed to initialize CA: {e}, creating new one")
            self._create_ca()
    
    def _create_ca(self):
        """Create a new Certificate Authority."""
        # Generate CA private key
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=self.backend
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PurgeProof Enterprise"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PurgeProof Root CA"),
        ])
        
        self.ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("purgeproof.local"),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(self.ca_private_key, hashes.SHA256(), self.backend)
        
        # Save CA files
        try:
            with open("purgeproof_ca_key.pem", "wb") as f:
                f.write(self.ca_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open("purgeproof_ca_cert.pem", "wb") as f:
                f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
                
        except Exception as e:
            logger.warning(f"Failed to save CA files: {e}")
    
    def generate_rsa_keypair(self, key_size: Optional[int] = None) -> Tuple[RSAPrivateKey, str]:
        """Generate RSA key pair and return private key and public key fingerprint."""
        key_size = key_size or self.key_size
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        # Generate fingerprint
        public_key_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(public_key_der).hexdigest()
        
        return private_key, fingerprint
    
    def generate_ec_keypair(self, curve_name: Optional[str] = None) -> Tuple[EllipticCurvePrivateKey, str]:
        """Generate EC key pair and return private key and public key fingerprint."""
        curve_name = curve_name or self.curve_name
        
        if curve_name == "secp256r1":
            curve = ec.SECP256R1()
        elif curve_name == "secp384r1":
            curve = ec.SECP384R1()
        elif curve_name == "secp521r1":
            curve = ec.SECP521R1()
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")
        
        private_key = ec.generate_private_key(curve, self.backend)
        
        # Generate fingerprint
        public_key_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(public_key_der).hexdigest()
        
        return private_key, fingerprint
    
    def create_x509_certificate(self, private_key: Any, subject: CertificateSubject, 
                              certificate_type: str, validity_days: int = 365) -> x509.Certificate:
        """Create an X.509 certificate."""
        # Build subject name
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{subject.common_name} - {certificate_type}"),
        ])
        
        if subject.email:
            subject_name = x509.Name(list(subject_name) + [
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject.email)
            ])
        
        # Build certificate
        builder = x509.CertificateBuilder().subject_name(
            subject_name
        ).issuer_name(
            self.ca_certificate.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
                x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
            ]),
            critical=True,
        )
        
        # Add certificate type as extension
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.RFC822Name(f"purgeproof-{certificate_type}@example.com"),
            ]),
            critical=False,
        )
        
        # Sign with CA
        certificate = builder.sign(self.ca_private_key, hashes.SHA256(), self.backend)
        
        return certificate
    
    def sign_data(self, private_key: Any, data: bytes, algorithm: str) -> bytes:
        """Sign data with specified algorithm."""
        if isinstance(private_key, RSAPrivateKey):
            if algorithm == SignatureAlgorithm.RSA_PSS_SHA256:
                signature = private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif algorithm == SignatureAlgorithm.RSA_PKCS1_SHA256:
                signature = private_key.sign(
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            else:
                raise ValueError(f"Unsupported RSA algorithm: {algorithm}")
                
        elif isinstance(private_key, EllipticCurvePrivateKey):
            if algorithm == SignatureAlgorithm.ECDSA_SHA256:
                signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            elif algorithm == SignatureAlgorithm.ECDSA_SHA384:
                signature = private_key.sign(data, ec.ECDSA(hashes.SHA384()))
            else:
                raise ValueError(f"Unsupported ECDSA algorithm: {algorithm}")
        else:
            raise ValueError(f"Unsupported key type: {type(private_key)}")
        
        return signature
    
    def generate_compliance_certificate(self, compliance_data: Dict[str, Any], 
                                      certificate_type: str = CertificateType.COMPLIANCE_REPORT,
                                      algorithm: str = SignatureAlgorithm.RSA_PSS_SHA256,
                                      subject: Optional[CertificateSubject] = None) -> ComplianceCertificate:
        """Generate a complete compliance certificate with digital signature."""
        
        # Use default subject if not provided
        if subject is None:
            subject = CertificateSubject()
        
        # Generate appropriate key pair
        if algorithm.startswith("RSA"):
            private_key, fingerprint = self.generate_rsa_keypair()
        else:
            private_key, fingerprint = self.generate_ec_keypair()
        
        # Create X.509 certificate
        x509_cert = self.create_x509_certificate(private_key, subject, certificate_type)
        
        # Prepare data for signing
        cert_id = str(uuid.uuid4())
        issue_date = datetime.now(timezone.utc).isoformat()
        expiry_date = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        
        # Create certificate data structure
        cert_data = {
            "certificate_id": cert_id,
            "certificate_type": certificate_type,
            "issue_date": issue_date,
            "expiry_date": expiry_date,
            "subject": asdict(subject),
            "issuer": {
                "organization": "PurgeProof Enterprise",
                "common_name": "PurgeProof Root CA"
            },
            "compliance_data": compliance_data
        }
        
        # Sign the certificate data
        data_to_sign = json.dumps(cert_data, sort_keys=True).encode('utf-8')
        signature = self.sign_data(private_key, data_to_sign, algorithm)
        
        # Create digital signature structure
        digital_signature = DigitalSignature(
            signature_data=base64.b64encode(signature).decode('utf-8'),
            algorithm=algorithm,
            public_key_fingerprint=fingerprint,
            timestamp=datetime.now(timezone.utc).isoformat(),
            signer_info={
                "organization": subject.organization,
                "common_name": subject.common_name,
                "certificate_serial": str(x509_cert.serial_number)
            },
            verification_info={
                "verification_method": "X.509 Certificate Chain",
                "ca_fingerprint": hashlib.sha256(
                    self.ca_certificate.public_bytes(serialization.Encoding.DER)
                ).hexdigest(),
                "signature_algorithm": algorithm
            }
        )
        
        # Get public key PEM
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Get certificate chain
        certificate_chain = [
            x509_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            self.ca_certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        ]
        
        # Store keys for later use
        self._private_keys[cert_id] = private_key
        self._certificates[cert_id] = x509_cert
        
        return ComplianceCertificate(
            certificate_id=cert_id,
            certificate_type=certificate_type,
            issue_date=issue_date,
            expiry_date=expiry_date,
            subject=asdict(subject),
            issuer={
                "organization": "PurgeProof Enterprise",
                "common_name": "PurgeProof Root CA"
            },
            compliance_data=compliance_data,
            digital_signature=digital_signature,
            public_key_pem=public_key_pem,
            certificate_chain=certificate_chain
        )
    
    def verify_certificate(self, certificate: ComplianceCertificate) -> bool:
        """Verify a compliance certificate's digital signature."""
        try:
            # Reconstruct the signed data
            cert_data = {
                "certificate_id": certificate.certificate_id,
                "certificate_type": certificate.certificate_type,
                "issue_date": certificate.issue_date,
                "expiry_date": certificate.expiry_date,
                "subject": certificate.subject,
                "issuer": certificate.issuer,
                "compliance_data": certificate.compliance_data
            }
            
            data_to_verify = json.dumps(cert_data, sort_keys=True).encode('utf-8')
            signature = base64.b64decode(certificate.digital_signature.signature_data)
            
            # Load public key from PEM
            public_key = serialization.load_pem_public_key(
                certificate.public_key_pem.encode('utf-8'),
                backend=self.backend
            )
            
            # Verify signature based on algorithm
            algorithm = certificate.digital_signature.algorithm
            
            if isinstance(public_key, rsa.RSAPublicKey):
                if algorithm == SignatureAlgorithm.RSA_PSS_SHA256:
                    public_key.verify(
                        signature,
                        data_to_verify,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                elif algorithm == SignatureAlgorithm.RSA_PKCS1_SHA256:
                    public_key.verify(
                        signature,
                        data_to_verify,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                else:
                    return False
                    
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                if algorithm == SignatureAlgorithm.ECDSA_SHA256:
                    public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
                elif algorithm == SignatureAlgorithm.ECDSA_SHA384:
                    public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA384()))
                else:
                    return False
            else:
                return False
            
            # If we get here, signature is valid
            logger.info(f"Certificate {certificate.certificate_id} signature verified successfully")
            return True
            
        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            return False
    
    def export_certificate(self, certificate: ComplianceCertificate, 
                          format_type: str = "json") -> str:
        """Export certificate in specified format."""
        if format_type.lower() == "json":
            return json.dumps(asdict(certificate), indent=2)
        elif format_type.lower() == "pem":
            # Return certificate chain in PEM format
            return "\n".join(certificate.certificate_chain)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def import_certificate(self, data: str, format_type: str = "json") -> ComplianceCertificate:
        """Import certificate from specified format."""
        if format_type.lower() == "json":
            cert_dict = json.loads(data)
            
            # Convert nested dataclass
            digital_signature_dict = cert_dict["digital_signature"]
            digital_signature = DigitalSignature(**digital_signature_dict)
            
            cert_dict["digital_signature"] = digital_signature
            
            return ComplianceCertificate(**cert_dict)
        else:
            raise ValueError(f"Unsupported import format: {format_type}")

# Convenience functions for integration with existing compliance module
def get_certification_engine() -> CertificationEngine:
    """Get a global certification engine instance."""
    if not hasattr(get_certification_engine, "_instance"):
        get_certification_engine._instance = CertificationEngine()
    return get_certification_engine._instance

def generate_sanitization_certificate(device_path: str, method: str, 
                                   compliance_level: str, verification_passed: bool,
                                   duration_minutes: float, bytes_processed: int) -> ComplianceCertificate:
    """Generate a certificate for sanitization completion."""
    engine = get_certification_engine()
    
    compliance_data = {
        "sanitization_details": {
            "device_path": device_path,
            "method_used": method,
            "compliance_level": compliance_level,
            "verification_passed": verification_passed,
            "duration_minutes": duration_minutes,
            "bytes_processed": bytes_processed,
            "completion_timestamp": datetime.now(timezone.utc).isoformat()
        },
        "nist_compliance": {
            "standard": "NIST SP 800-88 Rev.1",
            "category": "Purge" if verification_passed else "Clear",
            "meets_requirements": verification_passed
        }
    }
    
    return engine.generate_compliance_certificate(
        compliance_data=compliance_data,
        certificate_type=CertificateType.SANITIZATION_PROOF
    )

def generate_audit_certificate(audit_events: List[Dict], device_path: str) -> ComplianceCertificate:
    """Generate a certificate for audit trail integrity."""
    engine = get_certification_engine()
    
    # Calculate audit trail hash
    audit_data = json.dumps(audit_events, sort_keys=True).encode('utf-8')
    audit_hash = hashlib.sha256(audit_data).hexdigest()
    
    compliance_data = {
        "audit_details": {
            "device_path": device_path,
            "events_count": len(audit_events),
            "audit_hash": audit_hash,
            "generation_timestamp": datetime.now(timezone.utc).isoformat()
        },
        "integrity_proof": {
            "hash_algorithm": "SHA-256",
            "tamper_evident": True,
            "cryptographic_seal": audit_hash
        }
    }
    
    return engine.generate_compliance_certificate(
        compliance_data=compliance_data,
        certificate_type=CertificateType.AUDIT_TRAIL
    )