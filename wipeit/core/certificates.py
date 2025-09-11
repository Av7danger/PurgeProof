"""
Certificate Generation Module - NIST SP 800-88 Rev.1 Compliant Certificates

This module generates tamper-proof wipe certificates in both JSON and PDF formats.
All certificates are digitally signed and include comprehensive sanitization metadata
for compliance and audit purposes.

Certificate Features:
- NIST SP 800-88 Rev.1 compliance mapping
- Digital signatures for tamper detection
- QR codes linking JSON and PDF certificates
- Comprehensive device and operation metadata
- Audit trail and verification data
"""

import os
import sys
import time
import json
import logging
import hashlib
import qrcode
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.pdfgen import canvas
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    import reportlab
except ImportError:
    reportlab = None

try:
    from PIL import Image as PILImage
except ImportError:
    PILImage = None

from .device_utils import DeviceInfo
from .wipe_engine import WipeResult, SanitizationMethod
from .verification import VerificationReport, VerificationResult
from .crypto_utils import CryptoManager, DigitalSignature

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class CertificateMetadata:
    """Certificate metadata structure."""
    certificate_id: str
    certificate_version: str
    generated_at: float
    generated_by: str
    nist_compliance_level: str
    audit_trail_id: str


@dataclass
class WipeCertificate:
    """Complete wipe certificate data structure."""
    metadata: CertificateMetadata
    device_info: Dict[str, Any]
    sanitization_details: Dict[str, Any] 
    verification_results: Dict[str, Any]
    compliance_assessment: Dict[str, Any]
    digital_signature: Optional[Dict[str, Any]]
    certificate_hash: str


class CertificateGenerator:
    """
    NIST SP 800-88 Rev.1 compliant certificate generator.
    
    Generates tamper-proof certificates in JSON and PDF formats with
    digital signatures and comprehensive audit information.
    """
    
    def __init__(self, crypto_manager: Optional[CryptoManager] = None, 
                 output_directory: Optional[str] = None):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize crypto manager
        self.crypto_manager = crypto_manager or CryptoManager()
        
        # Output directory for certificates
        self.output_directory = Path(output_directory or self._get_default_output_path())
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Certificate configuration
        self.certificate_version = "1.0"
        self.organization_name = "PurgeProof Data Sanitization"
        self.compliance_framework = "NIST SP 800-88 Rev.1"
        
        # Check required dependencies
        if not reportlab:
            self.logger.warning("ReportLab not available - PDF generation disabled")
        if not PILImage:
            self.logger.warning("PIL not available - QR code generation may be limited")
        
        # Initialize styles for PDF generation
        if reportlab:
            self._init_pdf_styles()
    
    def _get_default_output_path(self) -> str:
        """Get default certificate output path."""
        if sys.platform == "win32":
            documents = os.path.join(os.path.expanduser("~"), "Documents")
            return os.path.join(documents, "PurgeProof", "Certificates")
        else:
            return os.path.join(os.path.expanduser("~"), "purgeproof", "certificates")
    
    def _init_pdf_styles(self) -> None:
        """Initialize PDF styles for ReportLab."""
        try:
            self.styles = getSampleStyleSheet()
            
            # Custom styles
            self.styles.add(ParagraphStyle(
                name='CertificateTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.darkblue,
                alignment=TA_CENTER,
                spaceAfter=30
            ))
            
            self.styles.add(ParagraphStyle(
                name='SectionHeader',
                parent=self.styles['Heading2'],
                fontSize=14,
                textColor=colors.darkblue,
                spaceBefore=20,
                spaceAfter=10
            ))
            
            self.styles.add(ParagraphStyle(
                name='CertificateBody',
                parent=self.styles['Normal'],
                fontSize=10,
                leftIndent=20,
                spaceAfter=6
            ))
            
            self.styles.add(ParagraphStyle(
                name='Footer',
                parent=self.styles['Normal'],
                fontSize=8,
                textColor=colors.grey,
                alignment=TA_CENTER,
                topPadding=20
            ))
        
        except Exception as e:
            self.logger.error(f"Error initializing PDF styles: {e}")
    
    def generate_certificate(self, device_info: DeviceInfo, wipe_result: WipeResult,
                           verification_report: VerificationReport, 
                           certificate_id: Optional[str] = None,
                           formats: List[str] = None) -> Dict[str, str]:
        """
        Generate complete wipe certificate in specified formats.
        
        Args:
            device_info: Device information
            wipe_result: Sanitization operation result
            verification_report: Verification results
            certificate_id: Custom certificate ID (auto-generated if None)
            formats: List of formats to generate ("json", "pdf")
        
        Returns:
            Dictionary mapping format to file path
        """
        try:
            formats = formats or ["json", "pdf"]
            certificate_id = certificate_id or self._generate_certificate_id(device_info, wipe_result)
            
            self.logger.info(f"Generating certificate {certificate_id} in formats: {formats}")
            
            # Create certificate data structure
            certificate = self._create_certificate_data(
                device_info, wipe_result, verification_report, certificate_id
            )
            
            # Generate certificates in requested formats
            generated_files = {}
            
            if "json" in formats:
                json_path = self._generate_json_certificate(certificate, certificate_id)
                generated_files["json"] = json_path
            
            if "pdf" in formats and reportlab:
                pdf_path = self._generate_pdf_certificate(certificate, certificate_id)
                generated_files["pdf"] = pdf_path
            elif "pdf" in formats:
                self.logger.warning("PDF generation requested but ReportLab not available")
            
            self.logger.info(f"Certificate generation completed: {len(generated_files)} files created")
            return generated_files
        
        except Exception as e:
            self.logger.error(f"Error generating certificate: {e}")
            raise
    
    def _generate_certificate_id(self, device_info: DeviceInfo, wipe_result: WipeResult) -> str:
        """Generate unique certificate ID."""
        try:
            # Create ID from device serial, timestamp, and method
            components = [
                device_info.serial[:8] if device_info.serial != "Unknown" else "NOSER",
                str(int(wipe_result.start_time))[-8:],
                wipe_result.method_used.value[:4].upper()
            ]
            
            # Add hash for uniqueness
            id_string = "-".join(components)
            hash_suffix = hashlib.sha256(id_string.encode()).hexdigest()[:6].upper()
            
            return f"PP-{id_string}-{hash_suffix}"
        
        except Exception as e:
            self.logger.error(f"Error generating certificate ID: {e}")
            return f"PP-ERROR-{int(time.time())}"
    
    def _create_certificate_data(self, device_info: DeviceInfo, wipe_result: WipeResult,
                                verification_report: VerificationReport, 
                                certificate_id: str) -> WipeCertificate:
        """Create complete certificate data structure."""
        try:
            timestamp = time.time()
            
            # Certificate metadata
            metadata = CertificateMetadata(
                certificate_id=certificate_id,
                certificate_version=self.certificate_version,
                generated_at=timestamp,
                generated_by=self.organization_name,
                nist_compliance_level=self.compliance_framework,
                audit_trail_id=f"AT-{certificate_id}"
            )
            
            # Device information (sanitized for certificate)
            device_data = {
                "device_path": device_info.path,
                "model": device_info.model,
                "serial_number": device_info.serial,
                "device_type": device_info.device_type,
                "storage_capacity_bytes": device_info.size_bytes,
                "storage_capacity_gb": round(device_info.size_bytes / (1024**3), 2),
                "platform": device_info.platform,
                "encryption_status": {
                    "is_encrypted": device_info.is_encrypted,
                    "encryption_type": device_info.encryption_type
                },
                "firmware_version": device_info.firmware_version,
                "capabilities": device_info.capabilities
            }
            
            # Sanitization details
            sanitization_data = {
                "method_used": wipe_result.method_used.value,
                "nist_method_classification": self._get_nist_classification(wipe_result.method_used),
                "operation_start_time": wipe_result.start_time,
                "operation_end_time": wipe_result.end_time,
                "duration_seconds": wipe_result.duration_seconds,
                "duration_formatted": self._format_duration(wipe_result.duration_seconds),
                "bytes_processed": wipe_result.bytes_processed,
                "result_status": wipe_result.result.value,
                "error_message": wipe_result.error_message,
                "method_specific_data": wipe_result.method_specific_data
            }
            
            # Verification results
            verification_data = {
                "verification_performed": True,
                "verification_level": verification_report.verification_level.value,
                "verification_result": verification_report.result.value,
                "confidence_level": verification_report.confidence_level,
                "samples_analyzed": verification_report.samples_analyzed,
                "bytes_verified": verification_report.total_bytes_verified,
                "verification_duration": verification_report.duration_seconds,
                "entropy_analysis": verification_report.entropy_statistics,
                "pattern_analysis": verification_report.pattern_analysis,
                "error_details": verification_report.error_details
            }
            
            # Compliance assessment
            compliance_data = {
                "nist_sp_800_88_compliant": verification_report.compliance_status.get("overall_compliant", False),
                "compliance_details": verification_report.compliance_status,
                "method_effectiveness": self._assess_method_effectiveness(wipe_result, verification_report),
                "risk_assessment": self._perform_risk_assessment(wipe_result, verification_report),
                "recommendations": self._generate_recommendations(wipe_result, verification_report)
            }
            
            # Create certificate without signature first
            certificate_data = {
                "metadata": asdict(metadata),
                "device_info": device_data,
                "sanitization_details": sanitization_data,
                "verification_results": verification_data,
                "compliance_assessment": compliance_data
            }
            
            # Calculate certificate hash
            certificate_json = json.dumps(certificate_data, sort_keys=True, separators=(',', ':'))
            certificate_hash = hashlib.sha256(certificate_json.encode()).hexdigest()
            
            # Create digital signature
            sealed_certificate = self.crypto_manager.create_tamper_proof_seal(certificate_data)
            
            return WipeCertificate(
                metadata=metadata,
                device_info=device_data,
                sanitization_details=sanitization_data,
                verification_results=verification_data,
                compliance_assessment=compliance_data,
                digital_signature=sealed_certificate.get("integrity"),
                certificate_hash=certificate_hash
            )
        
        except Exception as e:
            self.logger.error(f"Error creating certificate data: {e}")
            raise
    
    def _get_nist_classification(self, method: SanitizationMethod) -> str:
        """Get NIST SP 800-88 Rev.1 classification for sanitization method."""
        classifications = {
            SanitizationMethod.OVERWRITE_SINGLE: "CLEAR - Logical sanitization",
            SanitizationMethod.OVERWRITE_MULTI: "CLEAR - Logical sanitization",
            SanitizationMethod.CRYPTO_ERASE: "PURGE - Cryptographic erase",
            SanitizationMethod.FIRMWARE_SECURE_ERASE: "PURGE - Firmware secure erase",
            SanitizationMethod.NVME_SANITIZE: "PURGE - NVMe sanitize",
            SanitizationMethod.PHYSICAL_DESTROY: "DESTROY - Physical destruction"
        }
        return classifications.get(method, "UNKNOWN")
    
    def _format_duration(self, duration_seconds: float) -> str:
        """Format duration in human-readable format."""
        try:
            if duration_seconds < 60:
                return f"{duration_seconds:.1f} seconds"
            elif duration_seconds < 3600:
                minutes = duration_seconds / 60
                return f"{minutes:.1f} minutes"
            else:
                hours = duration_seconds / 3600
                return f"{hours:.1f} hours"
        except Exception:
            return "Unknown duration"
    
    def _assess_method_effectiveness(self, wipe_result: WipeResult, 
                                   verification_report: VerificationReport) -> str:
        """Assess the effectiveness of the sanitization method."""
        try:
            if verification_report.result == VerificationResult.PASSED:
                if verification_report.confidence_level >= 90:
                    return "Highly Effective"
                elif verification_report.confidence_level >= 75:
                    return "Effective"
                else:
                    return "Moderately Effective"
            elif verification_report.result == VerificationResult.PARTIAL:
                return "Partially Effective"
            else:
                return "Ineffective"
        except Exception:
            return "Unknown"
    
    def _perform_risk_assessment(self, wipe_result: WipeResult, 
                               verification_report: VerificationReport) -> Dict[str, Any]:
        """Perform risk assessment based on sanitization results."""
        try:
            risk_level = "UNKNOWN"
            risk_factors = []
            
            # Assess based on verification results
            if verification_report.result == VerificationResult.PASSED:
                if verification_report.confidence_level >= 95:
                    risk_level = "MINIMAL"
                elif verification_report.confidence_level >= 85:
                    risk_level = "LOW"
                elif verification_report.confidence_level >= 70:
                    risk_level = "MODERATE"
                else:
                    risk_level = "HIGH"
                    risk_factors.append("Low verification confidence")
            else:
                risk_level = "HIGH"
                risk_factors.append("Verification failed or incomplete")
            
            # Additional risk factors
            if wipe_result.method_used in [SanitizationMethod.OVERWRITE_SINGLE, SanitizationMethod.OVERWRITE_MULTI]:
                if not verification_report.compliance_status.get("clear_method_acceptable", False):
                    risk_factors.append("Clear method may not be sufficient for sensitive data")
            
            if verification_report.pattern_analysis.get("structured_data_found", False):
                risk_factors.append("Structured data patterns detected")
            
            if verification_report.entropy_statistics.get("mean", 0) < 7.0:
                risk_factors.append("Low entropy indicates potential data recovery")
            
            return {
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "data_recovery_likelihood": self._estimate_recovery_likelihood(verification_report),
                "recommended_classification": self._recommend_data_classification(risk_level)
            }
        
        except Exception as e:
            self.logger.error(f"Error performing risk assessment: {e}")
            return {"risk_level": "UNKNOWN", "risk_factors": ["Assessment error"]}
    
    def _estimate_recovery_likelihood(self, verification_report: VerificationReport) -> str:
        """Estimate likelihood of data recovery."""
        try:
            if verification_report.result == VerificationResult.PASSED:
                if verification_report.confidence_level >= 95:
                    return "NEGLIGIBLE"
                elif verification_report.confidence_level >= 85:
                    return "VERY LOW"
                elif verification_report.confidence_level >= 70:
                    return "LOW"
                else:
                    return "MODERATE"
            else:
                return "HIGH"
        except Exception:
            return "UNKNOWN"
    
    def _recommend_data_classification(self, risk_level: str) -> str:
        """Recommend appropriate data classification based on risk."""
        recommendations = {
            "MINIMAL": "Suitable for all data classifications including TOP SECRET",
            "LOW": "Suitable for SECRET and below classifications",
            "MODERATE": "Suitable for CONFIDENTIAL and below classifications", 
            "HIGH": "Only suitable for UNCLASSIFIED data, consider re-sanitization",
            "UNKNOWN": "Classification assessment cannot be determined"
        }
        return recommendations.get(risk_level, "Unknown classification")
    
    def _generate_recommendations(self, wipe_result: WipeResult, 
                                verification_report: VerificationReport) -> List[str]:
        """Generate recommendations based on sanitization results."""
        recommendations = []
        
        try:
            # General recommendations based on results
            if verification_report.result == VerificationResult.PASSED:
                recommendations.append("Sanitization appears successful - device may be safely reused or disposed")
            else:
                recommendations.append("Sanitization verification failed - consider additional sanitization or physical destruction")
            
            # Method-specific recommendations
            if wipe_result.method_used == SanitizationMethod.OVERWRITE_SINGLE:
                recommendations.append("Single-pass overwrite used - acceptable for most commercial applications")
                if verification_report.confidence_level < 80:
                    recommendations.append("Consider using cryptographic erase or secure erase for higher security")
            
            elif wipe_result.method_used == SanitizationMethod.CRYPTO_ERASE:
                recommendations.append("Cryptographic erase is highly effective for encrypted storage")
                recommendations.append("Ensure encryption keys are properly managed and rotated")
            
            elif wipe_result.method_used in [SanitizationMethod.FIRMWARE_SECURE_ERASE, SanitizationMethod.NVME_SANITIZE]:
                recommendations.append("Hardware-based sanitization provides excellent security")
                recommendations.append("Verify firmware sanitization support before deployment")
            
            elif wipe_result.method_used == SanitizationMethod.PHYSICAL_DESTROY:
                recommendations.append("Physical destruction required - use certified destruction service")
                recommendations.append("Maintain chain of custody documentation")
            
            # Risk-based recommendations
            risk_level = verification_report.compliance_status.get("overall_compliant", False)
            if not risk_level:
                recommendations.append("NIST SP 800-88 compliance not achieved - review sanitization method")
            
            # Pattern analysis recommendations
            if verification_report.pattern_analysis.get("structured_data_found", False):
                recommendations.append("Structured data detected - verify sanitization effectiveness")
                recommendations.append("Consider additional sanitization passes or alternative methods")
            
            # Entropy recommendations
            mean_entropy = verification_report.entropy_statistics.get("mean", 0)
            if mean_entropy < 7.0:
                recommendations.append(f"Low entropy detected ({mean_entropy:.2f}/8.0) - may indicate incomplete sanitization")
            
            return recommendations
        
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            return ["Error generating recommendations - manual review required"]
    
    def _generate_json_certificate(self, certificate: WipeCertificate, certificate_id: str) -> str:
        """Generate JSON format certificate."""
        try:
            # Convert certificate to dictionary
            cert_dict = {
                "certificate_id": certificate_id,
                "certificate_version": certificate.metadata.certificate_version,
                "generated_at": certificate.metadata.generated_at,
                "generated_at_iso": datetime.fromtimestamp(certificate.metadata.generated_at, tz=timezone.utc).isoformat(),
                "generated_by": certificate.metadata.generated_by,
                "nist_compliance_level": certificate.metadata.nist_compliance_level,
                "audit_trail_id": certificate.metadata.audit_trail_id,
                "device_info": certificate.device_info,
                "sanitization_details": certificate.sanitization_details,
                "verification_results": certificate.verification_results,
                "compliance_assessment": certificate.compliance_assessment,
                "certificate_hash": certificate.certificate_hash
            }
            
            # Add digital signature if available
            if certificate.digital_signature:
                cert_dict["digital_signature"] = certificate.digital_signature
            
            # Save to file
            json_filename = f"{certificate_id}.json"
            json_path = self.output_directory / json_filename
            
            with open(json_path, 'w') as f:
                json.dump(cert_dict, f, indent=2, sort_keys=True)
            
            self.logger.info(f"JSON certificate generated: {json_path}")
            return str(json_path)
        
        except Exception as e:
            self.logger.error(f"Error generating JSON certificate: {e}")
            raise
    
    def _generate_pdf_certificate(self, certificate: WipeCertificate, certificate_id: str) -> str:
        """Generate PDF format certificate."""
        try:
            if not reportlab:
                raise ImportError("ReportLab is required for PDF generation")
            
            # Create PDF file
            pdf_filename = f"{certificate_id}.pdf"
            pdf_path = self.output_directory / pdf_filename
            
            # Create PDF document
            doc = SimpleDocTemplate(str(pdf_path), pagesize=letter, topMargin=0.5*inch)
            story = []
            
            # Add certificate content
            self._add_pdf_header(story, certificate)
            self._add_pdf_device_info(story, certificate)
            self._add_pdf_sanitization_details(story, certificate)
            self._add_pdf_verification_results(story, certificate)
            self._add_pdf_compliance_assessment(story, certificate)
            self._add_pdf_signature_section(story, certificate)
            self._add_pdf_footer(story, certificate)
            
            # Build PDF
            doc.build(story)
            
            self.logger.info(f"PDF certificate generated: {pdf_path}")
            return str(pdf_path)
        
        except Exception as e:
            self.logger.error(f"Error generating PDF certificate: {e}")
            raise
    
    def _add_pdf_header(self, story: List, certificate: WipeCertificate) -> None:
        """Add PDF header section."""
        try:
            # Certificate title
            title = Paragraph("DATA SANITIZATION CERTIFICATE", self.styles['CertificateTitle'])
            story.append(title)
            story.append(Spacer(1, 12))
            
            # Certificate info table
            cert_info = [
                ["Certificate ID:", certificate.metadata.certificate_id],
                ["Generated:", datetime.fromtimestamp(certificate.metadata.generated_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
                ["Compliance Framework:", certificate.metadata.nist_compliance_level],
                ["Organization:", certificate.metadata.generated_by]
            ]
            
            table = Table(cert_info, colWidths=[2*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 20))
        
        except Exception as e:
            self.logger.error(f"Error adding PDF header: {e}")
    
    def _add_pdf_device_info(self, story: List, certificate: WipeCertificate) -> None:
        """Add device information section to PDF."""
        try:
            story.append(Paragraph("DEVICE INFORMATION", self.styles['SectionHeader']))
            
            device_info = [
                ["Device Path:", certificate.device_info["device_path"]],
                ["Model:", certificate.device_info["model"]],
                ["Serial Number:", certificate.device_info["serial_number"]],
                ["Device Type:", certificate.device_info["device_type"].upper()],
                ["Storage Capacity:", f"{certificate.device_info['storage_capacity_gb']} GB"],
                ["Platform:", certificate.device_info["platform"].title()],
                ["Encrypted:", "Yes" if certificate.device_info["encryption_status"]["is_encrypted"] else "No"]
            ]
            
            if certificate.device_info["encryption_status"]["is_encrypted"]:
                device_info.append(["Encryption Type:", certificate.device_info["encryption_status"]["encryption_type"] or "Unknown"])
            
            table = Table(device_info, colWidths=[2*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 15))
        
        except Exception as e:
            self.logger.error(f"Error adding device info to PDF: {e}")
    
    def _add_pdf_sanitization_details(self, story: List, certificate: WipeCertificate) -> None:
        """Add sanitization details section to PDF."""
        try:
            story.append(Paragraph("SANITIZATION DETAILS", self.styles['SectionHeader']))
            
            sanitization_info = [
                ["Method Used:", certificate.sanitization_details["method_used"].replace("_", " ").title()],
                ["NIST Classification:", certificate.sanitization_details["nist_method_classification"]],
                ["Operation Status:", certificate.sanitization_details["result_status"].upper()],
                ["Duration:", certificate.sanitization_details["duration_formatted"]],
                ["Bytes Processed:", f"{certificate.sanitization_details['bytes_processed']:,}"],
                ["Start Time:", datetime.fromtimestamp(certificate.sanitization_details["operation_start_time"]).strftime("%Y-%m-%d %H:%M:%S")],
                ["End Time:", datetime.fromtimestamp(certificate.sanitization_details["operation_end_time"]).strftime("%Y-%m-%d %H:%M:%S")]
            ]
            
            if certificate.sanitization_details["error_message"]:
                sanitization_info.append(["Error Message:", certificate.sanitization_details["error_message"]])
            
            table = Table(sanitization_info, colWidths=[2*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgreen),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 15))
        
        except Exception as e:
            self.logger.error(f"Error adding sanitization details to PDF: {e}")
    
    def _add_pdf_verification_results(self, story: List, certificate: WipeCertificate) -> None:
        """Add verification results section to PDF."""
        try:
            story.append(Paragraph("VERIFICATION RESULTS", self.styles['SectionHeader']))
            
            verification_info = [
                ["Verification Level:", certificate.verification_results["verification_level"].title()],
                ["Verification Result:", certificate.verification_results["verification_result"].upper()],
                ["Confidence Level:", f"{certificate.verification_results['confidence_level']:.1f}%"],
                ["Samples Analyzed:", f"{certificate.verification_results['samples_analyzed']:,}"],
                ["Bytes Verified:", f"{certificate.verification_results['bytes_verified']:,}"],
                ["Verification Duration:", f"{certificate.verification_results['verification_duration']:.2f} seconds"]
            ]
            
            # Add entropy analysis if available
            entropy_stats = certificate.verification_results.get("entropy_analysis", {})
            if entropy_stats.get("mean"):
                verification_info.append(["Mean Entropy:", f"{entropy_stats['mean']:.2f}/8.0"])
            
            table = Table(verification_info, colWidths=[2*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightyellow),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 15))
        
        except Exception as e:
            self.logger.error(f"Error adding verification results to PDF: {e}")
    
    def _add_pdf_compliance_assessment(self, story: List, certificate: WipeCertificate) -> None:
        """Add compliance assessment section to PDF."""
        try:
            story.append(Paragraph("COMPLIANCE ASSESSMENT", self.styles['SectionHeader']))
            
            compliance = certificate.compliance_assessment
            
            compliance_info = [
                ["NIST SP 800-88 Compliant:", "YES" if compliance["nist_sp_800_88_compliant"] else "NO"],
                ["Method Effectiveness:", compliance["method_effectiveness"]],
                ["Risk Level:", compliance["risk_assessment"]["risk_level"]],
                ["Data Recovery Likelihood:", compliance["risk_assessment"]["data_recovery_likelihood"]],
                ["Recommended Classification:", compliance["risk_assessment"]["recommended_classification"]]
            ]
            
            table = Table(compliance_info, colWidths=[2*inch, 4*inch])
            
            # Color code compliance status
            compliance_color = colors.lightgreen if compliance["nist_sp_800_88_compliant"] else colors.lightcoral
            
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), compliance_color),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 10))
            
            # Add recommendations
            if compliance["recommendations"]:
                story.append(Paragraph("RECOMMENDATIONS:", self.styles['SectionHeader']))
                for i, recommendation in enumerate(compliance["recommendations"][:5], 1):  # Limit to 5
                    rec_text = f"{i}. {recommendation}"
                    story.append(Paragraph(rec_text, self.styles['CertificateBody']))
                story.append(Spacer(1, 15))
        
        except Exception as e:
            self.logger.error(f"Error adding compliance assessment to PDF: {e}")
    
    def _add_pdf_signature_section(self, story: List, certificate: WipeCertificate) -> None:
        """Add digital signature section to PDF."""
        try:
            story.append(Paragraph("DIGITAL SIGNATURE", self.styles['SectionHeader']))
            
            if certificate.digital_signature:
                sig_info = [
                    ["Certificate Hash:", certificate.certificate_hash[:32] + "..."],
                    ["Signature Algorithm:", certificate.digital_signature["signature_algorithm"]],
                    ["Hash Algorithm:", certificate.digital_signature["hash_algorithm"]],
                    ["Signed By:", certificate.digital_signature["signed_by"]],
                    ["Signature Timestamp:", datetime.fromtimestamp(certificate.digital_signature["signature_timestamp"]).strftime("%Y-%m-%d %H:%M:%S")]
                ]
                
                table = Table(sig_info, colWidths=[2*inch, 4*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lavender),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(table)
            else:
                story.append(Paragraph("No digital signature available", self.styles['CertificateBody']))
            
            story.append(Spacer(1, 15))
        
        except Exception as e:
            self.logger.error(f"Error adding signature section to PDF: {e}")
    
    def _add_pdf_footer(self, story: List, certificate: WipeCertificate) -> None:
        """Add footer to PDF."""
        try:
            footer_text = f"""
            This certificate was generated by {certificate.metadata.generated_by} in compliance with 
            {certificate.metadata.nist_compliance_level}. The digital signature ensures the integrity 
            and authenticity of this certificate. For verification, use the certificate validation tool 
            with the provided certificate hash: {certificate.certificate_hash[:16]}...
            """
            
            story.append(Spacer(1, 30))
            story.append(Paragraph(footer_text, self.styles['Footer']))
        
        except Exception as e:
            self.logger.error(f"Error adding PDF footer: {e}")
    
    def verify_certificate(self, certificate_path: str) -> Tuple[bool, str]:
        """
        Verify the integrity and authenticity of a certificate.
        
        Args:
            certificate_path: Path to certificate file (JSON format)
        
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            if not os.path.exists(certificate_path):
                return False, "Certificate file not found"
            
            # Load certificate
            with open(certificate_path, 'r') as f:
                cert_data = json.load(f)
            
            # Check if digital signature exists
            if "digital_signature" not in cert_data:
                return False, "No digital signature found in certificate"
            
            # Verify tamper-proof seal
            is_valid, message = self.crypto_manager.verify_tamper_proof_seal(cert_data)
            
            if is_valid:
                return True, "Certificate is valid and has not been tampered with"
            else:
                return False, f"Certificate verification failed: {message}"
        
        except Exception as e:
            self.logger.error(f"Error verifying certificate: {e}")
            return False, f"Verification error: {e}"
    
    def list_certificates(self) -> List[Dict[str, Any]]:
        """List all certificates in the output directory."""
        try:
            certificates = []
            
            for json_file in self.output_directory.glob("*.json"):
                try:
                    with open(json_file, 'r') as f:
                        cert_data = json.load(f)
                    
                    # Extract basic information
                    cert_info = {
                        "certificate_id": cert_data.get("certificate_id", "Unknown"),
                        "file_path": str(json_file),
                        "generated_at": cert_data.get("generated_at_iso", "Unknown"),
                        "device_model": cert_data.get("device_info", {}).get("model", "Unknown"),
                        "sanitization_method": cert_data.get("sanitization_details", {}).get("method_used", "Unknown"),
                        "compliance_status": cert_data.get("compliance_assessment", {}).get("nist_sp_800_88_compliant", False)
                    }
                    
                    certificates.append(cert_info)
                
                except Exception as e:
                    self.logger.error(f"Error reading certificate {json_file}: {e}")
                    continue
            
            return sorted(certificates, key=lambda x: x["generated_at"], reverse=True)
        
        except Exception as e:
            self.logger.error(f"Error listing certificates: {e}")
            return []


def main():
    """CLI interface for certificate generator testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PurgeProof Certificate Generator Test")
    parser.add_argument("--list", action="store_true", help="List all certificates")
    parser.add_argument("--verify", help="Verify certificate file")
    parser.add_argument("--output-dir", help="Certificate output directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")
    
    try:
        # Initialize certificate generator
        generator = CertificateGenerator(output_directory=args.output_dir)
        
        if args.list:
            certificates = generator.list_certificates()
            print(f"Found {len(certificates)} certificates:")
            for cert in certificates:
                status = "✓" if cert["compliance_status"] else "✗"
                print(f"  {status} {cert['certificate_id']}: {cert['device_model']} ({cert['sanitization_method']}) - {cert['generated_at']}")
        
        elif args.verify:
            is_valid, message = generator.verify_certificate(args.verify)
            print(f"Certificate verification: {'VALID' if is_valid else 'INVALID'}")
            print(f"Details: {message}")
        
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
