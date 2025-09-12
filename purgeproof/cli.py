#!/usr/bin/env python3
"""
PurgeProof CLI Interface.

Command-line interface for the PurgeProof hybrid sanitization system,
providing enterprise-grade device sanitization with compliance validation.
"""

import sys
import os
import asyncio
import argparse
import json
import time
import signal
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging
from datetime import datetime

# Add the parent directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from purgeproof import (
        scan_devices, sanitize, get_stats, get_orchestrator,
        DeviceCapabilities, SanitizationMethod, ComplianceLevel, SecurityObjective
    )
    from purgeproof.compliance import get_compliance_framework, ComplianceStandard
    from purgeproof.sampling_verification import SamplingEngine, VerificationLevel
    from purgeproof.decision_engine import MethodSelectionEngine, SelectionCriteria, DeviceContext
except ImportError as e:
    print(f"Error importing PurgeProof modules: {e}")
    print("Please ensure PurgeProof is properly installed.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProgressBar:
    """Simple progress bar for CLI output."""
    
    def __init__(self, total: int, width: int = 50):
        self.total = total
        self.width = width
        self.current = 0
        self.start_time = time.time()
    
    def update(self, progress: int, status: str = ""):
        """Update progress bar."""
        self.current = progress
        percent = (progress / self.total) * 100
        filled = int((progress / self.total) * self.width)
        bar = '█' * filled + '░' * (self.width - filled)
        
        elapsed = time.time() - self.start_time
        rate = progress / elapsed if elapsed > 0 else 0
        eta = (self.total - progress) / rate if rate > 0 else 0
        
        sys.stdout.write(f'\r[{bar}] {percent:.1f}% | {progress}/{self.total} | '
                        f'{rate:.1f}/s | ETA: {eta:.0f}s | {status}')
        sys.stdout.flush()
    
    def finish(self, status: str = "Complete"):
        """Finish progress bar."""
        self.update(self.total, status)
        print()

class PurgeProofCLI:
    """Main CLI application class."""
    
    def __init__(self):
        self.orchestrator = get_orchestrator()
        self.compliance_framework = get_compliance_framework()
        self.sampling_engine = SamplingEngine()
        self.method_selector = MethodSelectionEngine()
        self.running = True
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n\nReceived shutdown signal. Cleaning up...")
        self.running = False
        sys.exit(0)
    
    async def list_devices(self, args):
        """List available storage devices."""
        print("Scanning for storage devices...")
        
        try:
            devices = scan_devices()
            
            if not devices:
                print("No storage devices found.")
                return
            
            print(f"\nFound {len(devices)} storage device(s):\n")
            
            for i, device in enumerate(devices, 1):
                print(f"{i}. {device.path}")
                print(f"   Type: {device.device_type.name}")
                print(f"   Model: {device.model}")
                print(f"   Size: {device.size_bytes / (1024**3):.1f} GB")
                print(f"   Interface: {device.interface_type.name}")
                
                # Show capabilities
                capabilities = []
                if device.supports_crypto_erase:
                    capabilities.append("Crypto Erase")
                if device.supports_secure_erase:
                    capabilities.append("Secure Erase")
                if device.supports_nvme_sanitize:
                    capabilities.append("NVMe Sanitize")
                if device.supports_trim:
                    capabilities.append("TRIM")
                
                if capabilities:
                    print(f"   Capabilities: {', '.join(capabilities)}")
                
                if device.is_encrypted:
                    print(f"   Encryption: {device.encryption_type.name} ({device.encryption_algorithm})")
                
                print()
        
        except Exception as e:
            print(f"Error scanning devices: {e}")
            return 1
        
        return 0
    
    async def analyze_device(self, args):
        """Analyze a specific device and recommend sanitization method."""
        device_path = args.device
        
        try:
            devices = scan_devices()
            device = next((d for d in devices if d.path == device_path), None)
            
            if not device:
                print(f"Device {device_path} not found.")
                return 1
            
            print(f"Analyzing device: {device.path}")
            print("=" * 50)
            
            # Show device information
            print(f"Model: {device.model}")
            print(f"Serial: {device.serial}")
            print(f"Size: {device.size_bytes / (1024**3):.1f} GB")
            print(f"Type: {device.device_type.name}")
            print(f"Interface: {device.interface_type.name}")
            print(f"Sector Size: {device.sector_size} bytes")
            
            if device.is_encrypted:
                print(f"Encryption: {device.encryption_type.name}")
                print(f"Algorithm: {device.encryption_algorithm}")
            
            print(f"Performance:")
            print(f"  Read Speed: {device.max_read_speed_mbps:.0f} MB/s")
            print(f"  Write Speed: {device.max_write_speed_mbps:.0f} MB/s")
            print(f"  Random IOPS: {device.random_iops:,}")
            print(f"  Latency: {device.latency_ms:.2f} ms")
            
            # Show capabilities
            print(f"\nSupported Methods:")
            methods = []
            if device.supports_crypto_erase:
                methods.append(f"  • Crypto Erase (~{device.crypto_erase_time_estimate} min)")
            if device.supports_secure_erase:
                methods.append(f"  • Secure Erase (~{device.secure_erase_time_estimate} min)")
            if device.supports_nvme_sanitize:
                methods.append("  • NVMe Sanitize")
            if device.supports_trim:
                methods.append("  • TRIM/Discard")
            
            methods.append(f"  • Overwrite (~{device.overwrite_time_estimate} min)")
            
            for method in methods:
                print(method)
            
            # Recommend optimal method
            compliance_level = getattr(ComplianceLevel, args.compliance.upper(), ComplianceLevel.STANDARD)
            security_objective = getattr(SecurityObjective, args.objective.upper(), SecurityObjective.BALANCED)
            
            device_context = DeviceContext(capabilities=device)
            criteria = SelectionCriteria(
                compliance_level=compliance_level,
                security_objective=security_objective
            )
            
            recommendation = self.method_selector.select_optimal_method(device_context, criteria)
            
            print(f"\nRecommended Method: {recommendation.method.name}")
            print(f"Overall Score: {recommendation.overall_score:.1f}/100")
            print(f"Estimated Duration: {recommendation.estimated_duration_minutes:.1f} minutes")
            print(f"Security Level: {recommendation.security_level}")
            print(f"Compliance Standards: {', '.join(recommendation.compliance_standards)}")
            
            if recommendation.risk_factors:
                print(f"Risk Factors:")
                for risk in recommendation.risk_factors:
                    print(f"  • {risk}")
            
            if recommendation.optimization_notes:
                print(f"Optimization Notes:")
                for note in recommendation.optimization_notes:
                    print(f"  • {note}")
        
        except Exception as e:
            print(f"Error analyzing device: {e}")
            return 1
        
        return 0
    
    async def sanitize_device(self, args):
        """Sanitize a device with specified parameters."""
        device_path = args.device
        
        try:
            devices = scan_devices()
            device = next((d for d in devices if d.path == device_path), None)
            
            if not device:
                print(f"Device {device_path} not found.")
                return 1
            
            # Parse arguments
            compliance_level = getattr(ComplianceLevel, args.compliance.upper(), ComplianceLevel.STANDARD)
            security_objective = getattr(SecurityObjective, args.objective.upper(), SecurityObjective.BALANCED)
            
            method = None
            if args.method:
                try:
                    method = getattr(SanitizationMethod, args.method.upper())
                except AttributeError:
                    print(f"Invalid sanitization method: {args.method}")
                    print("Available methods: CRYPTO_ERASE, SECURE_ERASE, NVME_SANITIZE, TRIM_DISCARD, OVERWRITE_SINGLE, OVERWRITE_MULTI")
                    return 1
            
            # Confirm operation
            if not args.force:
                print(f"WARNING: This will permanently destroy all data on {device_path}")
                print(f"Device: {device.model} ({device.size_bytes / (1024**3):.1f} GB)")
                print(f"Compliance Level: {compliance_level.name}")
                print(f"Security Objective: {security_objective.name}")
                
                if method:
                    print(f"Method: {method.name}")
                
                response = input("\nAre you sure you want to proceed? (yes/no): ")
                if response.lower() not in ['yes', 'y']:
                    print("Operation cancelled.")
                    return 0
            
            print(f"\nStarting sanitization of {device_path}...")
            
            # Submit sanitization job
            job_id = self.orchestrator.submit_sanitization_job(
                device_path,
                compliance_level,
                security_objective
            )
            
            print(f"Job submitted with ID: {job_id}")
            
            # Monitor progress
            progress_bar = ProgressBar(100)
            last_progress = 0
            
            while self.running:
                status = self.orchestrator.get_job_status(job_id)
                
                if status is None:
                    print("Failed to get job status")
                    break
                
                current_progress = status.get('progress', 0)
                job_status = status.get('status', 'unknown')
                
                if current_progress != last_progress:
                    progress_bar.update(current_progress, job_status)
                    last_progress = current_progress
                
                if job_status in ['completed', 'failed', 'cancelled']:
                    break
                
                await asyncio.sleep(1)
            
            if job_status == 'completed':
                progress_bar.finish("Sanitization completed successfully")
                
                # Show results
                result = status.get('result', {}) if status else {}
                print(f"\nSanitization Results:")
                print(f"  Method Used: {result.get('method', 'Unknown')}")
                print(f"  Duration: {result.get('duration', 0):.1f} minutes")
                print(f"  Bytes Processed: {result.get('bytes_processed', 0):,}")
                
                if args.verify:
                    print("\nPerforming verification...")
                    await self._verify_sanitization(device, method or SanitizationMethod.OVERWRITE_SINGLE)
                
                if args.compliance_report:
                    print("\nGenerating compliance report...")
                    await self._generate_compliance_report(device, method or SanitizationMethod.OVERWRITE_SINGLE, compliance_level)
            
            elif job_status == 'failed':
                print(f"\nSanitization failed: {status.get('error', 'Unknown error') if status else 'Unknown error'}")
                return 1
            
            else:
                print(f"\nSanitization {job_status}")
                return 1
        
        except KeyboardInterrupt:
            print("\n\nOperation interrupted by user")
            return 1
        except Exception as e:
            print(f"Error during sanitization: {e}")
            return 1
        
        return 0
    
    async def _verify_sanitization(self, device, method):
        """Perform verification of sanitization."""
        try:
            verification_level = VerificationLevel.STANDARD
            
            print("Running statistical sampling verification...")
            
            report = await self.sampling_engine.verify_sanitization(
                device, method, verification_level
            )
            
            print(f"Verification Results:")
            print(f"  Samples Taken: {report.samples_taken}")
            print(f"  Success Rate: {report.overall_success_rate * 100:.2f}%")
            print(f"  Confidence Interval: {report.confidence_interval[0]*100:.2f}% - {report.confidence_interval[1]*100:.2f}%")
            print(f"  Statistical Significance: {report.statistical_significance * 100:.2f}%")
            
            if report.violations:
                print(f"  Violations:")
                for violation in report.violations:
                    print(f"    • {violation}")
            
            if report.recommendations:
                print(f"  Recommendations:")
                for rec in report.recommendations:
                    print(f"    • {rec}")
        
        except Exception as e:
            print(f"Verification failed: {e}")
    
    async def _generate_compliance_report(self, device, method, compliance_level):
        """Generate compliance report."""
        try:
            report = self.compliance_framework.validate_method_compliance(
                device, method, compliance_level
            )
            
            print(f"Compliance Report:")
            print(f"  Overall Status: {report.overall_status.name}")
            print(f"  Standards Validated: {len(report.target_standards)}")
            print(f"  Risk Score: {report.risk_assessment['overall_risk_score']:.1f}/100")
            
            # Export full report if requested
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"compliance_report_{timestamp}.json"
            
            json_report = self.compliance_framework.export_compliance_report(report, "json")
            
            with open(filename, 'w') as f:
                f.write(json_report)
            
            print(f"  Full report saved to: {filename}")
        
        except Exception as e:
            print(f"Compliance report generation failed: {e}")
    
    async def show_status(self, args):
        """Show system status and statistics."""
        try:
            stats = get_stats()
            
            print("PurgeProof System Status")
            print("=" * 30)
            print(f"Total Jobs: {stats['total_jobs']}")
            print(f"Completed Jobs: {stats['completed_jobs']}")
            print(f"Failed Jobs: {stats['failed_jobs']}")
            print(f"Total Bytes Processed: {stats['total_bytes_processed']:,}")
            
            if 'active_jobs' in stats:
                print(f"Active Jobs: {len(stats['active_jobs'])}")
                
                for job_id in stats['active_jobs']:
                    job_status = self.orchestrator.get_job_status(job_id)
                    if job_status:
                        print(f"  {job_id}: {job_status.get('status', 'unknown')} ({job_status.get('progress', 0)}%)")
            
            print(f"\nNative Engine: {'Available' if stats.get('native_engine_available', False) else 'Using Fallback'}")
            
        except Exception as e:
            print(f"Error getting status: {e}")
            return 1
        
        return 0
    
    def run(self):
        """Main CLI entry point."""
        parser = argparse.ArgumentParser(
            description="PurgeProof - Enterprise Data Sanitization Tool",
            epilog="For detailed help on commands, use: purgeproof <command> --help"
        )
        
        parser.add_argument('--version', action='version', version='PurgeProof 2.1.0')
        parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        parser.add_argument('--config', help='Configuration file path')
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # List devices command
        list_parser = subparsers.add_parser('list', help='List available storage devices')
        list_parser.set_defaults(func=self.list_devices)
        
        # Analyze device command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze device and recommend method')
        analyze_parser.add_argument('device', help='Device path to analyze')
        analyze_parser.add_argument('--compliance', default='standard', 
                                  choices=['basic', 'standard', 'enhanced', 'classified', 'top_secret'],
                                  help='Required compliance level')
        analyze_parser.add_argument('--objective', default='balanced',
                                  choices=['speed', 'security', 'compliance', 'balanced'],
                                  help='Primary security objective')
        analyze_parser.set_defaults(func=self.analyze_device)
        
        # Sanitize command
        sanitize_parser = subparsers.add_parser('sanitize', help='Sanitize a device')
        sanitize_parser.add_argument('device', help='Device path to sanitize')
        sanitize_parser.add_argument('--method', 
                                   choices=['crypto_erase', 'secure_erase', 'nvme_sanitize', 
                                          'trim_discard', 'overwrite_single', 'overwrite_multi'],
                                   help='Specific sanitization method to use')
        sanitize_parser.add_argument('--compliance', default='standard',
                                   choices=['basic', 'standard', 'enhanced', 'classified', 'top_secret'],
                                   help='Required compliance level')
        sanitize_parser.add_argument('--objective', default='balanced',
                                   choices=['speed', 'security', 'compliance', 'balanced'],
                                   help='Primary security objective')
        sanitize_parser.add_argument('--verify', action='store_true', 
                                   help='Perform verification after sanitization')
        sanitize_parser.add_argument('--compliance-report', choices=['summary', 'full'],
                                   help='Generate compliance report')
        sanitize_parser.add_argument('--force', action='store_true',
                                   help='Skip confirmation prompts')
        sanitize_parser.set_defaults(func=self.sanitize_device)
        
        # Status command
        status_parser = subparsers.add_parser('status', help='Show system status and statistics')
        status_parser.set_defaults(func=self.show_status)
        
        args = parser.parse_args()
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        if not args.command:
            parser.print_help()
            return 1
        
        try:
            return asyncio.run(args.func(args))
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            return 1
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

def main():
    """Main entry point."""
    cli = PurgeProofCLI()
    return cli.run()

if __name__ == "__main__":
    sys.exit(main())