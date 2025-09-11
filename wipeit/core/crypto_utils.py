"""
Cryptographic Utilities Module

This module provides cryptographic utilities for PurgeProof, including:
- Digital signatures for certificates and verification
- Key generation and management
- Hashing and integrity verification
- Certificate validation and trust chains

All cryptographic operations follow industry best practices and use
well-established algorithms (RSA-2048/4096, ECDSA P-256/P-384, SHA-256/SHA-3).
"""

import os
import sys
import time
import json
import base64
import hashlib
import logging
import datetime
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    from cryptography.hazmat.backends import default_backend
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import cryptography
except ImportError:
    cryptography = None

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class KeyPair:
    """Cryptographic key pair container."""
    private_key: Any  # Private key object
    public_key: Any   # Public key object
    algorithm: str    # "RSA" or "ECDSA"
    key_size: int     # Key size in bits
    created_at: float # Unix timestamp
    key_id: str       # Unique identifier


@dataclass
class DigitalSignature:
    """Digital signature container."""
    signature: bytes
    algorithm: str
    hash_algorithm: str
    public_key_id: str
    timestamp: float
    data_hash: str


class CryptoManager:
    """
    Cryptographic operations manager for PurgeProof.
    
    Handles key generation, digital signatures, and certificate validation
    for tamper-proof wipe certificates.
    """
    
    def __init__(self, key_storage_path: Optional[str] = None):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        if not cryptography:
            raise ImportError("cryptography library is required but not installed")
        
        # Key storage configuration
        self.key_storage_path = Path(key_storage_path or self._get_default_key_path())
        self.key_storage_path.mkdir(parents=True, exist_ok=True)
        
        # Supported algorithms and parameters
        self.supported_algorithms = {
            "RSA-2048": {"algorithm": "RSA", "key_size": 2048},
            "RSA-4096": {"algorithm": "RSA", "key_size": 4096},
            "ECDSA-P256": {"algorithm": "ECDSA", "curve": "secp256r1"},
            "ECDSA-P384": {"algorithm": "ECDSA", "curve": "secp384r1"}
        }
        
        # Default algorithm for new keys
        self.default_algorithm = "RSA-2048"
        
        # Certificate validity period (days)
        self.cert_validity_days = 365 * 5  # 5 years
        
        # Load or generate master key pair
        self.master_key_pair = self._load_or_generate_master_key()
    
    def _get_default_key_path(self) -> str:
        """Get default key storage path based on platform."""
        if sys.platform == "win32":
            # Windows: Use AppData
            app_data = os.environ.get("APPDATA", os.path.expanduser("~"))
            return os.path.join(app_data, "PurgeProof", "keys")
        else:
            # Unix-like: Use XDG config directory
            config_home = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
            return os.path.join(config_home, "purgeproof", "keys")
    
    def _load_or_generate_master_key(self) -> KeyPair:
        """Load existing master key or generate a new one."""
        master_key_file = self.key_storage_path / "master_key.pem"
        
        if master_key_file.exists():
            try:
                return self._load_key_pair("master_key")
            except Exception as e:
                self.logger.warning(f"Failed to load existing master key: {e}")
                self.logger.info("Generating new master key")
        
        # Generate new master key
        return self.generate_key_pair("master_key", self.default_algorithm)
    
    def generate_key_pair(self, key_id: str, algorithm: Optional[str] = None) -> KeyPair:
        """
        Generate a new cryptographic key pair.
        
        Args:
            key_id: Unique identifier for the key pair
            algorithm: Algorithm to use (e.g., "RSA-2048", "ECDSA-P256")
        
        Returns:
            KeyPair object containing the generated keys
        """
        try:
            algorithm = algorithm or self.default_algorithm
            
            if algorithm not in self.supported_algorithms:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            algo_config = self.supported_algorithms[algorithm]
            
            self.logger.info(f"Generating {algorithm} key pair: {key_id}")
            
            # Generate key pair based on algorithm
            if algo_config["algorithm"] == "RSA":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=algo_config["key_size"],
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                key_size = algo_config["key_size"]
            
            elif algo_config["algorithm"] == "ECDSA":
                if algo_config["curve"] == "secp256r1":
                    curve = ec.SECP256R1()
                    key_size = 256
                elif algo_config["curve"] == "secp384r1":
                    curve = ec.SECP384R1()
                    key_size = 384
                else:
                    raise ValueError(f"Unsupported curve: {algo_config['curve']}")
                
                private_key = ec.generate_private_key(curve, default_backend())
                public_key = private_key.public_key()
            
            else:
                raise ValueError(f"Unsupported algorithm type: {algo_config['algorithm']}")
            
            # Create key pair object
            key_pair = KeyPair(
                private_key=private_key,
                public_key=public_key,
                algorithm=algorithm,
                key_size=key_size,
                created_at=time.time(),
                key_id=key_id
            )
            
            # Save key pair to storage
            self._save_key_pair(key_pair)
            
            self.logger.info(f"Successfully generated {algorithm} key pair: {key_id}")
            return key_pair
        
        except Exception as e:
            self.logger.error(f"Error generating key pair: {e}")
            raise
    
    def _save_key_pair(self, key_pair: KeyPair) -> None:
        """Save key pair to persistent storage."""
        try:
            # Save private key
            private_pem = key_pair.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            private_key_file = self.key_storage_path / f"{key_pair.key_id}_private.pem"
            with open(private_key_file, 'wb') as f:
                f.write(private_pem)
            
            # Save public key
            public_pem = key_pair.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            public_key_file = self.key_storage_path / f"{key_pair.key_id}_public.pem"
            with open(public_key_file, 'wb') as f:
                f.write(public_pem)
            
            # Save metadata
            metadata = {
                "key_id": key_pair.key_id,
                "algorithm": key_pair.algorithm,
                "key_size": key_pair.key_size,
                "created_at": key_pair.created_at
            }
            
            metadata_file = self.key_storage_path / f"{key_pair.key_id}_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Set restrictive permissions (Unix-like systems)
            if hasattr(os, 'chmod'):
                os.chmod(private_key_file, 0o600)  # Read/write for owner only
                os.chmod(public_key_file, 0o644)   # Read for all, write for owner
                os.chmod(metadata_file, 0o644)
        
        except Exception as e:
            self.logger.error(f"Error saving key pair: {e}")
            raise
    
    def _load_key_pair(self, key_id: str) -> KeyPair:
        """Load key pair from persistent storage."""
        try:
            # Load metadata
            metadata_file = self.key_storage_path / f"{key_id}_metadata.json"
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            # Load private key
            private_key_file = self.key_storage_path / f"{key_id}_private.pem"
            with open(private_key_file, 'rb') as f:
                private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
            
            # Load public key
            public_key_file = self.key_storage_path / f"{key_id}_public.pem"
            with open(public_key_file, 'rb') as f:
                public_key = load_pem_public_key(f.read(), backend=default_backend())
            
            return KeyPair(
                private_key=private_key,
                public_key=public_key,
                algorithm=metadata["algorithm"],
                key_size=metadata["key_size"],
                created_at=metadata["created_at"],
                key_id=key_id
            )
        
        except Exception as e:
            self.logger.error(f"Error loading key pair {key_id}: {e}")
            raise
    
    def list_key_pairs(self) -> List[str]:
        """List all available key pair IDs."""
        try:
            key_ids = set()
            
            for file_path in self.key_storage_path.glob("*_metadata.json"):
                key_id = file_path.stem.replace("_metadata", "")
                key_ids.add(key_id)
            
            return sorted(list(key_ids))
        
        except Exception as e:
            self.logger.error(f"Error listing key pairs: {e}")
            return []
    
    def delete_key_pair(self, key_id: str) -> bool:
        """Delete a key pair from storage."""
        try:
            files_to_delete = [
                self.key_storage_path / f"{key_id}_private.pem",
                self.key_storage_path / f"{key_id}_public.pem",
                self.key_storage_path / f"{key_id}_metadata.json"
            ]
            
            deleted_count = 0
            for file_path in files_to_delete:
                if file_path.exists():
                    file_path.unlink()
                    deleted_count += 1
            
            if deleted_count > 0:
                self.logger.info(f"Deleted key pair: {key_id}")
                return True
            else:
                self.logger.warning(f"Key pair not found: {key_id}")
                return False
        
        except Exception as e:
            self.logger.error(f"Error deleting key pair {key_id}: {e}")
            return False
    
    def sign_data(self, data: Union[str, bytes], key_pair: Optional[KeyPair] = None, 
                  hash_algorithm: str = "SHA-256") -> DigitalSignature:
        """
        Create a digital signature for data.
        
        Args:
            data: Data to sign (string or bytes)
            key_pair: Key pair to use for signing (uses master key if None)
            hash_algorithm: Hash algorithm to use
        
        Returns:
            DigitalSignature object
        """
        try:
            key_pair = key_pair or self.master_key_pair
            
            # Convert data to bytes if needed
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Calculate data hash
            if hash_algorithm == "SHA-256":
                hash_obj = hashes.SHA256()
                hasher = hashlib.sha256()
            elif hash_algorithm == "SHA-3":
                hash_obj = hashes.SHA3_256()
                hasher = hashlib.sha3_256()
            else:
                raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
            
            hasher.update(data_bytes)
            data_hash = hasher.hexdigest()
            
            # Create signature
            if "RSA" in key_pair.algorithm:
                signature = key_pair.private_key.sign(
                    data_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hash_obj),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_obj
                )
            elif "ECDSA" in key_pair.algorithm:
                signature = key_pair.private_key.sign(data_bytes, ec.ECDSA(hash_obj))
            else:
                raise ValueError(f"Unsupported signature algorithm: {key_pair.algorithm}")
            
            return DigitalSignature(
                signature=signature,
                algorithm=key_pair.algorithm,
                hash_algorithm=hash_algorithm,
                public_key_id=key_pair.key_id,
                timestamp=time.time(),
                data_hash=data_hash
            )
        
        except Exception as e:
            self.logger.error(f"Error signing data: {e}")
            raise
    
    def verify_signature(self, data: Union[str, bytes], signature: DigitalSignature, 
                        public_key: Optional[Any] = None) -> bool:
        """
        Verify a digital signature.
        
        Args:
            data: Original data that was signed
            signature: DigitalSignature object to verify
            public_key: Public key to use for verification (loads from storage if None)
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Load public key if not provided
            if public_key is None:
                if signature.public_key_id == self.master_key_pair.key_id:
                    public_key = self.master_key_pair.public_key
                else:
                    key_pair = self._load_key_pair(signature.public_key_id)
                    public_key = key_pair.public_key
            
            # Convert data to bytes if needed
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Verify data hash
            if signature.hash_algorithm == "SHA-256":
                hash_obj = hashes.SHA256()
                hasher = hashlib.sha256()
            elif signature.hash_algorithm == "SHA-3":
                hash_obj = hashes.SHA3_256()
                hasher = hashlib.sha3_256()
            else:
                raise ValueError(f"Unsupported hash algorithm: {signature.hash_algorithm}")
            
            hasher.update(data_bytes)
            calculated_hash = hasher.hexdigest()
            
            if calculated_hash != signature.data_hash:
                self.logger.warning("Data hash mismatch during signature verification")
                return False
            
            # Verify signature
            try:
                if "RSA" in signature.algorithm:
                    public_key.verify(
                        signature.signature,
                        data_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hash_obj),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hash_obj
                    )
                elif "ECDSA" in signature.algorithm:
                    public_key.verify(signature.signature, data_bytes, ec.ECDSA(hash_obj))
                else:
                    raise ValueError(f"Unsupported signature algorithm: {signature.algorithm}")
                
                return True
            
            except Exception:
                # Signature verification failed
                return False
        
        except Exception as e:
            self.logger.error(f"Error verifying signature: {e}")
            return False
    
    def export_public_key(self, key_id: str, format: str = "PEM") -> str:
        """
        Export public key in specified format.
        
        Args:
            key_id: Key pair identifier
            format: Export format ("PEM" or "DER")
        
        Returns:
            Exported public key as string
        """
        try:
            key_pair = self._load_key_pair(key_id)
            
            if format.upper() == "PEM":
                public_bytes = key_pair.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return public_bytes.decode('utf-8')
            
            elif format.upper() == "DER":
                public_bytes = key_pair.public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return base64.b64encode(public_bytes).decode('utf-8')
            
            else:
                raise ValueError(f"Unsupported export format: {format}")
        
        except Exception as e:
            self.logger.error(f"Error exporting public key: {e}")
            raise
    
    def import_public_key(self, public_key_data: str, format: str = "PEM") -> Any:
        """
        Import public key from string data.
        
        Args:
            public_key_data: Public key data as string
            format: Import format ("PEM" or "DER")
        
        Returns:
            Public key object
        """
        try:
            if format.upper() == "PEM":
                public_key = load_pem_public_key(
                    public_key_data.encode('utf-8'),
                    backend=default_backend()
                )
            
            elif format.upper() == "DER":
                der_data = base64.b64decode(public_key_data)
                public_key = serialization.load_der_public_key(
                    der_data,
                    backend=default_backend()
                )
            
            else:
                raise ValueError(f"Unsupported import format: {format}")
            
            return public_key
        
        except Exception as e:
            self.logger.error(f"Error importing public key: {e}")
            raise
    
    def generate_certificate(self, subject_name: str, key_pair: Optional[KeyPair] = None,
                           issuer_key_pair: Optional[KeyPair] = None,
                           validity_days: Optional[int] = None) -> bytes:
        """
        Generate a self-signed X.509 certificate for the key pair.
        
        Args:
            subject_name: Certificate subject name
            key_pair: Key pair for the certificate (uses master key if None)
            issuer_key_pair: Issuer key pair for signing (self-signed if None)
            validity_days: Certificate validity period
        
        Returns:
            X.509 certificate in PEM format
        """
        try:
            key_pair = key_pair or self.master_key_pair
            issuer_key_pair = issuer_key_pair or key_pair  # Self-signed by default
            validity_days = validity_days or self.cert_validity_days
            
            # Create certificate subject
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PurgeProof"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Data Sanitization"),
            ])
            
            # Certificate validity period
            cert_valid_from = datetime.datetime.utcnow()
            cert_valid_to = cert_valid_from + datetime.timedelta(days=validity_days)
            
            # Build certificate
            cert_builder = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key_pair.public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                cert_valid_from
            ).not_valid_after(
                cert_valid_to
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("purgeproof.local"),
                ]),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            
            # Sign certificate
            certificate = cert_builder.sign(issuer_key_pair.private_key, hashes.SHA256(), default_backend())
            
            # Return PEM-encoded certificate
            return certificate.public_bytes(serialization.Encoding.PEM)
        
        except Exception as e:
            self.logger.error(f"Error generating certificate: {e}")
            raise
    
    def hash_data(self, data: Union[str, bytes], algorithm: str = "SHA-256") -> str:
        """
        Calculate hash of data using specified algorithm.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm ("SHA-256", "SHA-3", "SHA-512")
        
        Returns:
            Hexadecimal hash string
        """
        try:
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            if algorithm == "SHA-256":
                hasher = hashlib.sha256()
            elif algorithm == "SHA-3":
                hasher = hashlib.sha3_256()
            elif algorithm == "SHA-512":
                hasher = hashlib.sha512()
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
            hasher.update(data_bytes)
            return hasher.hexdigest()
        
        except Exception as e:
            self.logger.error(f"Error hashing data: {e}")
            raise
    
    def create_tamper_proof_seal(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a tamper-proof seal for certificate data.
        
        Args:
            data: Dictionary containing certificate data
        
        Returns:
            Dictionary with added signature and integrity fields
        """
        try:
            # Serialize data for signing
            data_json = json.dumps(data, sort_keys=True, separators=(',', ':'))
            
            # Create signature
            signature = self.sign_data(data_json)
            
            # Add tamper-proof seal
            sealed_data = data.copy()
            sealed_data.update({
                "integrity": {
                    "data_hash": signature.data_hash,
                    "signature": base64.b64encode(signature.signature).decode('utf-8'),
                    "signature_algorithm": signature.algorithm,
                    "hash_algorithm": signature.hash_algorithm,
                    "signed_by": signature.public_key_id,
                    "signature_timestamp": signature.timestamp,
                    "seal_version": "1.0"
                }
            })
            
            return sealed_data
        
        except Exception as e:
            self.logger.error(f"Error creating tamper-proof seal: {e}")
            raise
    
    def verify_tamper_proof_seal(self, sealed_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verify tamper-proof seal on certificate data.
        
        Args:
            sealed_data: Dictionary with tamper-proof seal
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            if "integrity" not in sealed_data:
                return False, "No integrity seal found"
            
            integrity = sealed_data["integrity"]
            
            # Extract signature information
            signature = DigitalSignature(
                signature=base64.b64decode(integrity["signature"]),
                algorithm=integrity["signature_algorithm"],
                hash_algorithm=integrity["hash_algorithm"],
                public_key_id=integrity["signed_by"],
                timestamp=integrity["signature_timestamp"],
                data_hash=integrity["data_hash"]
            )
            
            # Remove integrity section for verification
            data_copy = sealed_data.copy()
            del data_copy["integrity"]
            
            # Serialize data for verification
            data_json = json.dumps(data_copy, sort_keys=True, separators=(',', ':'))
            
            # Verify signature
            if self.verify_signature(data_json, signature):
                return True, "Seal is valid"
            else:
                return False, "Signature verification failed"
        
        except Exception as e:
            self.logger.error(f"Error verifying tamper-proof seal: {e}")
            return False, f"Verification error: {e}"
    
    def get_public_key_fingerprint(self, key_id: str) -> str:
        """
        Get fingerprint of a public key for identification.
        
        Args:
            key_id: Key pair identifier
        
        Returns:
            SHA-256 fingerprint of the public key
        """
        try:
            key_pair = self._load_key_pair(key_id)
            
            public_bytes = key_pair.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return hashlib.sha256(public_bytes).hexdigest()
        
        except Exception as e:
            self.logger.error(f"Error getting key fingerprint: {e}")
            raise


def main():
    """CLI interface for crypto utilities testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PurgeProof Crypto Utilities Test")
    parser.add_argument("--generate-key", help="Generate new key pair with given ID")
    parser.add_argument("--algorithm", default="RSA-2048", help="Key algorithm")
    parser.add_argument("--list-keys", action="store_true", help="List all key pairs")
    parser.add_argument("--export-key", help="Export public key for given ID")
    parser.add_argument("--sign-file", help="Sign a file")
    parser.add_argument("--verify-file", help="Verify signature of a file")
    parser.add_argument("--signature-file", help="Signature file for verification")
    parser.add_argument("--key-storage", help="Key storage directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")
    
    try:
        # Initialize crypto manager
        crypto_manager = CryptoManager(args.key_storage)
        
        if args.generate_key:
            key_pair = crypto_manager.generate_key_pair(args.generate_key, args.algorithm)
            print(f"Generated {key_pair.algorithm} key pair: {key_pair.key_id}")
            fingerprint = crypto_manager.get_public_key_fingerprint(key_pair.key_id)
            print(f"Public key fingerprint: {fingerprint}")
        
        elif args.list_keys:
            keys = crypto_manager.list_key_pairs()
            print(f"Available key pairs ({len(keys)}):")
            for key_id in keys:
                try:
                    fingerprint = crypto_manager.get_public_key_fingerprint(key_id)
                    print(f"  {key_id}: {fingerprint}")
                except Exception as e:
                    print(f"  {key_id}: Error - {e}")
        
        elif args.export_key:
            public_key_pem = crypto_manager.export_public_key(args.export_key)
            print(f"Public key for {args.export_key}:")
            print(public_key_pem)
        
        elif args.sign_file:
            if not os.path.exists(args.sign_file):
                print(f"File not found: {args.sign_file}")
                return
            
            with open(args.sign_file, 'rb') as f:
                file_data = f.read()
            
            signature = crypto_manager.sign_data(file_data)
            
            # Save signature
            signature_file = args.sign_file + ".sig"
            signature_data = {
                "signature": base64.b64encode(signature.signature).decode('utf-8'),
                "algorithm": signature.algorithm,
                "hash_algorithm": signature.hash_algorithm,
                "public_key_id": signature.public_key_id,
                "timestamp": signature.timestamp,
                "data_hash": signature.data_hash
            }
            
            with open(signature_file, 'w') as f:
                json.dump(signature_data, f, indent=2)
            
            print(f"File signed: {args.sign_file}")
            print(f"Signature saved: {signature_file}")
        
        elif args.verify_file:
            if not os.path.exists(args.verify_file):
                print(f"File not found: {args.verify_file}")
                return
            
            signature_file = args.signature_file or (args.verify_file + ".sig")
            if not os.path.exists(signature_file):
                print(f"Signature file not found: {signature_file}")
                return
            
            # Load file data
            with open(args.verify_file, 'rb') as f:
                file_data = f.read()
            
            # Load signature
            with open(signature_file, 'r') as f:
                signature_data = json.load(f)
            
            signature = DigitalSignature(
                signature=base64.b64decode(signature_data["signature"]),
                algorithm=signature_data["algorithm"],
                hash_algorithm=signature_data["hash_algorithm"],
                public_key_id=signature_data["public_key_id"],
                timestamp=signature_data["timestamp"],
                data_hash=signature_data["data_hash"]
            )
            
            # Verify signature
            is_valid = crypto_manager.verify_signature(file_data, signature)
            print(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")
        
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
