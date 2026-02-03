"""
ConnectU Security Module
Encoding Techniques Implementation
"""

import base64
from io import BytesIO

# QR code is optional - install separately if needed
try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

from PIL import Image



class EncodingService:
    """
    Handles encoding and decoding operations
    
    Encoding Techniques Used:
    1. Base64 - For image/file data transfer
    2. QR Code - For 2FA setup and data sharing
    
    Security Considerations:
    - Base64 is NOT encryption - it's encoding for data transfer
    - Always use TLS/HTTPS for transport security
    - Validate all decoded data before use
    """
    
    @staticmethod
    def encode_base64(data):
        """
        Encode data to Base64
        Used for image uploads and binary data transfer
        
        Args:
            data: bytes or string to encode
        
        Returns:
            Base64 encoded string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encoded = base64.b64encode(data)
        return encoded.decode('utf-8')
    
    @staticmethod
    def decode_base64(encoded_data):
        """
        Decode Base64 data
        
        Args:
            encoded_data: Base64 encoded string
        
        Returns:
            Decoded bytes
        """
        return base64.b64decode(encoded_data)
    
    @staticmethod
    def encode_image_to_base64(image_bytes, mime_type='image/jpeg'):
        """
        Encode image to Base64 data URI
        
        Args:
            image_bytes: Image file bytes
            mime_type: MIME type of image (image/jpeg, image/png, etc.)
        
        Returns:
            Data URI string (data:image/jpeg;base64,...)
        """
        encoded = EncodingService.encode_base64(image_bytes)
        return f"data:{mime_type};base64,{encoded}"
    
    @staticmethod
    def resize_image_if_needed(image_bytes, max_size=(2048, 2048), quality=85):
        """
        Resize image if it exceeds maximum dimensions for optimization
        
        Args:
            image_bytes: Raw image file bytes
            max_size: Tuple (width, height)
            quality: JPEG quality (1-95)
            
        Returns:
            Compressed/resized image bytes
        """
        try:
            img = Image.open(BytesIO(image_bytes))
            
            # Convert to RGB if necessary (e.g. for PNG/RGBA to JPEG)
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')
            
            # Check dimensions
            width, height = img.size
            if width > max_size[0] or height > max_size[1]:
                # Maintain aspect ratio
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                buffer = BytesIO()
                img.save(buffer, format='JPEG', quality=quality, optimize=True)
                return buffer.getvalue()
            
            # Even if not resizing, optimize for JPEG storage if large
            if len(image_bytes) > 512 * 1024:  # > 512KB
                buffer = BytesIO()
                img.save(buffer, format='JPEG', quality=quality, optimize=True)
                return buffer.getvalue()
                
            return image_bytes
        except Exception as e:
            print(f"Image resize failed: {e}")
            return image_bytes
    
    @staticmethod
    def decode_image_from_base64(data_uri):
        """
        Decode Base64 data URI to image bytes
        
        Args:
            data_uri: Data URI string (data:image/jpeg;base64,...)
        
        Returns:
            (image_bytes, mime_type)
        """
        # Remove data:image/jpeg;base64, prefix
        if ',' in data_uri:
            header, encoded = data_uri.split(',', 1)
            # Extract MIME type
            if ';' in header:
                mime_type = header.split(';')[0].replace('data:', '')
            else:
                mime_type = 'image/jpeg'
        else:
            encoded = data_uri
            mime_type = 'image/jpeg'
        
        # Decode
        image_bytes = EncodingService.decode_base64(encoded)
        return image_bytes, mime_type
    
    @staticmethod
    def generate_qr_code(data, size=10, border=4):
        """
        Generate QR code for data
        Used for 2FA setup and sharing profiles
        
        Args:
            data: String data to encode
            size: Box size (pixels per module)
            border: Border size (modules)
        
        Returns:
            Base64 encoded QR code image (PNG)
        """
        if not HAS_QRCODE:
            raise ImportError("qrcode library not available. Install with: pip install qrcode[pil]")
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,  # Auto size
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=size,
            border=border,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_bytes = buffer.getvalue()
        
        # Encode to Base64
        return EncodingService.encode_image_to_base64(img_bytes, 'image/png')
    
    @staticmethod
    def url_safe_encode(data):
        """
        URL-safe Base64 encoding
        Used for tokens and URL parameters
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encoded = base64.urlsafe_b64encode(data)
        return encoded.decode('utf-8').rstrip('=')  # Remove padding
    
    @staticmethod
    def url_safe_decode(encoded_data):
        """
        URL-safe Base64 decoding
        """
        # Add padding if needed
        padding = 4 - (len(encoded_data) % 4)
        if padding != 4:
            encoded_data += '=' * padding
        
        return base64.urlsafe_b64decode(encoded_data)


class EncodingSecurity:
    """
    Documentation of encoding security levels and risks
    """
    
    @staticmethod
    def get_security_info():
        """
        Return security information about encoding techniques
        """
        return {
            'Base64': {
                'security_level': 'Low',
                'purpose': 'Data encoding for transfer, NOT encryption',
                'strengths': [
                    'Simple and fast',
                    'Widely supported',
                    'Good for binary data in text protocols',
                    'Reversible without key'
                ],
                'weaknesses': [
                    'NOT a security mechanism',
                    'Data is easily decoded',
                    'Increases data size by ~33%',
                    'No integrity protection'
                ],
                'use_cases': [
                    'Image data in HTML/JSON',
                    'Email attachments (MIME)',
                    'Embedding binary in text',
                    'URL-safe tokens'
                ],
                'attacks': [
                    'Direct decoding - anyone can decode Base64',
                    'Injection attacks if not validated',
                    'Buffer overflow if size not checked'
                ],
                'mitigations': [
                    'Always use HTTPS for transport',
                    'Validate decoded data',
                    'Limit maximum size',
                    'Combine with encryption for sensitive data'
                ]
            },
            'QR Code': {
                'security_level': 'Low to Medium',
                'purpose': 'Visual encoding for easy scanning',
                'strengths': [
                    'Easy to scan with camera',
                    'Error correction built-in',
                    'Fast authentication setup',
                    'No typing required'
                ],
                'weaknesses': [
                    'Visible to anyone who can see it',
                    'Can be photographed/copied',
                    'Limited data capacity',
                    'No built-in authentication'
                ],
                'use_cases': [
                    '2FA setup (TOTP secret)',
                    'Profile sharing',
                    'URL sharing',
                    'Payment information'
                ],
                'attacks': [
                    'QR code replacement (phishing)',
                    'Shoulder surfing',
                    'Man-in-the-middle during setup',
                    'Malicious QR codes'
                ],
                'mitigations': [
                    'Display over secure channel',
                    'One-time use QR codes',
                    'Verify destination before scanning',
                    'Use short expiration times',
                    'SSL pinning for sensitive operations'
                ]
            },
            'NIST_Guidelines': {
                'recommendations': [
                    'Use TLS 1.2+ for all data transport',
                    'Encoding is NOT encryption - use proper crypto for confidentiality',
                    'Validate all inputs after decoding',
                    'Implement rate limiting to prevent abuse',
                    'Log security-relevant encoding operations'
                ]
            }
        }
    
    @staticmethod
    def get_comparison_table():
        """Return comparison of encoding vs encryption"""
        return """
        +------------------+------------------+------------------+
        |   Technique      |   Security       |   Use Case       |
        +------------------+------------------+------------------+
        | Base64           | No Security      | Data Transfer    |
        | URL Encoding     | No Security      | URL Parameters   |
        | QR Code          | No Security      | Visual Sharing   |
        +------------------+------------------+------------------+
        | AES Encryption   | High Security    | Confidentiality  |
        | RSA Encryption   | High Security    | Key Exchange     |
        | SHA-256 Hash     | Medium Security  | Integrity        |
        +------------------+------------------+------------------+
        
        IMPORTANT: Encoding ≠ Encryption
        - Encoding transforms data format (reversible, no key)
        - Encryption protects data confidentiality (requires key)
        """
