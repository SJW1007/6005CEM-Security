"""
CAPTCHA utility functions for generating and validating CAPTCHA challenges.
Provides image-based CAPTCHA generation for Tkinter applications.
"""

import random
import string
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import hashlib
import time


def generate_captcha_text(length: int = 5) -> str:
    """
    Generate a random CAPTCHA text string.
    
    Args:
        length: Length of the CAPTCHA text (default: 5)
        
    Returns:
        Random string of uppercase letters and digits
    """
    # Use uppercase letters and digits, excluding confusing characters
    chars = string.ascii_uppercase.replace('O', '').replace('I', '') + string.digits.replace('0', '').replace('1', '')
    return ''.join(random.choice(chars) for _ in range(length))


def generate_captcha_image(text: str, width: int = 150, height: int = 50) -> BytesIO:
    """
    Generate a CAPTCHA image with the given text.
    
    Args:
        text: The text to display in the CAPTCHA
        width: Image width in pixels (default: 150)
        height: Image height in pixels (default: 50)
        
    Returns:
        BytesIO object containing the PNG image data
    """
    # Create image with white background
    image = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(image)
    
    # Try to use a font, fallback to default if not available
    try:
        # Try common system fonts
        font_size = 24
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            try:
                font = ImageFont.truetype("C:/Windows/Fonts/arial.ttf", font_size)
            except:
                font = ImageFont.load_default()
    except:
        font = ImageFont.load_default()
    
    # Draw text with random positioning and rotation
    char_width = width // len(text)
    for i, char in enumerate(text):
        # Random position for each character
        x = i * char_width + random.randint(5, 15)
        y = random.randint(5, height - 25)
        
        # Random rotation
        angle = random.randint(-20, 20)
        
        # Create a temporary image for rotated text
        temp_img = Image.new('RGBA', (char_width, height), (255, 255, 255, 0))
        temp_draw = ImageDraw.Draw(temp_img)
        
        # Random color for each character
        color = (
            random.randint(0, 100),
            random.randint(0, 100),
            random.randint(0, 100)
        )
        
        temp_draw.text((0, y - 5), char, fill=color, font=font)
        rotated = temp_img.rotate(angle, expand=False)
        image.paste(rotated, (x, 0), rotated)
    
    # Add noise lines
    for _ in range(random.randint(3, 6)):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=(200, 200, 200), width=1)
    
    # Add noise dots
    for _ in range(random.randint(50, 100)):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(random.randint(150, 255), random.randint(150, 255), random.randint(150, 255)))
    
    # Save to BytesIO
    img_bytes = BytesIO()
    image.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    return img_bytes


def create_captcha_hash(text: str, timestamp: float, secret: str = "captcha_secret") -> str:
    """
    Create a hash for CAPTCHA validation to prevent tampering.
    
    Args:
        text: The CAPTCHA text
        timestamp: Timestamp when CAPTCHA was created
        secret: Secret key for hashing (default: "captcha_secret")
        
    Returns:
        SHA256 hash string
    """
    data = f"{text}:{timestamp}:{secret}"
    return hashlib.sha256(data.encode()).hexdigest()


def verify_captcha_hash(text: str, timestamp: float, hash_value: str, secret: str = "captcha_secret", max_age: int = 300) -> bool:
    """
    Verify a CAPTCHA hash and check if it's still valid (not expired).
    
    Args:
        text: The CAPTCHA text to verify
        timestamp: Timestamp when CAPTCHA was created
        hash_value: The hash to verify against
        secret: Secret key for hashing (default: "captcha_secret")
        max_age: Maximum age in seconds (default: 300 = 5 minutes)
        
    Returns:
        True if valid and not expired, False otherwise
    """
    # Check if expired
    if time.time() - timestamp > max_age:
        return False
    
    # Verify hash
    expected_hash = create_captcha_hash(text, timestamp, secret)
    return hash_value == expected_hash


