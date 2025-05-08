"""
Image Forensics Module - Digital Forensics Project
This module handles image-specific forensics including EXIF data extraction and analysis
"""

import os
import logging
from PIL import Image, ExifTags
import PIL
import datetime
import re

class ImageForensics:
    def __init__(self, image_path):
        """Initialize with the path to the image for analysis"""
        self.image_path = image_path
        self.image_exists = os.path.exists(image_path)
        self.results = {}
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("ImageForensics")
        
    def analyze_image(self):
        """Main analysis method that calls all other analysis functions"""
        if not self.image_exists:
            self.logger.error(f"Image not found: {self.image_path}")
            return {"error": "Image not found"}
        
        try:
            # Try to open and verify it's an image
            img = Image.open(self.image_path)
            img.verify()  # Verify it's a valid image
            
            # Re-open as verify() closes the file
            img = Image.open(self.image_path)
            
            self.results["image_info"] = self.get_image_info(img)
            self.results["exif_data"] = self.extract_exif_data(img)
            self.results["gps_data"] = self.extract_gps_data(img)
            self.results["manipulation_indicators"] = self.check_manipulation_indicators(img)
            
            return self.results
            
        except (IOError, SyntaxError) as e:
            self.logger.error(f"Not a valid image or corrupted: {str(e)}")
            return {
                "error": f"Not a valid image or corrupted: {str(e)}",
                "valid_image": False
            }
    
    def get_image_info(self, img):
        """Extract basic image information"""
        return {
            "format": img.format,
            "mode": img.mode,
            "size": {
                "width": img.width,
                "height": img.height,
                "resolution": f"{img.width}x{img.height}"
            },
            "color_mode": self.get_color_mode(img.mode),
            "bits_per_pixel": self.get_bits_per_pixel(img.mode)
        }
    
    def extract_exif_data(self, img):
        """Extract and process EXIF metadata"""
        exif_data = {}
        
        try:
            # Get raw EXIF data
            raw_exif = img._getexif()
            
            if not raw_exif:
                return {"status": "No EXIF data found"}
                
            # Process EXIF data with known tags
            for tag_id, value in raw_exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                
                # Format datetime values
                if tag in ['DateTimeOriginal', 'DateTimeDigitized', 'DateTime']:
                    exif_data[tag] = str(value)
                # Format camera make/model
                elif tag in ['Make', 'Model', 'Software']:
                    exif_data[tag] = str(value)
                # Handle thumbnail data differently
                elif tag == 'UserComment':
                    try:
                        exif_data[tag] = value.decode('utf-8').strip('\x00')
                    except:
                        exif_data[tag] = "Binary data"
                # For binary data
                elif isinstance(value, bytes):
                    exif_data[tag] = "Binary data"
                else:
                    exif_data[tag] = value
            
            # Add analysis of software used
            if 'Software' in exif_data:
                exif_data['SoftwareAnalysis'] = self.analyze_software_info(exif_data['Software'])
            
            # Check for metadata inconsistencies
            exif_data['Inconsistencies'] = self.check_exif_inconsistencies(exif_data)
            
            return exif_data
            
        except (AttributeError, KeyError, IndexError, TypeError) as e:
            self.logger.error(f"Error extracting EXIF data: {str(e)}")
            return {"error": f"Error extracting EXIF data: {str(e)}"}
    
    def extract_gps_data(self, img):
        """Extract and process GPS coordinates from EXIF if available"""
        try:
            raw_exif = img._getexif()
            if not raw_exif:
                return {"status": "No EXIF data found"}
                
            gps_info = {}
            
            # Check if GPS data exists
            for tag_id, value in raw_exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag == 'GPSInfo':
                    # Process GPS data
                    for gps_tag_id, gps_value in value.items():
                        gps_tag = ExifTags.GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_info[gps_tag] = gps_value
                    
                    # Calculate decimal coordinates if available
                    if 'GPSLatitude' in gps_info and 'GPSLatitudeRef' in gps_info and \
                       'GPSLongitude' in gps_info and 'GPSLongitudeRef' in gps_info:
                        
                        lat = self.convert_to_decimal(gps_info['GPSLatitude'], gps_info['GPSLatitudeRef'])
                        lon = self.convert_to_decimal(gps_info['GPSLongitude'], gps_info['GPSLongitudeRef'])
                        
                        gps_info['DecimalCoordinates'] = {
                            'latitude': lat,
                            'longitude': lon,
                            'google_maps_url': f"https://www.google.com/maps?q={lat},{lon}"
                        }
                    
                    return gps_info
            
            return {"status": "No GPS data found"}
            
        except (AttributeError, KeyError, IndexError, TypeError) as e:
            self.logger.error(f"Error extracting GPS data: {str(e)}")
            return {"error": f"Error extracting GPS data: {str(e)}"}
    
    def check_manipulation_indicators(self, img):
        """Check for potential image manipulation indicators"""
        indicators = {}
        
        # Check for thumbnail-main image inconsistency
        try:
            raw_exif = img._getexif()
            if raw_exif and 'ThumbnailImage' in raw_exif:
                # Try to create thumbnail from main image
                thumb_size = (160, 120)  # Standard thumbnail size
                img.thumbnail(thumb_size)
                # Compare with EXIF thumbnail (simplified check)
                indicators['thumbnail_mismatch'] = "Thumbnail analysis could not be performed in detail"
        except Exception as e:
            indicators['thumbnail_error'] = str(e)
        
        # Check for editing software traces
        exif_data = self.results.get('exif_data', {})
        if 'Software' in exif_data:
            software = exif_data['Software']
            if any(editor in software for editor in ['Photoshop', 'GIMP', 'Lightroom', 'Illustrator']):
                indicators['editing_software_detected'] = software
        
        # Check for discrete cosine transform (DCT) artifacts in JPEG
        if img.format == 'JPEG':
            indicators['compression_analysis'] = "Basic JPEG compression analysis would require more specialized libraries"
        
        # Color filter array (CFA) artifacts check
        indicators['cfa_analysis'] = "CFA artifact analysis requires specialized algorithms"
        
        # Basic error level analysis indication
        indicators['error_level_analysis'] = "Error Level Analysis (ELA) requires specialized processing"
        
        return indicators
    
    @staticmethod
    def convert_to_decimal(dms, ref):
        """Convert GPS coordinates from DMS (degrees, minutes, seconds) to decimal format"""
        degrees = dms[0]
        minutes = dms[1] / 60.0
        seconds = dms[2] / 3600.0
        
        decimal = degrees + minutes + seconds
        
        if ref in ['S', 'W']:
            decimal = -decimal
            
        return decimal
    
    @staticmethod
    def get_color_mode(mode):
        """Get a description of the image color mode"""
        mode_descriptions = {
            '1': 'Bilevel (black and white)',
            'L': 'Grayscale',
            'P': 'Palette-mapped',
            'RGB': 'True color RGB',
            'RGBA': 'True color with transparency',
            'CMYK': 'Pre-press CMYK',
            'YCbCr': 'Video format',
            'LAB': 'CIE Lab color space',
            'HSV': 'Hue, Saturation, Value color space',
            'I': 'Integer pixels',
            'F': 'Float pixels'
        }
        
        return mode_descriptions.get(mode, f"Unknown mode: {mode}")
    
    @staticmethod
    def get_bits_per_pixel(mode):
        """Calculate bits per pixel based on image mode"""
        bits_map = {
            '1': 1,
            'L': 8,
            'P': 8,
            'RGB': 24,
            'RGBA': 32,
            'CMYK': 32,
            'YCbCr': 24,
            'I': 32,
            'F': 32
        }
        
        return bits_map.get(mode, 0)
    
    @staticmethod
    def analyze_software_info(software_string):
        """Analyze software information for potential editing traces"""
        software_analysis = {}
        
        # Check for common editing software
        editing_software = {
            'photoshop': 'Adobe Photoshop',
            'lightroom': 'Adobe Lightroom',
            'gimp': 'GIMP',
            'illustrator': 'Adobe Illustrator',
            'inkscape': 'Inkscape',
            'corel': 'CorelDRAW',
            'affinity': 'Affinity',
            'paintshop': 'PaintShop',
            'pixelmator': 'Pixelmator'
        }
        
        software_lower = software_string.lower()
        
        for key, name in editing_software.items():
            if key in software_lower:
                software_analysis['editing_software_detected'] = name
                break
        
        # Try to extract version information
        version_pattern = r'(\d+\.?\d*\.?\d*)'
        version_match = re.search(version_pattern, software_string)
        if version_match:
            software_analysis['version'] = version_match.group(1)
        
        return software_analysis
    
    @staticmethod
    def check_exif_inconsistencies(exif_data):
        """Check for potential inconsistencies in EXIF data"""
        inconsistencies = []
        
        # Check date inconsistencies
        date_fields = ['DateTimeOriginal', 'DateTimeDigitized', 'DateTime']
        date_values = []
        
        for field in date_fields:
            if field in exif_data:
                date_values.append((field, exif_data[field]))
        
        # If we have multiple date fields, check for inconsistencies
        if len(date_values) > 1:
            for i in range(len(date_values) - 1):
                for j in range(i + 1, len(date_values)):
                    if date_values[i][1] != date_values[j][1]:
                        inconsistencies.append(f"Date inconsistency: {date_values[i][0]}={date_values[i][1]} vs {date_values[j][0]}={date_values[j][1]}")
        
        # Check if Make and Model are consistent
        if 'Make' in exif_data and 'Model' in exif_data:
            if exif_data['Make'] not in exif_data['Model'] and not any(make in exif_data['Model'].lower() for make in exif_data['Make'].lower().split()):
                inconsistencies.append(f"Make/Model inconsistency: Make={exif_data['Make']}, Model={exif_data['Model']}")
        
        return inconsistencies if inconsistencies else "No obvious inconsistencies detected"

if __name__ == "__main__":
    # Example usage
    image_path = "sample.jpg"
    analyzer = ImageForensics(image_path)
    results = analyzer.analyze_image()
    print(results)
