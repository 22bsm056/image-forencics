"""
Deepfake Detection Module - Digital Forensics Project
This module analyzes images for potential deepfake indicators through metadata analysis
"""

import os
import logging
import re
import math
from PIL import Image, ExifTags
import numpy as np

class DeepfakeDetection:
    def __init__(self, image_path):
        """Initialize with the path to the image for analysis"""
        self.image_path = image_path
        self.image_exists = os.path.exists(image_path)
        self.results = {}
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("DeepfakeDetection")
        
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
            
            # Run various detection methods
            self.results["metadata_analysis"] = self.analyze_metadata(img)
            self.results["visual_artifacts"] = self.analyze_visual_artifacts(img)
            self.results["compression_analysis"] = self.analyze_compression(img)
            self.results["noise_analysis"] = self.analyze_noise_patterns(img)
            
            # Overall assessment
            self.results["deepfake_assessment"] = self.assess_deepfake_probability()
            
            return self.results
            
        except (IOError, SyntaxError) as e:
            self.logger.error(f"Not a valid image or corrupted: {str(e)}")
            return {
                "error": f"Not a valid image or corrupted: {str(e)}",
                "valid_image": False
            }
    
    def analyze_metadata(self, img):
        """Analyze image metadata for deepfake indicators"""
        metadata_results = {}
        
        try:
            # Get EXIF data
            exif_data = img._getexif() or {}
            
            # Check for missing metadata that should be present
            metadata_results["missing_exif"] = self.check_missing_exif(exif_data)
            
            # Check for software traces
            metadata_results["software_traces"] = self.check_software_traces(exif_data)
            
            # Check for inconsistent metadata
            metadata_results["metadata_inconsistencies"] = self.check_metadata_inconsistencies(exif_data)
            
            # Overall metadata assessment
            if metadata_results["missing_exif"]["status"] == "suspicious" or \
               metadata_results["software_traces"]["status"] == "suspicious" or \
               metadata_results["metadata_inconsistencies"]["status"] == "suspicious":
                metadata_results["overall_assessment"] = "Suspicious metadata characteristics detected"
                metadata_results["risk_level"] = "High"
            elif metadata_results["missing_exif"]["status"] == "unusual" or \
                 metadata_results["software_traces"]["status"] == "unusual" or \
                 metadata_results["metadata_inconsistencies"]["status"] == "unusual":
                metadata_results["overall_assessment"] = "Some unusual metadata characteristics detected"
                metadata_results["risk_level"] = "Medium"
            else:
                metadata_results["overall_assessment"] = "No suspicious metadata characteristics detected"
                metadata_results["risk_level"] = "Low"
                
            return metadata_results
            
        except Exception as e:
            self.logger.error(f"Error analyzing metadata: {str(e)}")
            return {"error": f"Error analyzing metadata: {str(e)}"}
    
    def check_missing_exif(self, exif_data):
        """Check for suspiciously missing EXIF data"""
        result = {"missing_fields": []}
        
        # Key EXIF fields often present in genuine photos
        key_fields = [
            'Make', 'Model', 'DateTimeOriginal', 'ExposureTime', 
            'FNumber', 'ISOSpeedRatings', 'FocalLength'
        ]
        
        # Check which key fields are missing
        for field in key_fields:
            found = False
            for tag_id, tag_name in ExifTags.TAGS.items():
                if tag_name == field and tag_id in exif_data:
                    found = True
                    break
            
            if not found:
                result["missing_fields"].append(field)
        
        # Assess suspiciousness level
        if len(result["missing_fields"]) >= 5:
            result["status"] = "suspicious"
            result["assessment"] = "Unusually high number of key EXIF fields missing"
        elif len(result["missing_fields"]) >= 3:
            result["status"] = "unusual"
            result["assessment"] = "Several key EXIF fields missing"
        else:
            result["status"] = "normal"
            result["assessment"] = "Normal EXIF field presence"
        
        return result
    
    def check_software_traces(self, exif_data):
        """Check for software traces that might indicate manipulation"""
        result = {"software_detected": "None"}
        
        # Look for Software field
        software = None
        for tag_id, tag_name in ExifTags.TAGS.items():
            if tag_name == 'Software' and tag_id in exif_data:
                software = str(exif_data[tag_id])
                result["software_detected"] = software
                break
        
        # Check for AI generation/editing software traces
        ai_keywords = ['neural', 'gan', 'generative', 'ai', 'deepfake', 'synthesis', 
                     'generated', 'midjourney', 'stable diffusion', 'dall-e']
                     
        editing_software = ['photoshop', 'lightroom', 'gimp', 'affinity', 
                          'illustrator', 'pixelmator', 'paintshop']
        
        if software:
            software_lower = software.lower()
            
            # Check for AI generation traces
            for keyword in ai_keywords:
                if keyword in software_lower:
                    result["status"] = "suspicious"
                    result["assessment"] = f"AI-related software detected: {software}"
                    return result
            
            # Check for editing software
            for editor in editing_software:
                if editor in software_lower:
                    result["status"] = "unusual"
                    result["assessment"] = f"Image editing software detected: {software}"
                    return result
        
        result["status"] = "normal"
        result["assessment"] = "No suspicious software traces detected"
        return result
    
    def check_metadata_inconsistencies(self, exif_data):
        """Check for inconsistencies in metadata that might indicate tampering"""
        result = {"inconsistencies": []}
        
        # Check date inconsistencies
        date_fields = ['DateTimeOriginal', 'DateTimeDigitized', 'DateTime']
        date_values = {}
        
        for tag_id, tag_name in ExifTags.TAGS.items():
            if tag_name in date_fields and tag_id in exif_data:
                date_values[tag_name] = str(exif_data[tag_id])
        
        # If we have multiple date fields, check for inconsistencies
        if len(date_values) > 1:
            dates = list(date_values.values())
            if len(set(dates)) > 1:  # If we have different date values
                result["inconsistencies"].append({
                    "type": "date_mismatch",
                    "details": date_values
                })
        
        # Check for make/model inconsistencies
        make, model = None, None
        for tag_id, tag_name in ExifTags.TAGS.items():
            if tag_name == 'Make' and tag_id in exif_data:
                make = str(exif_data[tag_id])
            elif tag_name == 'Model' and tag_id in exif_data:
                model = str(exif_data[tag_id])
        
        if make and model:
            # Check if make is part of the model name (common in genuine photos)
            if make.lower() not in model.lower() and not any(word in model.lower() for word in make.lower().split()):
                result["inconsistencies"].append({
                    "type": "make_model_mismatch",
                    "details": {"Make": make, "Model": model}
                })
        
        # Assess overall inconsistency
        if len(result["inconsistencies"]) >= 2:
            result["status"] = "suspicious"
            result["assessment"] = "Multiple metadata inconsistencies detected"
        elif len(result["inconsistencies"]) == 1:
            result["status"] = "unusual"
            result["assessment"] = "One metadata inconsistency detected"
        else:
            result["status"] = "normal"
            result["assessment"] = "No metadata inconsistencies detected"
        
        return result
    
    def analyze_visual_artifacts(self, img):
        """Analyze visual artifacts that might indicate a deepfake image"""
        results = {}
        
        try:
            # Convert to numpy array for analysis
            img_array = np.array(img)
            
            # Check for face-related artifacts (basic implementation)
            results["facial_analysis"] = "Detailed facial analysis requires specialized face detection libraries"
            
            # Check for unrealistic details
            results["detail_consistency"] = self.check_detail_consistency(img_array)
            
            # Check for unnatural color distribution
            if img.mode in ['RGB', 'RGBA']:
                results["color_analysis"] = self.analyze_color_distribution(img_array)
            
            # Check for boundary artifacts
            results["boundary_analysis"] = self.check_boundary_artifacts(img_array)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing visual artifacts: {str(e)}")
            return {"error": f"Error analyzing visual artifacts: {str(e)}"}
    
    def check_detail_consistency(self, img_array):
        """Check for inconsistent level of details across the image"""
        result = {}
        
        try:
            # Basic implementation - check variation in high-frequency components
            if len(img_array.shape) >= 2:
                # Calculate horizontal and vertical gradients (simplified edge detection)
                if len(img_array.shape) == 3 and img_array.shape[2] >= 3:
                    # Convert to grayscale if RGB
                    gray = np.mean(img_array[:,:,:3], axis=2)
                else:
                    gray = img_array
                
                # Calculate horizontal and vertical gradients
                h_gradient = np.abs(gray[:, 1:] - gray[:, :-1]).flatten()
                v_gradient = np.abs(gray[1:, :] - gray[:-1, :]).flatten()
                
                # Analyze gradient statistics
                h_mean = np.mean(h_gradient)
                h_std = np.std(h_gradient)
                v_mean = np.mean(v_gradient)
                v_std = np.std(v_gradient)
                
                result["gradient_statistics"] = {
                    "horizontal_mean": float(h_mean),
                    "horizontal_std": float(h_std),
                    "vertical_mean": float(v_mean),
                    "vertical_std": float(v_std)
                }
                
                # Look for unusually smooth areas (potentially AI-generated)
                smooth_ratio = float(np.sum((h_gradient < h_mean/3) & (v_gradient < v_mean/3))) / float(h_gradient.size)
                result["smooth_ratio"] = smooth_ratio
                
                if smooth_ratio > 0.7:
                    result["assessment"] = "Unusually high percentage of smooth areas detected"
                    result["status"] = "suspicious"
                elif smooth_ratio > 0.5:
                    result["assessment"] = "Somewhat higher than normal smooth areas detected"
                    result["status"] = "unusual"
                else:
                    result["assessment"] = "Normal detail distribution"
                    result["status"] = "normal"
            else:
                result["assessment"] = "Cannot analyze detail consistency for this image format"
                result["status"] = "unknown"
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error in detail consistency check: {str(e)}")
            return {"error": f"Error in detail consistency check: {str(e)}"}
    
    def analyze_color_distribution(self, img_array):
        """Analyze color distribution for unnatural patterns"""
        result = {}
        
        try:
            if img_array.shape[2] >= 3:
                # Extract RGB channels
                r = img_array[:,:,0].flatten()
                g = img_array[:,:,1].flatten()
                b = img_array[:,:,2].flatten()
                
                # Calculate basic statistics
                r_mean, r_std = np.mean(r), np.std(r)
                g_mean, g_std = np.mean(g), np.std(g)
                b_mean, b_std = np.mean(b), np.std(b)
                
                result["channel_statistics"] = {
                    "red": {"mean": float(r_mean), "std": float(r_std)},
                    "green": {"mean": float(g_mean), "std": float(g_std)},
                    "blue": {"mean": float(b_mean), "std": float(b_std)}
                }
                
                # Check for anomalies in color distribution
                std_ratio_rg = float(r_std / g_std) if g_std > 0 else 0
                std_ratio_rb = float(r_std / b_std) if b_std > 0 else 0
                std_ratio_gb = float(g_std / b_std) if b_std > 0 else 0
                
                result["color_ratios"] = {
                    "red_green_std_ratio": std_ratio_rg,
                    "red_blue_std_ratio": std_ratio_rb,
                    "green_blue_std_ratio": std_ratio_gb
                }
                
                # Assess unusual color distributions
                if (std_ratio_rg > 3 or std_ratio_rg < 0.33 or
                    std_ratio_rb > 3 or std_ratio_rb < 0.33 or
                    std_ratio_gb > 3 or std_ratio_gb < 0.33):
                    result["assessment"] = "Unusual color channel distribution detected"
                    result["status"] = "suspicious"
                else:
                    result["assessment"] = "Normal color distribution"
                    result["status"] = "normal"
            else:
                result["assessment"] = "Not an RGB image, color analysis skipped"
                result["status"] = "unknown"
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error in color distribution analysis: {str(e)}")
            return {"error": f"Error in color distribution analysis: {str(e)}"}
    
    def check_boundary_artifacts(self, img_array):
        """Check for boundary artifacts that might indicate image splicing"""
        result = {}
        
        try:
            # Basic boundary check (simplified)
            if len(img_array.shape) == 3 and img_array.shape[2] >= 3:
                # Convert to grayscale
                gray = np.mean(img_array[:,:,:3], axis=2)
                
                # Get edges of image
                top_edge = gray[0, :]
                bottom_edge = gray[-1, :]
                left_edge = gray[:, 0]
                right_edge = gray[:, -1]
                
                # Calculate statistics
                edge_means = [np.mean(top_edge), np.mean(bottom_edge), 
                             np.mean(left_edge), np.mean(right_edge)]
                edge_stds = [np.std(top_edge), np.std(bottom_edge), 
                           np.std(left_edge), np.std(right_edge)]
                
                result["edge_statistics"] = {
                    "means": [float(m) for m in edge_means],
                    "stds": [float(s) for s in edge_stds]
                }
                
                # Calculate edge anomaly score
                mean_std = np.mean(edge_stds)
                std_of_stds = np.std(edge_stds)
                edge_anomaly = float(std_of_stds / mean_std) if mean_std > 0 else 0
                
                result["edge_anomaly_score"] = edge_anomaly
                
                if edge_anomaly > 1.5:
                    result["assessment"] = "Significant edge anomalies detected"
                    result["status"] = "suspicious"
                elif edge_anomaly > 0.8:
                    result["assessment"] = "Some edge anomalies detected"
                    result["status"] = "unusual"
                else:
                    result["assessment"] = "No significant edge anomalies"
                    result["status"] = "normal"
            else:
                result["assessment"] = "Cannot analyze boundaries for this image format"
                result["status"] = "unknown"
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error in boundary artifact check: {str(e)}")
            return {"error": f"Error in boundary artifact check: {str(e)}"}
    
    def analyze_compression(self, img):
        """Analyze compression artifacts for signs of manipulation"""
        results = {}
        
        try:
            # Check for compression consistency
            if img.format == 'JPEG':
                results["compression_assessment"] = self.check_jpeg_compression(img)
            else:
                results["compression_assessment"] = {
                    "status": "skipped",
                    "message": f"Compression analysis only available for JPEG, detected {img.format}"
                }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing compression: {str(e)}")
            return {"error": f"Error analyzing compression: {str(e)}"}
    
    def check_jpeg_compression(self, img):
        """Check for inconsistent JPEG compression artifacts"""
        result = {}
        
        try:
            # Convert to numpy array
            img_array = np.array(img)
            
            if len(img_array.shape) == 3 and img_array.shape[2] >= 3:
                # Convert to grayscale
                gray = np.mean(img_array[:,:,:3], axis=2)
                
                # Check for 8x8 block artifacts (common in JPEG)
                h, w = gray.shape
                
                # Analyze horizontal and vertical edges of 8x8 blocks
                block_edges_h = []
                block_edges_v = []
                
                # Get differences at potential 8x8 block boundaries
                for i in range(7, h-1, 8):
                    diffs = np.abs(gray[i, :] - gray[i+1, :])
                    block_edges_h.extend(diffs)
                
                for j in range(7, w-1, 8):
                    diffs = np.abs(gray[:, j] - gray[:, j+1])
                    block_edges_v.extend(diffs)
                
                # Get differences at non-boundary positions
                non_edges_h = []
                non_edges_v = []
                
                for i in range(h-1):
                    if i % 8 != 7:  # Not a block boundary
                        diffs = np.abs(gray[i, :] - gray[i+1, :])
                        non_edges_h.extend(diffs)
                
                for j in range(w-1):
                    if j % 8 != 7:  # Not a block boundary
                        diffs = np.abs(gray[:, j] - gray[:, j+1])
                        non_edges_v.extend(diffs)
                
                # Calculate statistics
                if block_edges_h and non_edges_h:
                    block_edge_mean = np.mean(block_edges_h)
                    non_edge_mean = np.mean(non_edges_h)
                    
                    # Calculate ratio of block boundary differences to non-boundary differences
                    block_ratio = float(block_edge_mean / non_edge_mean) if non_edge_mean > 0 else 0
                    
                    result["block_boundary_ratio"] = block_ratio
                    
                    # Assess compression consistency
                    if block_ratio > 1.5:
                        result["assessment"] = "Strong JPEG block artifacts detected, consistent with normal JPEG compression"
                        result["status"] = "normal"
                    elif block_ratio > 1.1:
                        result["assessment"] = "Moderate JPEG block artifacts detected"
                        result["status"] = "normal"
                    else:
                        result["assessment"] = "Unusually weak JPEG block artifacts for a JPEG image"
                        result["status"] = "unusual"
                else:
                    result["assessment"] = "Could not analyze block artifacts"
                    result["status"] = "unknown"
            else:
                result["assessment"] = "Cannot analyze compression for this image format"
                result["status"] = "unknown"
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error in JPEG compression check: {str(e)}")
            return {"error": f"Error in JPEG compression check: {str(e)}"}
    
    def analyze_noise_patterns(self, img):
        """Analyze image noise patterns for inconsistencies"""
        results = {}
        
        try:
            # Convert to numpy array
            img_array = np.array(img)
            
            if len(img_array.shape) == 3 and img_array.shape[2] >= 3:
                # Basic noise analysis
                results["noise_level"] = self.estimate_noise_level(img_array)
                
                # Noise consistency analysis
                results["noise_consistency"] = self.check_noise_consistency(img_array)
            else:
                results["assessment"] = "Cannot analyze noise for this image format"
                results["status"] = "unknown"
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing noise patterns: {str(e)}")
            return {"error": f"Error analyzing noise patterns: {str(e)}"}
    
    def estimate_noise_level(self, img_array):
        """Estimate the overall noise level in the image"""
        result = {}
        
        try:
            # Convert to grayscale
            if len(img_array.shape) == 3 and img_array.shape[2] >= 3:
                gray = np.mean(img_array[:,:,:3], axis=2)
            else:
                gray = img_array
            
            # Apply simple high-pass filter to extract noise
            h, w = gray.shape
            noise = np.zeros((h-2, w-2))
            
            for i in range(1, h-1):
                for j in range(1, w-1):
                    neighborhood = gray[i-1:i+2, j-1:j+2]
                    center = gray[i, j]
                    local_avg = (np.sum(neighborhood) - center) / 8.0
                    noise[i-1, j-1] = center - local_avg
            
            # Calculate noise statistics
            noise_std = float(np.std(noise))
            noise_mean = float(np.mean(np.abs(noise)))
            
            result["noise_std"] = noise_std
            result["noise_mean_abs"] = noise_mean
            
            # Assess noise level
            if noise_std < 1.0:
                result["assessment"] = "Very low noise level, potentially suspicious for AI-generated content"
                result["status"] = "suspicious"
            elif noise_std < 3.0:
                result["assessment"] = "Low noise level"
                result["status"] = "unusual"
            elif noise_std < 10.0:
                result["assessment"] = "Moderate noise level, typical for digital cameras"
                result["status"] = "normal"
            else:
                result["assessment"] = "High noise level"
                result["status"] = "normal"
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error in noise level estimation: {str(e)}")
            return {"error": f"Error in noise level estimation: {str(e)}"}
    
    def check_noise_consistency(self, img_array):
        """Check for consistency of noise patterns across the image"""
        result = {}
        
        try:
            # Divide image into regions and analyze noise in each
            h, w = img_array.shape[:2]
            grid_size = 4  # 4x4 grid
            
            # Define grid regions
            region_h = h // grid_size
            region_w = w // grid_size
            
            noise_levels = []
            
            # Convert to grayscale
            if len(img_array.shape) == 3 and img_array.shape[2] >= 3:
                gray = np.mean(img_array[:,:,:3], axis=2)
            else:
                gray = img_array
            
            # Calculate noise level in each region
            for i in range(grid_size):
                for j in range(grid_size):
                    # Get region boundaries
                    top = i * region_h
                    bottom = (i + 1) * region_h
                    left = j * region_w
                    right = (j + 1) * region_w
                    
                    # Extract region
                    region = gray[top:bottom, left:right]
                    
                    # Calculate local variance as noise estimate
                    if region.size > 0:
                        noise_level = float(np.std(region))
                        noise_levels.append(noise_level)
            
            # Calculate noise consistency statistics
            if noise_levels:
                avg_noise = np.mean(noise_levels)
                noise_std = np.std(noise_levels)
                noise_ratio = float(noise_std / avg_noise) if avg_noise > 0 else 0
                
                result["regional_noise_values"] = [float(n) for n in noise_levels]
                result["regional_noise_mean"] = float(avg_noise)
                result["regional_noise_std"] = float(noise_std)
                result["noise_consistency_ratio"] = noise_ratio
                
                # Assess noise consistency
                if noise_ratio > 0.7:
                    result["assessment"] = "Highly inconsistent noise across the image, potential indicator of manipulation"
                    result["status"] = "suspicious"
                elif noise_ratio > 0.4:
                    result["assessment"] = "Somewhat inconsistent noise patterns"
                    result["status"] = "unusual"
                else:
                    result["assessment"] = "Consistent noise patterns across the image"
                    result["status"] = "normal"
            else:
                result["assessment"] = "Could not analyze noise consistency"
                result["status"] = "unknown"
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error in noise consistency check: {str(e)}")
            return {"error": f"Error in noise consistency check: {str(e)}"}
    
    def assess_deepfake_probability(self):
        """Assess overall probability that the image is a deepfake"""
        assessment = {}
        score = 0
        risk_factors = []
        
        # Check metadata analysis
        metadata = self.results.get("metadata_analysis", {})
        if metadata.get("risk_level") == "High":
            score += 30
            risk_factors.append("Highly suspicious metadata characteristics")
        elif metadata.get("risk_level") == "Medium":
            score += 15
            risk_factors.append("Some unusual metadata characteristics")
        
        # Check visual artifacts
        visual = self.results.get("visual_artifacts", {})
        
        detail_consistency = visual.get("detail_consistency", {})
        if detail_consistency.get("status") == "suspicious":
            score += 25
            risk_factors.append("Suspicious detail consistency patterns")
        elif detail_consistency.get("status") == "unusual":
            score += 10
            risk_factors.append("Unusual detail consistency patterns")
        
        color_analysis = visual.get("color_analysis", {})
        if color_analysis.get("status") == "suspicious":
            score += 20
            risk_factors.append("Suspicious color distribution")
        
        boundary_analysis = visual.get("boundary_analysis", {})
        if boundary_analysis.get("status") == "suspicious":
            score += 25
            risk_factors.append("Suspicious boundary artifacts detected")
        elif boundary_analysis.get("status") == "unusual":
            score += 10
            risk_factors.append("Unusual boundary characteristics")
        
        # Check noise analysis
        noise = self.results.get("noise_analysis", {})
        
        noise_level = noise.get("noise_level", {})
        if noise_level.get("status") == "suspicious":
            score += 25
            risk_factors.append("Suspiciously low noise level")
        elif noise_level.get("status") == "unusual":
            score += 10
            risk_factors.append("Unusually low noise level")
        
        noise_consistency = noise.get("noise_consistency", {})
        if noise_consistency.get("status") == "suspicious":
            score += 30
            risk_factors.append("Highly inconsistent noise patterns")
        elif noise_consistency.get("status") == "unusual":
            score += 15
            risk_factors.append("Somewhat inconsistent noise patterns")
        
        # Determine probability level
        if score >= 70:
            probability = "High"
        elif score >= 40:
            probability = "Medium"
        elif score >= 20:
            probability = "Low"
        else:
            probability = "Very Low"
        
        assessment["deepfake_probability"] = probability
        assessment["risk_score"] = score
        assessment["risk_factors"] = risk_factors
        assessment["conclusion"] = self.get_conclusion(probability)
        
        return assessment
    
    @staticmethod
    def get_conclusion(probability):
        """Generate conclusion based on deepfake probability"""
        if probability == "High":
            return "The image shows multiple strong indicators consistent with synthetic or manipulated content. Further expert analysis is strongly recommended."
        elif probability == "Medium":
            return "The image shows some characteristics that may indicate manipulation or synthetic generation. Caution is advised."
        elif probability == "Low":
            return "The image shows few indicators of being manipulated or synthetically generated, but some minor unusual characteristics are present."
        else:  # Very Low
            return "The image shows no significant indicators of being manipulated or synthetically generated."

if __name__ == "__main__":
    # Example usage
    image_path = "sample.jpg"
    detector = DeepfakeDetection(image_path)
    results = detector.analyze_image()
    print(results)
