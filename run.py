#!/usr/bin/env python3
"""
Digital Forensics Tool - Main Runner
Combines image malware detection, forensics, and deepfake detection
"""

import argparse
import json
from malware_detection import ImageMalwareDetection
from image_forensics import ImageForensics
from deepfake_detection import DeepfakeDetection

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Digital Forensics Tool for Image Analysis")
    parser.add_argument("image_path", help="Path to the image file to analyze")
    parser.add_argument("--all", action="store_true", help="Run all analysis modules")
    parser.add_argument("--malware", action="store_true", help="Run malware detection only")
    parser.add_argument("--forensics", action="store_true", help="Run image forensics only")
    parser.add_argument("--deepfake", action="store_true", help="Run deepfake detection only")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--report", action="store_true", help="Generate a detailed text report")
    
    args = parser.parse_args()
    
    # Determine which modules to run
    run_all = args.all or not (args.malware or args.forensics or args.deepfake)
    
    results = {
        "image_path": args.image_path,
        "analyses": {}
    }
    
    # Run selected analyses
    if run_all or args.malware:
        malware_detector = ImageMalwareDetection(args.image_path)
        malware_results = malware_detector.analyze_image()
        results["analyses"]["malware_detection"] = malware_results
        
        if args.report:
            print("\n" + "="*80)
            print("MALWARE DETECTION REPORT")
            print("="*80)
            print(malware_detector.create_report())
    
    if run_all or args.forensics:
        forensics_analyzer = ImageForensics(args.image_path)
        forensics_results = forensics_analyzer.analyze_image()
        results["analyses"]["image_forensics"] = forensics_results
        
        if args.report:
            print("\n" + "="*80)
            print("IMAGE FORENSICS REPORT")
            print("="*80)
            print(json.dumps(forensics_results, indent=2))
    
    if run_all or args.deepfake:
        deepfake_detector = DeepfakeDetection(args.image_path)
        deepfake_results = deepfake_detector.analyze_image()
        results["analyses"]["deepfake_detection"] = deepfake_results
        
        if args.report:
            print("\n" + "="*80)
            print("DEEPFAKE DETECTION REPORT")
            print("="*80)
            print(json.dumps(deepfake_results, indent=2))
    
    # Output results in requested format
    if args.json:
        print(json.dumps(results, indent=2))
    elif not args.report:
        print("\nAnalysis Summary:")
        print("-"*40)
        if "malware_detection" in results["analyses"]:
            risk = results["analyses"]["malware_detection"].get("risk_assessment", {})
            print(f"Malware Risk: {risk.get('risk_level', 'Unknown')} (Score: {risk.get('risk_score', 0)})")
        
        if "image_forensics" in results["analyses"]:
            print("Forensics: Metadata and basic analysis completed")
        
        if "deepfake_detection" in results["analyses"]:
            prob = results["analyses"]["deepfake_detection"].get("deepfake_assessment", {})
            print(f"Deepfake Probability: {prob.get('deepfake_probability', 'Unknown')}")

if __name__ == "__main__":
    main()