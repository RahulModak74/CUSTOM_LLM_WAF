#!/usr/bin/env python3
"""
CSV Format Converter for WAF Session Data
Converts from original format with double-escaped JSON to clean CSV format
"""

import csv
import json
import sys
import os
from io import StringIO

def parse_csv_line_manually(line):
    """
    Manually parse CSV line to handle JSON with internal commas
    Returns (key, value_json, expires_at)
    """
    # Find the first comma (after key)
    first_comma = line.find(',')
    if first_comma == -1:
        return None
    
    key = line[:first_comma]
    
    # Find the last comma (before expires_at)
    last_comma = line.rfind(',')
    if last_comma == first_comma:
        return None
    
    # Extract the JSON part (between first and last comma)
    json_part = line[first_comma + 1:last_comma]
    
    # Extract expires_at
    expires_at = line[last_comma + 1:].strip()
    
    return key, json_part, expires_at

def clean_json_value(json_str):
    """
    Clean the JSON string by fixing double-escaped quotes and other issues
    """
    # Remove outer quotes if present
    if json_str.startswith('"') and json_str.endswith('"'):
        json_str = json_str[1:-1]
    
    # Fix double-escaped quotes
    json_str = json_str.replace('""', '"')
    
    # Try to parse to validate
    try:
        parsed = json.loads(json_str)
        # Re-serialize to ensure clean formatting
        return json.dumps(parsed)
    except json.JSONDecodeError as e:
        print(f"Warning: Could not parse JSON: {e}")
        print(f"Problematic JSON: {json_str[:100]}...")
        return json_str

def convert_csv_format(input_file, output_file):
    """
    Convert CSV from original format to clean format
    """
    print(f"Converting {input_file} to {output_file}...")
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found!")
        return False
    
    try:
        converted_rows = []
        skipped_rows = 0
        
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        
        print(f"Processing {len(lines)} lines...")
        
        # Skip header line, we'll create our own
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                parsed = parse_csv_line_manually(line)
                if parsed is None:
                    print(f"Warning: Could not parse line {i}")
                    skipped_rows += 1
                    continue
                
                key, json_value, expires_at = parsed
                
                # Clean the JSON value
                clean_json = clean_json_value(json_value)
                
                # Validate expires_at is numeric
                try:
                    int(expires_at)
                except ValueError:
                    print(f"Warning: Invalid expires_at value on line {i}: {expires_at}")
                    skipped_rows += 1
                    continue
                
                converted_rows.append([key, clean_json, expires_at])
                
            except Exception as e:
                print(f"Error processing line {i}: {e}")
                skipped_rows += 1
                continue
        
        # Write the converted CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.writer(outfile, quoting=csv.QUOTE_MINIMAL)
            
            # Write header
            writer.writerow(['key', 'value', 'expires_at'])
            
            # Write data rows
            for row in converted_rows:
                writer.writerow(row)
        
        print(f"✅ Conversion complete!")
        print(f"   Processed: {len(converted_rows)} rows")
        print(f"   Skipped: {skipped_rows} rows")
        print(f"   Output: {output_file}")
        
        # Validate a few rows by showing their content
        print(f"\n📊 Sample converted data:")
        print("-" * 60)
        
        for i, row in enumerate(converted_rows[:3]):
            print(f"Row {i+1}:")
            print(f"  Key: {row[0][:50]}...")
            
            # Try to parse and display JSON nicely
            try:
                parsed_json = json.loads(row[1])
                print(f"  JSON fields: {list(parsed_json.keys())}")
                if 'referer' in parsed_json and parsed_json['referer']:
                    print(f"  Referer: {parsed_json['referer']}")
                if 'user_agent' in parsed_json:
                    print(f"  User Agent: {parsed_json['user_agent'][:50]}...")
            except:
                print(f"  JSON: {row[1][:50]}...")
            
            print(f"  Expires: {row[2]}")
            print()
        
        return True
        
    except Exception as e:
        print(f"Error during conversion: {e}")
        return False

def validate_converted_csv(csv_file):
    """
    Validate the converted CSV file
    """
    print(f"\n🔍 Validating converted file: {csv_file}")
    print("-" * 60)
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            total_rows = 0
            valid_json = 0
            attack_indicators = 0
            
            for row in reader:
                total_rows += 1
                
                # Validate JSON
                try:
                    json_data = json.loads(row['value'])
                    valid_json += 1
                    
                    # Check for potential attack indicators
                    referer = json_data.get('referer', '')
                    if any(indicator in referer.lower() for indicator in ['script', 'alert', 'onerror', 'onload', 'javascript:']):
                        attack_indicators += 1
                        print(f"🚨 Potential attack in row {total_rows}: {referer}")
                        
                except json.JSONDecodeError:
                    print(f"❌ Invalid JSON in row {total_rows}")
        
        print(f"\n📈 Validation Results:")
        print(f"   Total rows: {total_rows}")
        print(f"   Valid JSON: {valid_json}/{total_rows}")
        print(f"   Attack indicators found: {attack_indicators}")
        
        if valid_json == total_rows:
            print("✅ All JSON values are valid!")
        else:
            print(f"⚠️  {total_rows - valid_json} rows have invalid JSON")
            
    except Exception as e:
        print(f"Error validating file: {e}")

def main():
    """
    Main function to handle command line arguments and run conversion
    """
    print("="*80)
    print("CSV FORMAT CONVERTER FOR WAF SESSION DATA")
    print("="*80)
    
    # Default file names
    input_file = "paste-2.txt"  # Your original data file
    output_file = "sample_session.csv"  # Clean output for the runner
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    
    # Run conversion
    success = convert_csv_format(input_file, output_file)
    
    if success:
        # Validate the result
        validate_converted_csv(output_file)
        
        print(f"\n🎉 Conversion completed successfully!")
        print(f"You can now run: python waf_runner.py")
        
        # Show next steps
        print(f"\n🚀 Next Steps:")
        print(f"1. Run the WAF detection: python waf_runner.py")
        print(f"2. The runner will process {output_file}")
        print(f"3. Results will be saved to a timestamped JSON file")
        
    else:
        print(f"\n❌ Conversion failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
