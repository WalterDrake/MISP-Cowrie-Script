import re
import sys

def preprocess_rule(line):
    """
    Preprocess a single Snort rule line.
    Adjusts formatting and escapes special characters as needed.
    """
    # Remove quotes inside square brackets if they exist
    line = re.sub(r'\[([a-zA-Z0-9\-]+:source-type=)"(.*?)"\]', r'[\1\2]', line)
    
    # Fix the `nocase` syntax
    line = re.sub(r'content:"(.*?)";\s*nocase;', r'content:"\1", nocase;', line)

    # Fix the "tag:session" syntax
    line = re.sub(r'tag:session,(\d+),seconds;', r'tag:session, seconds \1;', line)
    
    return line

def preprocess_rules(input_file, output_file):
    """
    Preprocess Snort rules from an input file and save them to an output file.
    """
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            if line.strip():  # Skip empty lines
                processed_line = preprocess_rule(line.strip())
                outfile.write(processed_line + '\n')

# Specify input and output file's
input_file = sys.argv[1]
output_file = sys.argv[2]

# Run preprocessing
preprocess_rules(input_file, output_file)
print(f"Preprocessed rules saved to {output_file}")
