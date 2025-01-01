import difflib
import os

def compare_files(running_file, updated_file):
    # Read the contents of the files
    with open(running_file, 'r') as f:
        running_lines = f.readlines()

    with open(updated_file, 'r') as f:
        updated_lines = f.readlines()

    # Compare the files
    diff = difflib.unified_diff(running_lines, updated_lines, fromfile=running_file, tofile=updated_file)
    
    # Process the diff to display more clearly
    added_lines = []
    deleted_lines = []
    context_lines = []

    for line in diff:
        if line.startswith('---') or line.startswith('+++') or line.startswith('@@'):
            context_lines.append(line)
        elif line.startswith('-'):
            deleted_lines.append(line)  # Deleted lines
        elif line.startswith('+'):
            added_lines.append(line)  # Added lines
    
 # Displaying the results clearly
    if not added_lines and not deleted_lines:
        print("No changes detected.")
        return;
    else:
        print("\nChanges detected:\n")

        if added_lines:
            print("\033[92mNewly added lines:\033[0m")  # Green text for added lines
            for line in added_lines:
                print(line.strip())

        if deleted_lines:
            print("\033[91mDeleted lines:\033[0m")  # Red text for deleted lines
            for line in deleted_lines:
                print(line.strip())

        # Display context (lines around the diff)
        print("\n\033[90mContext (unchanged lines):\033[0m")
        for line in context_lines:
            print(line.strip())

    # Ask if the user wants to update the running file
    user_input = input("\nDo you want to update the running rule with the changes? (yes/no): ").strip().lower()

    if user_input == 'yes':
        with open(running_file, 'w') as f:
            f.writelines(updated_lines)
        print(f"\n{running_file} has been updated with the changes.")
    else:
        print("\nNo changes were made to the running file.")

if __name__ == "__main__":
    print("File is needed to update: ")
    folder_path = '/usr/local/etc/snort/rules'
    file_list = f"{folder_path}/misp_rules_beta"
    files = os.listdir(file_list)
    print(files)      
    file_name = input()
    # Define the file paths for the running and updated rule files
    running_rule_file = f'{folder_path}/misp_rules/{file_name}.rules'
    updated_rule_file = f'{folder_path}/misp_rules_beta/{file_name}_new.rules'

    # Compare the files and display differences
    compare_files(running_rule_file, updated_rule_file)

