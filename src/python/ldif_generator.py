#!/usr/bin/env python3
"""
LDIF Generator Script

This script reads the OU structure CSV and the People CSV,
processes player data to generate LDIF packets, and writes two types of output:
- OU structure LDIF file.
- Individual Player LDIF files (one per player) stored in a designated directory.

Usage:
    python ldif_generator.py
"""

import argparse
import csv
import base64
import os
import re
import sys
from datetime import datetime
import logging
from pyad import *

# Set up logging to file only, not console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='ldif_generator.log',
    filemode='a'
)

# Disable logging to console
logging.getLogger().removeHandler(logging.StreamHandler())

def parse_arguments():
    parser = argparse.ArgumentParser(description="LDIF Generator Script")
    
    # Hardcoded default paths
    default_paths = {
        "csv_path": "C:\\Data\\mlb\\baseballdatabank\\core\\People.csv",
        "ou_csv_path": "C:\\gh\\setupdc2k5\\data\\csv\\PrimeOUStructure.csv",
        "ou_output": "C:\\gh\\setupdc2k5\\data\\ldfs\\ouStructure.ldf",
        "players_output": "C:\\gh\\setupdc2k5\\data\\ldfs\\peopleldf_files",
        "existing_users_csv": "C:\\gh\\setupdc2k5\\data\\csv\\All.MLB.DEV.Users.csv"
    }
    
    # Add arguments with hardcoded defaults
    parser.add_argument("--default-password", default="MLBPlayer2025!", help="Default password for accounts")
    parser.add_argument("--domain-dn", default="DC=mlb,DC=dev", help="Domain DN")
    parser.add_argument("--csv-path", default=default_paths["csv_path"], help="Path to People CSV file")
    parser.add_argument("--ou-csv-path", default=default_paths["ou_csv_path"], help="Path to OU structure CSV file")
    parser.add_argument("--ou-output", default=default_paths["ou_output"], help="Output path for OU structure LDIF file")
    parser.add_argument("--players-output", default=default_paths["players_output"], help="Directory path to store individual player LDIF files")
    parser.add_argument("--existing-users-csv", default=default_paths["existing_users_csv"], help="Path to CSV containing existing AD users")
    
    args = parser.parse_args()
    
    # Print paths being used
    print("\nUsing the following paths:")
    print(f"People CSV: {args.csv_path}")
    print(f"OU Structure CSV: {args.ou_csv_path}")
    print(f"OU Output LDIF: {args.ou_output}")
    print(f"Players Output Directory: {args.players_output}")
    print(f"Existing Users CSV: {args.existing_users_csv}")
    print(f"Domain DN: {args.domain_dn}")
    print()
    
    return args

def encode_password(password):
    # Wrap the password in quotes, encode as UTF-16LE, then base64 encode.
    pwd_str = f"\"{password}\""
    pwd_bytes = pwd_str.encode("utf-16-le")
    return base64.b64encode(pwd_bytes).decode("ascii")

def sanitize(text):
    """
    Sanitize text according to RFC 2253 for LDIF compatibility.
    Handles special characters, spaces, and UTF-8 encoding.
    """
    if not text:
        return text
        
    # Convert to string if not already
    text = str(text).strip()
    
    # Handle empty or whitespace-only strings
    if not text:
        return "Unknown"
        
    # Replace problematic characters with underscore
    text = re.sub(r'[,=\+<>#;\\"]', '_', text)
    
    # Handle leading/trailing spaces and # character
    text = text.strip()
    if text.startswith('#'):
        text = '_' + text[1:]
        
    # Handle carriage returns and newlines
    text = text.replace('\r', '').replace('\n', ' ')
    
    # Ensure result is not empty
    return text if text else "Unknown"

def encode_utf8_if_needed(text):
    """
    Encode text as base64 if it contains non-ASCII characters.
    Returns tuple (is_base64, encoded_text)
    """
    try:
        text.encode('ascii')
        return False, text
    except UnicodeEncodeError:
        # If contains non-ASCII, base64 encode UTF-8
        encoded = base64.b64encode(text.encode('utf-8')).decode('ascii')
        return True, encoded

def truncate_for_cn(name, max_length=64):
    """
    Truncate a name to fit within AD's CN length limits while preserving important parts.
    Ensures the playerID and career span are kept.
    """
    if len(name) <= max_length:
        return name
        
    # Extract parts: name and [playerID span] suffix
    parts = name.split('[')
    base_name = parts[0].strip()
    suffix = '[' + parts[1] if len(parts) > 1 else ''
    
    # Calculate how much space we have for the base name
    available_space = max_length - len(suffix) - 3  # -3 for "..."
    if available_space < 10:  # If we can't keep at least 10 chars of the name
        return name[:max_length-3] + "..."
        
    # Truncate base name and add suffix
    return base_name[:available_space] + "..." + suffix

def create_ou_ldif(ou_csv_path, domain_dn, ou_output_path):
    if not os.path.exists(ou_csv_path):
        print(f"Error: OU CSV not found at {ou_csv_path}")
        sys.exit(1)
    ldif_lines = []
    parent_dn = domain_dn
    final_ou_dn = None
    with open(ou_csv_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            level1 = row.get("Level1", "").strip()
            level2 = row.get("Level2", "").strip()
            if not level1:
                continue
            level1_dn = f"OU={level1},{parent_dn}"
            
            # Only try to modify the OU
            ldif_lines.append(f"dn: {level1_dn}")
            ldif_lines.append("changetype: modify")
            ldif_lines.append("replace: description")
            ldif_lines.append(f"description: {level1} Organization Unit")
            ldif_lines.append("-")
            ldif_lines.append("")
            
            if level2:
                level2_dn = f"OU={level2},{level1_dn}"
                
                # Only try to modify level2
                ldif_lines.append(f"dn: {level2_dn}")
                ldif_lines.append("changetype: modify")
                ldif_lines.append("replace: description")
                ldif_lines.append(f"description: {level2} Container")
                ldif_lines.append("-")
                ldif_lines.append("")
                
                parent_dn = level2_dn
                final_ou_dn = level2_dn
            else:
                parent_dn = level1_dn
                final_ou_dn = level1_dn
                
    with open(ou_output_path, "w", encoding="ascii") as f:
        f.write("\n".join(ldif_lines))
    print(f"OU structure LDIF file created at: {ou_output_path}")
    return final_ou_dn

def load_existing_users(csv_path):
    """Load existing users from CSV into a set of SAMAccountNames."""
    existing_users = set()
    try:
        with open(csv_path, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if "samaccountname" in row:
                    existing_users.add(row["samaccountname"].lower())
    except Exception as e:
        print(f"Warning: Could not load existing users from {csv_path}: {e}")
        print("Will treat all users as new users.")
    return existing_users

def check_user_exists_in_ad(username, domain="mlb.dev"):
    """Check if a user exists in Active Directory using pyad."""
    try:
        # Initialize pyad with the domain
        pyad.set_defaults(ldap_server=domain)
        
        # Query AD for the user silently
        q = adquery.ADQuery()
        q.execute_query(
            attributes=["distinguishedName"],
            where_clause=f"sAMAccountName = '{username}'",
            base_dn="DC=mlb,DC=dev",
            options={"silent": True}  # Suppress AD query output
        )
        
        # Convert generator to list to check length
        results = list(q.get_results())
        exists = len(results) > 0
        # Only log to file, not console
        logging.debug(f"Checking AD for user {username}: {'Exists' if exists else 'New'}")
        return exists
        
    except Exception as e:
        # Only log to file, not console
        logging.warning(f"Could not check AD for user {username}: {e}")
        logging.warning("Will treat user as new.")
        return False

def create_player_ldif(player, ou_dn, base64_password, existing_users):
    player_id = player.get("playerID", "").strip()
    if not player_id:
        return None

    # Get the basic fields that are most likely to exist
    name_last = player.get("nameLast", "").strip()
    if not name_last:
        return None  # Skip players without last names
        
    # Handle names based on what we have
    name_first = player.get("nameFirst", "").strip()
    name_given = player.get("nameGiven", "").strip()
    
    # For historical players with only last name, use last name as given name
    if not name_first and not name_given:
        name_first = name_last
        name_given = name_last
        
    # Ensure we always have non-empty values for required name fields
    name_first = name_first or name_given or name_last  # Fallback chain
    name_given = name_given or name_first
    
    # Get other fields
    debut = player.get("debut", "").strip()
    final_game = player.get("finalGame", "").strip()
    
    # Extract years for career span
    debut_year = debut.split("-")[0] if debut else ""
    final_game_year = final_game.split("-")[0] if final_game else ""
    career_span = f"{debut_year}-{final_game_year}" if debut_year and final_game_year else "Unknown"
    
    # Build display name and CN differently
    # Display name can have special chars, CN needs to be clean
    display_name = f"{name_given} {name_last} [{player_id} {career_span}]"
    display_name = sanitize(display_name)
    
    # CN needs to be simpler - no brackets or special chars
    cn = f"{name_given} {name_last} {player_id}"
    cn = sanitize(cn)
    
    # Truncate CN if needed
    cn = truncate_for_cn(cn)
    
    is_base64_dn, encoded_dn = encode_utf8_if_needed(display_name)
    
    # Build description with just birth location
    country = sanitize(player.get("birthCountry", "").strip() or "NoCountry")
    state = sanitize(player.get("birthState", "").strip())
    if not state and country.upper() == "USA":
        state = "NoState"
    elif not state:
        state = "NoProvince"
    city = sanitize(player.get("birthCity", "").strip() or "NoCity")
    
    # Format description as birthCountry|birthState|birthCity
    city = city.split("Retrosheet")[0].strip()
    city = city.split("Baseball-Reference")[0].strip()
    description = f"{country}|{state}|{city}"
    is_base64_desc, encoded_desc = encode_utf8_if_needed(description)

    # Use truncated name for CN, ensuring no extra spaces in DN
    dn = f"CN={cn},OU=Players,{ou_dn}"
    
    ldif_entry = []
    ldif_entry.append(f"dn: {dn}")

    # Check if user exists in AD - use ONLY the CSV check
    user_exists = player_id.lower() in existing_users

    if user_exists:
        # Modify Operation - don't try to modify RDN attributes
        ldif_entry.append("changetype: modify")
        
        # Add modify operations for non-RDN attributes only
        if is_base64_dn:
            ldif_entry.extend([
                "replace: displayName",
                f"displayName:: {encoded_dn}",
                "-"
            ])
        else:
            ldif_entry.extend([
                "replace: displayName",
                f"displayName: {display_name}",
                "-"
            ])
            
        if is_base64_desc:
            ldif_entry.extend([
                "replace: description",
                f"description:: {encoded_desc}",
                "-"
            ])
        else:
            ldif_entry.extend([
                "replace: description",
                f"description: {description}",
                "-"
            ])
            
        # Add other attributes that can be modified
        ldif_entry.extend([
            "replace: givenName",
            f"givenName: {sanitize(name_first)}",
            "-",
            "replace: sn",
            f"sn: {sanitize(name_last)}",
            "-"
        ])

        # Add MLB-specific attributes
        fields = [
            ("birthYear", "birthYear"),
            ("birthMonth", "birthMonth"),
            ("birthDay", "birthDay"),
            ("birthCountry", "mlbCountry"),
            ("birthState", "birthState"),
            ("birthCity", "birthCity"),
            ("deathYear", "deathYear"),
            ("deathMonth", "deathMonth"),
            ("deathDay", "deathDay"),
            ("deathCountry", "deathCountry"),
            ("deathState", "deathState"),
            ("deathCity", "deathCity"),
            ("nameFirst", "nameFirst"),
            ("nameLast", "nameLast"),
            ("nameGiven", "nameGiven"),
            ("weight", "weight"),
            ("height", "height"),
            ("bats", "bats"),
            ("throws", "throws"),
            ("debut", "debut"),
            ("finalGame", "finalGame"),
            ("retroID", "retroID"),
            ("bbrefID", "bbrefID")
        ]

        for csv_field, ldif_field in fields:
            value = player.get(csv_field, "").strip()
            if value:
                value = sanitize(value)
                is_base64, encoded = encode_utf8_if_needed(value)
                if is_base64:
                    ldif_entry.extend([
                        f"replace: {ldif_field}",
                        f"{ldif_field}:: {encoded}",
                        "-"
                    ])
                else:
                    ldif_entry.extend([
                        f"replace: {ldif_field}",
                        f"{ldif_field}: {value}",
                        "-"
                    ])
    else:
        # Add Operation
        ldif_entry.append("changetype: add")
        ldif_entry.append("objectClass: top")
        ldif_entry.append("objectClass: person")
        ldif_entry.append("objectClass: organizationalPerson")
        ldif_entry.append("objectClass: user")
        ldif_entry.append(f"cn: {cn}")
        ldif_entry.append(f"sAMAccountName: {player_id}")
        ldif_entry.append(f"userPrincipalName: {player_id}@mlb.dev")
        ldif_entry.append(f"givenName: {sanitize(name_first)}")
        ldif_entry.append(f"sn: {sanitize(name_last)}")
        
        if is_base64_dn:
            ldif_entry.append(f"displayName:: {encoded_dn}")
        else:
            ldif_entry.append(f"displayName: {display_name}")
            
        if is_base64_desc:
            ldif_entry.append(f"description:: {encoded_desc}")
        else:
            ldif_entry.append(f"description: {description}")
            
        ldif_entry.append(f"name: {cn}")
        ldif_entry.append("userAccountControl: 512")
        ldif_entry.append(f"unicodePwd:: {base64_password}")
        ldif_entry.append(f"playerID: {player_id}")

        # Add MLB-specific attributes
        for csv_field, ldif_field in fields:
            value = player.get(csv_field, "").strip()
            if value:
                value = sanitize(value)
                is_base64, encoded = encode_utf8_if_needed(value)
                if is_base64:
                    ldif_entry.append(f"{ldif_field}:: {encoded}")
                else:
                    ldif_entry.append(f"{ldif_field}: {value}")

    ldif_entry.append("")  # Add blank line to separate entries
    return "\n".join(ldif_entry)

def process_players(csv_path, ou_dn, base64_password, players_output_dir, existing_users):
    if not os.path.exists(csv_path):
        print(f"Error: Players CSV not found at {csv_path}")
        sys.exit(1)
    
    # ANSI color codes
    YELLOW = '\033[93m'  # For existing users
    GREEN = '\033[92m'   # For new users
    RESET = '\033[0m'    # Reset color
    
    count = 0
    total = 0
    
    # First count total players
    with open(csv_path, newline="", encoding="utf-8") as csvfile:
        total = sum(1 for row in csv.DictReader(csvfile))
    
    print(f"\nProcessing {total} players...")
    
    with open(csv_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            count += 1
            ldif = create_player_ldif(row, ou_dn, base64_password, existing_users)
            if ldif:
                player_id = row.get("playerID", "").strip()
                if not player_id:
                    continue
                    
                file_name = f"{player_id}.ldf"
                file_path = os.path.join(players_output_dir, file_name)
                with open(file_path, "w", encoding="ascii") as f:
                    f.write(ldif)
                logging.info(f"LDIF for player {player_id} written to: {file_path}")
                
                # Check if user exists and print colored status (only progress line to console)
                user_exists = check_user_exists_in_ad(player_id)
                status = "Exists" if user_exists else "New"
                color = YELLOW if user_exists else GREEN
                print(f"[{count}/{total}] {color}{player_id}: {status}{RESET}", flush=True)
    
    print(f"\nProcessed {count} players. Check ldif_generator.log for details.")
    return count

def main():
    args = parse_arguments()
    base64_password = encode_password(args.default_password)
    
    # Create output directories if they don't exist
    os.makedirs(os.path.dirname(args.ou_output), exist_ok=True)
    os.makedirs(args.players_output, exist_ok=True)
    
    # Load existing users
    existing_users = load_existing_users(args.existing_users_csv)
    print(f"Loaded {len(existing_users)} existing users from {args.existing_users_csv}")
    
    print("Generating OU structure LDIF...")
    ou_dn = create_ou_ldif(args.ou_csv_path, args.domain_dn, args.ou_output)
    if not ou_dn:
        print("Failed to generate OU structure.")
        sys.exit(1)
    
    print("Processing players CSV...")
    player_count = process_players(args.csv_path, ou_dn, base64_password, args.players_output, existing_users)
    if player_count == 0:
        print("No players were processed. Exiting.")
        sys.exit(1)
    
    print(f"""
LDIF Generation completed successfully:
- OU Structure LDIF: {args.ou_output}
- Player LDIFs ({player_count} files): {args.players_output}

To import these files, run the PowerShell script:
Import-42PyLDFPackets.ps1 -Server <server_name> -OUFile "{args.ou_output}" -PlayersDir "{args.players_output}" -LogFile <log_file_path>
""")

if __name__ == "__main__":
    main()
