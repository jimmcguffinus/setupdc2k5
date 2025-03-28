#!/usr/bin/env python3
"""
LDIF Generator Script (Dynamic Headers, Snapshot Cache)

Reads OU structure CSV and People CSV. Determines attributes to manage based
on People.csv headers (assuming direct mapping to AD attributes).
Builds/loads an AD snapshot cache (JSON file) to avoid slow AD queries.
Compares CSV data to snapshot data and generates LDIF packets only if changes
are detected or the user is new. Backs up previous LDF output.

Usage:
    python ldif_generator.py [--force-refresh] [--max-cache-age HOURS] [...]
"""

import argparse
import csv
import base64
import os
import re
import sys
import datetime
import logging
import shutil
import json
import time # Used indirectly via datetime

# Attempt specific pyad imports for clarity
try:
    import pyad
    from pyad import adquery, pyadexceptions, adobject
except ImportError:
    print("ERROR: pyad library not found. Please install it using: pip install pyad")
    sys.exit(1)

# --- Custom Defaults Wrapper ---
_global_ad_defaults = {} # Global dictionary to store defaults

def store_defaults(**kwargs):
    """Stores connection defaults in a global dictionary."""
    global _global_ad_defaults
    _global_ad_defaults.update(kwargs)
    logging.debug(f"Updated global AD defaults: {_global_ad_defaults}")

def get_stored_defaults():
    """Retrieves the stored connection defaults."""
    global _global_ad_defaults
    return _global_ad_defaults.copy() # Return a copy

# --- Global Variables / Constants ---

# Key identifier mapping
CSV_PLAYER_ID_FIELD = "playerID"
AD_SAMACCOUNTNAME_ATTR = "sAMAccountName"
AD_PLAYERID_ATTR = "playerID" # The custom playerID attribute in AD

# Attributes calculated from multiple CSV fields (must be handled explicitly)
# Map internal placeholder key to the target AD attribute name
CALCULATED_AD_ATTRIBUTES = {
    "_calculated_cn": "cn",
    "_calculated_displayName": "displayName",
    "_calculated_description": "description",
    "_calculated_givenName": "givenName",
    "_calculated_sn": "sn",
    "_calculated_name": "name" # AD 'name' attribute typically mirrors 'cn'
}

# CSV Headers to explicitly exclude from becoming managed AD attributes
EXCLUDED_CSV_HEADERS = {
    # Add any headers from People.csv that should NOT map to AD attributes
    # e.g., if there were internal processing flags or purely informational columns
}

# CSV headers used only for calculations, not direct AD attributes themselves
CALCULATION_SOURCE_HEADERS = {"nameFirst", "nameLast", "nameGiven", "debut", "finalGame"}

# Cache Configuration
CACHE_FILENAME = "player_ad_snapshot.json"
CACHE_DIRECTORY_NAME = "snapshot_cache" # Will be sibling to players_output dir
CURRENT_CACHE_VERSION = "1.1" # Increment if snapshot structure changes
DEFAULT_MAX_CACHE_AGE_HOURS = 24 # Default validity period for cache

# --- Logging Setup ---
def setup_logging():
    """Set up logging configuration"""
    log_dir = os.path.join("C:", "gh", "setupdc2k5", "data", "logs")
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"ldif_generator_{timestamp}.log")
    file_handler = logging.FileHandler(log_file, encoding='utf-8') # Specify encoding
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    logging.info(f"Log file created at: {log_file}")
    return log_file

# --- Argument Parsing ---
def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="LDIF Generator Script with Snapshot Cache")
    default_paths = {
        "csv_path": "C:\\Data\\mlb\\baseballdatabank\\core\\People.csv",
        "ou_csv_path": "C:\\gh\\setupdc2k5\\data\\csv\\PrimeOUStructure.csv",
        "ou_output": "C:\\gh\\setupdc2k5\\data\\ldfs\\ouStructure.ldf",
        "players_output": "C:\\gh\\setupdc2k5\\data\\ldfs\\peopleldf_files"
    }
    parser.add_argument("--default-password", default="MLBPlayer2025!", help="Default password for new accounts")
    parser.add_argument("--domain-dn", default="DC=mlb,DC=dev", help="Domain DN (e.g., DC=mlb,DC=dev)")
    parser.add_argument("--domain", default="mlb.dev", help="Domain suffix for UPN (e.g., mlb.dev)")
    parser.add_argument("--ldap-server", help="LDAP server hostname/IP. Defaults to domain suffix if not specified")
    parser.add_argument("--ldap-user", help="Username for LDAP authentication (optional)")
    parser.add_argument("--ldap-password", help="Password for LDAP authentication (optional)")
    parser.add_argument("--players-ou-name", default="Players", help="Name of the OU where player objects will be created")
    parser.add_argument("--csv-path", default=default_paths["csv_path"], help="Path to People CSV file")
    parser.add_argument("--ou-csv-path", default=default_paths["ou_csv_path"], help="Path to OU structure CSV file")
    parser.add_argument("--ou-output", default=default_paths["ou_output"], help="Output path for OU structure LDIF file")
    parser.add_argument("--players-output", default=default_paths["players_output"], help="Directory path to store individual player LDIF files")
    # Cache control arguments
    parser.add_argument("--force-refresh", action="store_true", help="Force refresh of AD snapshot cache, ignoring existing cache file.")
    parser.add_argument("--max-cache-age", type=int, default=DEFAULT_MAX_CACHE_AGE_HOURS,
                        help="Maximum age of cache file in hours before refresh is triggered.")

    args = parser.parse_args()

    if not args.ldap_server:
        args.ldap_server = args.domain

    logging.info("Using the following configuration:")
    logging.info(f"  People CSV: {args.csv_path}")
    logging.info(f"  OU Structure CSV: {args.ou_csv_path}")
    logging.info(f"  OU Output LDIF: {args.ou_output}")
    logging.info(f"  Players Output Directory: {args.players_output}")
    logging.info(f"  Domain DN: {args.domain_dn}")
    logging.info(f"  Domain Suffix: {args.domain}")
    logging.info(f"  LDAP Server: {args.ldap_server}")
    logging.info(f"  Players OU Name: {args.players_ou_name}")
    if args.ldap_user: logging.info(f"  LDAP User: {args.ldap_user}")
    logging.info(f"  Force Cache Refresh: {args.force_refresh}")
    logging.info(f"  Max Cache Age (Hours): {args.max_cache_age}")

    return args

# --- Helper Functions ---
def encode_password(password):
    """Encodes password for unicodePwd"""
    pwd_str = f"\"{password}\""
    pwd_bytes = pwd_str.encode("utf-16-le")
    return base64.b64encode(pwd_bytes).decode("ascii")

def sanitize(text, is_dn_component=False):
    """Sanitizes text. Returns EMPTY STRING for empty/None input."""
    if text is None: return "" # Return empty string for None
    text = str(text).strip()
    if not text: return "" # Return empty string for empty

    # Keep other replacements
    text = re.sub(r'[,=\+<>#;\\"]', '_', text)
    text = text.strip()
    if text.startswith('#'): text = '_' + text[1:]
    text = text.replace('\r', '').replace('\n', ' ')

    # DN component specific rules
    if is_dn_component:
        text = re.sub(r'[\/\[\]\{\}\(\)\*\?\!\@\$\%\^\&]', '_', text)
        text = text.strip()
        text = re.sub(r'_+', '_', text)

    # Return potentially empty string if all replacements made it empty
    return text.strip() # Ensure no trailing spaces on valid output

def encode_utf8_if_needed(text):
    """Base64 encodes UTF-8 text if it contains non-ASCII characters."""
    try:
        text.encode('ascii'); return False, text
    except UnicodeEncodeError:
        encoded = base64.b64encode(text.encode('utf-8')).decode('ascii'); return True, encoded

def truncate_for_cn(name, player_id_for_logging, max_length=64):
    """Truncate CN if needed, logging the event."""
    original_name = name
    if len(name) <= max_length: return name
    parts = name.split('[')
    base_name = parts[0].strip()
    suffix = '[' + parts[1] if len(parts) > 1 else ''
    available_space = max_length - len(suffix) - 3
    if available_space < 10: truncated_name = name[:max_length-3] + "..."
    else: truncated_name = base_name[:available_space] + "..." + suffix
    logging.warning(f"CN for player '{player_id_for_logging}' truncated: '{original_name}' -> '{truncated_name}'")
    return truncated_name

# --- OU Structure ---
def create_ou_ldif(ou_csv_path, domain_dn, ou_output_path, players_ou_name):
    """Creates LDIF for OU structure using changetype: add."""
    if not os.path.exists(ou_csv_path): logging.error(f"OU CSV not found: {ou_csv_path}"); sys.exit(1)
    logging.info(f"Processing OU structure from {ou_csv_path}")
    ldif_lines = []; final_player_container_dn = None
    created_dns = set() # Track created DNs to avoid duplicates in LDIF

    try:
        with open(ou_csv_path, newline="", encoding="utf-8-sig") as csvfile: # Use utf-8-sig
            reader = csv.DictReader(csvfile)
            # Assume structure is hierarchical, process level 1 then level 2
            # This simplistic approach assumes CSV is ordered or structure is simple
            # A more robust approach might build a tree first
            level1_ous = {} # Store level 1 DNs to attach level 2 correctly
            for row in reader:
                level1 = sanitize(row.get("Level1", ""), is_dn_component=True)
                if not level1 or level1 == "Unknown": continue

                level1_dn = f"OU={level1},{domain_dn}"
                if level1_dn.lower() not in created_dns:
                    logging.debug(f"Defining Level 1 OU: {level1_dn}")
                    ldif_lines.extend([f"dn: {level1_dn}", "changetype: add", "objectClass: organizationalUnit", f"ou: {level1}", f"description: {level1} Organization Unit", ""])
                    created_dns.add(level1_dn.lower())
                    level1_ous[level1] = level1_dn # Store for level 2 processing

            # Reset file pointer to process level 2 after all level 1 are defined
            csvfile.seek(0)
            next(reader) # Skip header again

            for row in reader:
                level1 = sanitize(row.get("Level1", ""), is_dn_component=True)
                level2 = sanitize(row.get("Level2", ""), is_dn_component=True)
                if not level1 or level1 == "Unknown": continue

                level1_dn = level1_ous.get(level1)
                if not level1_dn:
                    logging.warning(f"Could not find parent Level 1 OU '{level1}' for Level 2 '{level2}'. Skipping Level 2.")
                    continue

                current_parent_dn_for_player_ou = level1_dn
                target_player_dn_for_this_row = None # Initialize

                if level2 and level2 != "Unknown":
                    # If Level 2 IS the desired players OU name:
                    if level2.lower() == players_ou_name.lower():
                        players_dn = f"OU={level2},{level1_dn}" # This IS the player DN
                        if players_dn.lower() not in created_dns:
                            logging.debug(f"Defining Players OU (as Level 2): {players_dn}")
                            ldif_lines.extend([f"dn: {players_dn}", "changetype: add", "objectClass: organizationalUnit", f"ou: {level2}", f"description: Container for player objects", ""])
                            created_dns.add(players_dn.lower())
                        target_player_dn_for_this_row = players_dn
                    else:
                        # Level 2 is an intermediate OU
                        level2_dn = f"OU={level2},{level1_dn}"
                        if level2_dn.lower() not in created_dns:
                            logging.debug(f"Defining Level 2 OU: {level2_dn}")
                            ldif_lines.extend([f"dn: {level2_dn}", "changetype: add", "objectClass: organizationalUnit", f"ou: {level2}", f"description: {level2} Container", ""])
                            created_dns.add(level2_dn.lower())
                        current_parent_dn_for_player_ou = level2_dn # Update parent for Players OU

                        # Create Players OU under Level 2 (since Level 2 wasn't 'Players')
                        players_dn = f"OU={players_ou_name},{current_parent_dn_for_player_ou}"
                        if players_dn.lower() not in created_dns:
                            logging.debug(f"Defining Players OU under {level2}: {players_dn}")
                            ldif_lines.extend([f"dn: {players_dn}", "changetype: add", "objectClass: organizationalUnit", f"ou: {players_ou_name}", f"description: Container for player objects", ""])
                            created_dns.add(players_dn.lower())
                        target_player_dn_for_this_row = players_dn

                else: # Only Level 1 defined
                    # Create Players OU under Level 1
                    players_dn = f"OU={players_ou_name},{current_parent_dn_for_player_ou}" # Parent is Level 1
                    if players_dn.lower() not in created_dns:
                        logging.debug(f"Defining Players OU under {level1}: {players_dn}")
                        ldif_lines.extend([f"dn: {players_dn}", "changetype: add", "objectClass: organizationalUnit", f"ou: {players_ou_name}", f"description: Container for player objects", ""])
                        created_dns.add(players_dn.lower())
                    target_player_dn_for_this_row = players_dn

                # Update the overall final DN found
                if target_player_dn_for_this_row:
                    final_player_container_dn = target_player_dn_for_this_row # Keep track of the last valid one defined

        # Write the combined OU LDIF file
        os.makedirs(os.path.dirname(ou_output_path), exist_ok=True) # Ensure dir exists
        with open(ou_output_path, "w", encoding="ascii") as f: f.write("\n".join(ldif_lines))
        logging.info(f"OU structure LDIF file created at: {ou_output_path}")

        return final_player_container_dn

    except Exception as e: logging.error(f"Error processing OU structure: {str(e)}", exc_info=True); raise


# --- AD Interaction ---
class ADConnectionError(Exception): pass
class ADQueryError(Exception): pass

class ADConnection:
    """Manages Active Directory connection."""
    def __init__(self, server, base_dn, domain, username=None, password=None):
        self.server = server; self.base_dn = base_dn; self.domain = domain
        self.username = username; self.password = password
        try:
            pyad_args = {"ldap_server": server}
            if username and password:
                pyad_args.update({"username": username, "password": password})

            # Store our connection defaults
            store_defaults(**pyad_args)

            logging.info(f"Stored AD connection context for server {server}")

        except (pyadexceptions.win32Exception, pyadexceptions.genericADSIException) as e:
            raise ADConnectionError(f"Could not connect to AD server {server}: {e}") from e
        except Exception as e:
            logging.error(f"Caught unexpected exception during AD init: {type(e).__name__} - {e}")
            raise ADConnectionError(f"Unexpected error initializing AD connection: {e}") from e

    def build_ad_snapshot(self, target_container_dn, attributes_to_fetch):
        """Build a snapshot of AD user data for the target container."""
        logging.info(f"Building AD snapshot for container: {target_container_dn}")
        try:
            q = adquery.ADQuery()
            fetch_list = list(set([AD_SAMACCOUNTNAME_ATTR] + attributes_to_fetch))
            logging.debug(f"Fetching attributes: {fetch_list}")

            # Pass defaults explicitly via 'options'
            current_options = get_stored_defaults()

            q.execute_query(
                attributes=fetch_list,
                where_clause=f"objectClass = 'user'",
                base_dn=target_container_dn,
                options=current_options
            )
            ad_snapshot = {}
            for row in q.get_results():
                sam_account = row.get(AD_SAMACCOUNTNAME_ATTR)
                if not sam_account: continue
                ad_snapshot[sam_account] = {k: v for k, v in row.items()}
            logging.info(f"Successfully built AD snapshot with {len(ad_snapshot)} users")
            return ad_snapshot

        except (pyadexceptions.win32Exception, pyadexceptions.genericADSIException, ADConnectionError) as e:
            logging.error(f"Failed AD snapshot query: {str(e)}", exc_info=True)
            return None
        except Exception as e:
            logging.error(f"Unexpected error building AD snapshot: {str(e)}", exc_info=True)
            return None


# --- Cache Handling ---
def get_cache_file_path(players_output_dir):
    """Determines the path for the cache file."""
    base_dir = os.path.dirname(players_output_dir)
    cache_dir = os.path.join(base_dir, CACHE_DIRECTORY_NAME)
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, CACHE_FILENAME)

def verify_and_load_cache(cache_file_path, max_age_hours):
    """Verify cache file and load if valid."""
    if not os.path.exists(cache_file_path):
        logging.info("Cache file not found.")
        return None

    try:
        file_stat = os.stat(cache_file_path)
        file_mod_time = datetime.datetime.fromtimestamp(file_stat.st_mtime)
        now = datetime.datetime.now()
        file_age = now - file_mod_time
        max_age_timedelta = datetime.timedelta(hours=max_age_hours)

        if file_age > max_age_timedelta:
            logging.info(f"Cache file '{cache_file_path}' is older than {max_age_hours} hours ({file_age}). Requires refresh.")
            return None

        logging.info(f"Attempting to load cache file: {cache_file_path}")
        with open(cache_file_path, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)

        # Verify structure, version
        if not isinstance(cache_data, dict) or \
           cache_data.get('version') != CURRENT_CACHE_VERSION or \
           'snapshot' not in cache_data or \
           not isinstance(cache_data['snapshot'], dict):
            logging.warning("Cache file invalid structure or version mismatch. Requires refresh.")
            return None

        logging.info(f"Valid cache file loaded (Version: {cache_data['version']}, Updated: {cache_data.get('last_updated', 'N/A')}).")
        return cache_data['snapshot']

    except (json.JSONDecodeError, IOError, TypeError, ValueError, KeyError) as e:
        logging.warning(f"Failed to load or verify cache file '{cache_file_path}': {e}")
        return None

def save_cache(cache_file_path, ad_snapshot_dict):
    """Saves the snapshot dictionary to the cache file."""
    cache_data = {
        'version': CURRENT_CACHE_VERSION,
        'last_updated': datetime.datetime.now().isoformat(),
        'snapshot': ad_snapshot_dict
    }
    try:
        # Write to temp file first, then rename for atomicity
        temp_cache_file = cache_file_path + ".tmp"
        with open(temp_cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2) # Smaller indent for potentially large file
        # Replace existing cache file atomically (on most OS)
        os.replace(temp_cache_file, cache_file_path)
        logging.info(f"Successfully saved AD snapshot cache to {cache_file_path}")
    except (IOError, TypeError) as e:
        logging.error(f"Failed to save cache file '{cache_file_path}': {e}")


# --- Comparison Logic ---
def normalize_for_compare(value):
    """Normalizes AD/CSV values for comparison (treat None as empty string, strip)."""
    if value is None: return ""
    return str(value).strip()

def attributes_are_different(current_ad_values, new_csv_values, attributes_to_compare, player_id):
    """Compare AD values with new CSV values, with detailed logging of differences."""
    if not current_ad_values: 
        logging.debug(f"No current AD values for {player_id} - treating as different")
        return True

    for attr in attributes_to_compare:
        ad_val = current_ad_values.get(attr)
        csv_val = new_csv_values.get(attr)
        ad_val_norm = normalize_for_compare(ad_val)
        csv_val_norm = normalize_for_compare(csv_val)

        # Debug print when a difference is found
        if ad_val_norm.lower() != csv_val_norm.lower():
            logging.debug(f"Difference DETECTED for '{attr}' on {player_id}:")
            logging.debug(f"  AD value: '{ad_val}' (normalized: '{ad_val_norm}')")
            logging.debug(f"  CSV value: '{csv_val}' (normalized: '{csv_val_norm}')")
            return True
    return False

# --- LDIF Generation ---
def create_player_ldif(player, player_container_dn, base64_password, ad_snapshot,
                       dynamic_ad_attributes, calculated_ad_attributes_map, ad_conn_domain):
    """Create LDIF entry for a player, comparing against snapshot if user exists."""

    player_id = player.get(CSV_PLAYER_ID_FIELD, "").strip()
    if not player_id: return None, "Skipped (No PlayerID)"
    player_id_lower = player_id.lower()

    user_exists_in_snapshot = player_id_lower in ad_snapshot

    # --- Construct ALL potential 'new' values from CSV first ---
    new_values_from_csv = {}

    # 1. Explicitly Calculated Attributes
    name_last = player.get("nameLast", "").strip()
    if not name_last: return None, "Skipped (No Last Name)"

    name_first = player.get("nameFirst", "").strip()
    name_given = player.get("nameGiven", "").strip()
    if not name_first and not name_given: name_first = name_last; name_given = name_last
    name_first = name_first or name_given or name_last
    name_given = name_given or name_first

    # Store sanitized calculated values using AD attribute names as keys
    new_values_from_csv["givenName"] = sanitize(name_first)
    new_values_from_csv["sn"] = sanitize(name_last)

    debut = player.get("debut", "").strip()
    final_game = player.get("finalGame", "").strip()
    debut_year = debut.split("-")[0] if debut and '-' in debut else ""
    final_game_year = final_game.split("-")[0] if final_game and '-' in final_game else ""
    career_span = f"{debut_year}-{final_game_year}" if debut_year and final_game_year else "Unknown"

    display_name_raw = f"{name_given} {name_last} [{player_id} {career_span}]"
    new_values_from_csv["displayName"] = sanitize(display_name_raw)

    cn_raw = f"{name_given} {name_last} {player_id}"
    calculated_cn = truncate_for_cn(sanitize(cn_raw), player_id)
    new_values_from_csv["cn"] = calculated_cn
    new_values_from_csv["name"] = calculated_cn # 'name' mirrors 'cn'

    country = sanitize(player.get("birthCountry", "").strip() or "NoCountry")
    state = sanitize(player.get("birthState", "").strip())
    if not state and country.upper() == "USA": state = "NoState"
    elif not state: state = "NoProvince"
    city = sanitize(player.get("birthCity", "").strip() or "NoCity")
    city = city.split("Retrosheet")[0].strip(); city = city.split("Baseball-Reference")[0].strip()
    description_raw = f"{country}|{state}|{city}"
    new_values_from_csv["description"] = sanitize(description_raw)

    # Explicitly add the custom playerID attribute value
    new_values_from_csv[AD_PLAYERID_ATTR] = player_id


    # 2. Dynamically Handled Attributes (from CSV header)
    for ad_attr_name in dynamic_ad_attributes:
        csv_header = ad_attr_name # Assumes direct 1:1 mapping holds
        raw_csv_value = player.get(csv_header, "")
        new_values_from_csv[ad_attr_name] = sanitize(raw_csv_value)

    # --- Define attributes to compare ---
    attributes_to_compare_now = list(calculated_ad_attributes_map.values()) + dynamic_ad_attributes
    attributes_to_compare_now = sorted(list(set(attributes_to_compare_now)))
    if AD_SAMACCOUNTNAME_ATTR in attributes_to_compare_now:
        attributes_to_compare_now.remove(AD_SAMACCOUNTNAME_ATTR)


    # --- Check if Modify is needed ---
    generate_modify_ldif = False
    status_detail = "Unknown" # For richer status reporting

    if user_exists_in_snapshot:
        current_ad_values = ad_snapshot[player_id_lower]
        if attributes_are_different(current_ad_values, new_values_from_csv, attributes_to_compare_now, player_id):
            generate_modify_ldif = True
            status_detail = "Exists (Modify)"
            logging.debug(f"Changes detected for existing player {player_id}.")
        else:
            status_detail = "Exists (No Change)"
            logging.info(f"No changes detected for existing player {player_id}. Skipping.")
            return None, status_detail # Skip generation
    else:
        status_detail = "New (Add)"


    # --- Build LDIF ---
    dn = f"CN={new_values_from_csv['cn']},{player_container_dn}"
    ldif_entry = []
    ldif_entry.append(f"dn: {dn}")

    attributes_to_write = attributes_to_compare_now # Use comparison list as source of truth for managed attrs

    if generate_modify_ldif:
        ldif_entry.append("changetype: modify")
        modify_operations = 0
        for attr_name in attributes_to_write:
            if attr_name == 'cn': continue # Cannot modify RDN

            value_to_write = new_values_from_csv.get(attr_name, "Unknown") # Default to Unknown if somehow missing
            current_ad_val_norm = normalize_for_compare(current_ad_values.get(attr_name))
            new_val_norm = normalize_for_compare(value_to_write)

            # Only include replace if value actually differs (case-insensitive)
            # This makes the generated modify LDIF smaller/cleaner
            if current_ad_val_norm.lower() != new_val_norm.lower():
                 modify_operations += 1
                 is_base64, encoded_val = encode_utf8_if_needed(value_to_write) # Encode the original sanitized value
                 ldif_entry.append(f"replace: {attr_name}")
                 if is_base64: ldif_entry.append(f"{attr_name}:: {encoded_val}")
                 else: ldif_entry.append(f"{attr_name}: {value_to_write}")
                 ldif_entry.append("-")

        if modify_operations > 0 and ldif_entry[-1] == "-":
            ldif_entry.pop() # Remove trailing '-' only if operations were added
        elif modify_operations == 0:
             # This case implies attributes_are_different logic might need refinement
             # Or maybe only non-compared attributes changed (unlikely here)
             logging.warning(f"Modify LDIF generated for {player_id} but no different attributes found during LDIF construction phase.")
             # Optionally return None here too if no operations were actually added
             # return None, "Exists (No Change - Verified)"

    elif not user_exists_in_snapshot: # Add New User
        ldif_entry.append("changetype: add")
        ldif_entry.extend(["objectClass: top", "objectClass: person",
                           "objectClass: organizationalPerson", "objectClass: user"])

        # Core attributes
        ldif_entry.append(f"cn: {new_values_from_csv['cn']}")
        ldif_entry.append(f"sAMAccountName: {player_id}")
        ldif_entry.append(f"userPrincipalName: {player_id}@{ad_conn_domain}")
        ldif_entry.append(f"givenName: {new_values_from_csv['givenName']}")
        ldif_entry.append(f"sn: {new_values_from_csv['sn']}")
        ldif_entry.append(f"name: {new_values_from_csv['name']}")
        ldif_entry.append("userAccountControl: 512")
        ldif_entry.append(f"unicodePwd:: {base64_password}")

        # Other attributes
        for attr_name in attributes_to_write:
             if attr_name not in ['cn', 'sAMAccountName', 'userPrincipalName', 'givenName', 'sn', 'name']:
                 value_to_write = new_values_from_csv.get(attr_name)
                 if value_to_write is not None and value_to_write != "Unknown":
                     is_base64, encoded_val = encode_utf8_if_needed(value_to_write)
                     if is_base64: ldif_entry.append(f"{attr_name}:: {encoded_val}")
                     else: ldif_entry.append(f"{attr_name}: {value_to_write}")
    else: # Should not happen
         return None, "Internal Error"

    ldif_entry.append("")
    return "\n".join(ldif_entry), status_detail


# --- Main Processing Logic ---
def process_players(csv_path, player_container_dn, base64_password, output_dir, ad_snapshot,
                   dynamic_ad_attributes, calculated_ad_attributes_map, ad_conn_domain):
    """Process players CSV, generate LDIFs using AD snapshot and dynamic attributes."""
    processed_count = 0; generated_count = 0; skipped_no_change_count = 0; error_count = 0
    try:
        # Get total rows for progress
        with open(csv_path, newline="", encoding="utf-8-sig") as f_count:
            total_players = sum(1 for row in csv.DictReader(f_count) if row.get(CSV_PLAYER_ID_FIELD,"").strip()) # Count rows with playerID
            if total_players == 0: logging.warning("No players found in CSV file."); return 0

        logging.info(f"Processing {total_players} players from CSV...")
        GREEN = '\033[92m'; YELLOW = '\033[93m'; CYAN = '\033[96m'; RED = '\033[91m'; RESET = '\033[0m'

        with open(csv_path, newline="", encoding="utf-8-sig") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                processed_count += 1
                player_id = row.get(CSV_PLAYER_ID_FIELD, "unknown")
                status = "Processing..."; color = RESET; ldif = None; status_detail = "Init"

                # Minimal print before processing attempts
                print(f"\r[{processed_count}/{total_players}] {color}{player_id}: {status}{RESET}", end="      ", flush=True)

                try:
                    ldif, status_detail = create_player_ldif(
                        row, player_container_dn, base64_password, ad_snapshot,
                        dynamic_ad_attributes, calculated_ad_attributes_map, ad_conn_domain
                    )

                    if ldif:
                        output_file = os.path.join(output_dir, f"{player_id}.ldf")
                        with open(output_file, "w", encoding="ascii") as f: f.write(ldif)
                        generated_count += 1
                        # Set color based on final status detail from create_player_ldif
                        if status_detail == "New (Add)": color = GREEN
                        elif status_detail == "Exists (Modify)": color = YELLOW
                        else: color = YELLOW # Default if detail not perfectly matched
                    elif status_detail == "Exists (No Change)":
                        skipped_no_change_count += 1
                        color = CYAN
                    else: # Skipped due to input error (no playerID, no lastname)
                         error_count += 1 # Count as error/skip based on input
                         color = RED # Use red for input skips too

                    # Update final status line
                    print(f"\r[{processed_count}/{total_players}] {color}{player_id}: {status_detail}{RESET}", end="      ", flush=True)

                except Exception as e:
                    error_count += 1; status = "ERROR"; color = RED
                    print(f"\r[{processed_count}/{total_players}] {color}{player_id}: {status}{RESET}", end="      ", flush=True)
                    logging.error(f"\nError processing player {player_id}: {str(e)}", exc_info=True)
                    continue # Continue to next player

            print("\n") # Final newline
            logging.info(f"Processing Summary:")
            logging.info(f"  Total records processed: {processed_count}")
            logging.info(f"  LDF files generated: {generated_count}")
            logging.info(f"  Skipped (no changes): {skipped_no_change_count}")
            logging.info(f"  Skipped/Errors: {error_count}") # Combined input errors and processing exceptions
            return generated_count

    except (KeyboardInterrupt, SystemExit): print("\nOperation interrupted."); raise
    except Exception as e: logging.error(f"Critical error: {e}", exc_info=True); raise RuntimeError(f"Failed processing players CSV: {e}") from e

# --- Main Execution ---
def main():
    log_file = None; ad_conn = None
    try:
        log_file = setup_logging()
        logging.info("="*30 + " Starting LDIF Generator " + "="*30)
        args = parse_arguments()
        base64_password = encode_password(args.default_password)
        players_output_dir = args.players_output
        cache_file = get_cache_file_path(players_output_dir)

        # --- Backup and Clear Logic ---
        if os.path.exists(players_output_dir):
            is_empty = not any(os.scandir(players_output_dir))
            if not is_empty:
                backup_base_dir = os.path.join(os.path.dirname(players_output_dir), "ldf_backups")
                os.makedirs(backup_base_dir, exist_ok=True)
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_dest_dir = os.path.join(backup_base_dir, f"backup_{timestamp}")
                try:
                    logging.info(f"Backing up existing '{os.path.basename(players_output_dir)}' to '{backup_dest_dir}'...")
                    shutil.move(players_output_dir, backup_dest_dir)
                    logging.info(f"Backup complete.")
                except Exception as e:
                    logging.error(f"Backup failed: {e}", exc_info=True); sys.exit(f"Error during backup. Exiting.")
            else: logging.info(f"Output dir '{players_output_dir}' exists but is empty.")
        else: logging.info(f"Output dir '{players_output_dir}' does not exist.")
        try:
            os.makedirs(players_output_dir, exist_ok=True)
            logging.info(f"Ensured output directory exists: {players_output_dir}")
        except OSError as e: logging.error(f"Failed create output dir: {e}", exc_info=True); sys.exit("Error creating output dir.")
        # --- END Backup and Clear Logic ---

        # --- Get CSV Headers and Determine Dynamic Attributes ---
        try:
            with open(args.csv_path, newline="", encoding="utf-8-sig") as csvfile:
                 reader = csv.reader(csvfile); csv_headers = next(reader, [])
                 if not csv_headers: raise ValueError("People CSV is empty or has no header.")
            logging.info(f"Read {len(csv_headers)} headers from {args.csv_path}")
            # Assume direct mapping: CSV header name is the AD attribute name
            # Exclude known non-AD fields, ID field, calculation sources, and calculated targets
            all_calculated_target_attrs = set(CALCULATED_AD_ATTRIBUTES.values())
            dynamic_ad_attributes = [
                h for h in csv_headers
                if h != CSV_PLAYER_ID_FIELD and
                   h not in EXCLUDED_CSV_HEADERS and
                   h not in CALCULATION_SOURCE_HEADERS and
                   h not in all_calculated_target_attrs # Avoid adding 'cn', 'displayName' etc. if they are headers
            ]
            logging.info(f"Dynamically determined {len(dynamic_ad_attributes)} AD attributes from headers: {dynamic_ad_attributes}")
        except Exception as e: logging.error(f"Failed CSV header processing: {e}", exc_info=True); sys.exit("Error processing CSV.")
        # --- End Dynamic Attribute Determination ---

        # --- Initialize AD connection ---
        try:
            ad_conn = ADConnection(
                server=args.ldap_server, base_dn=args.domain_dn, domain=args.domain,
                username=args.ldap_user, password=args.ldap_password
            )
        except ADConnectionError as e: logging.error(f"AD connection failed: {e}"); sys.exit(1)

        # --- Create OU structure ---
        player_container_dn = create_ou_ldif(
            args.ou_csv_path, args.domain_dn, args.ou_output, args.players_ou_name
        )
        if not player_container_dn: logging.error("Failed to determine player container DN from OU structure"); sys.exit(1)
        logging.info(f"Target container DN for players: {player_container_dn}")

        # --- Build or Load AD Snapshot ---
        ad_snapshot = None
        if not args.force_refresh:
             ad_snapshot = verify_and_load_cache(cache_file, args.max_cache_age)

        if ad_snapshot is None:
            logging.info("Refreshing AD snapshot from Active Directory...")
            attributes_to_fetch_now = list(CALCULATED_AD_ATTRIBUTES.values()) + dynamic_ad_attributes
            attributes_to_fetch_now = sorted(list(set([AD_SAMACCOUNTNAME_ATTR] + attributes_to_fetch_now)))

            ad_snapshot = ad_conn.build_ad_snapshot(player_container_dn, attributes_to_fetch_now)

            if ad_snapshot is not None: # Query succeeded (even if empty result)
                 save_cache(cache_file, ad_snapshot)
            else: # Query itself failed
                 logging.error("Snapshot build failed. Cannot proceed with accurate comparisons.")
                 sys.exit("Failed to build necessary AD snapshot.")
        # --- End Build AD Snapshot ---

        # After building/loading snapshot, add debug info
        if 'aardsda01' in ad_snapshot:
            logging.debug("--- Initial Snapshot data for aardsda01 ---")
            logging.debug(json.dumps(ad_snapshot['aardsda01'], indent=2))
        else:
            logging.debug("aardsda01 not found in initial snapshot")

        # --- Process players ---
        try:
            start_process_time = time.time()
            files_generated_count = process_players(
                args.csv_path, player_container_dn, base64_password, players_output_dir,
                ad_snapshot, dynamic_ad_attributes, CALCULATED_AD_ATTRIBUTES, ad_conn.domain
            )
            end_process_time = time.time()
            logging.info(f"Player processing completed in {end_process_time - start_process_time:.2f} seconds.")
            logging.info(f"Generated {files_generated_count} LDF files requiring changes.")
        except RuntimeError as e: logging.error(f"Player processing failed: {e}"); sys.exit(1)

        logging.info("LDIF Generator finished successfully.")

    except KeyboardInterrupt: logging.error("Operation cancelled by user"); sys.exit(1)
    except SystemExit as e:
        if e.code and e.code != 0: logging.error(f"Script exited with error code {e.code}.")
    except Exception as e:
        logging.critical(f"An unexpected fatal error occurred: {str(e)}", exc_info=True)
        sys.exit(1) # Ensure exit on critical failure
    finally:
        if log_file: logging.info(f"Log file location: {log_file}")
        logging.info("="*30 + " Script Execution Ended " + "="*30)


if __name__ == "__main__":
    main()