#!/usr/bin/env python3
"""
Test Active Directory connectivity using pyad library and generate LDIF entries.
"""

from pyad import *
import logging
import sys
from datetime import datetime

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# AD domain details
domain = "mlb.dev"

def generate_ldif_add(user_dn, attributes):
    """Generate LDIF entry for adding a new user."""
    ldif = f"dn: {user_dn}\n"
    ldif += "changetype: add\n"
    ldif += "objectClass: user\n"
    ldif += "objectClass: top\n"
    ldif += "objectClass: person\n"
    ldif += "objectClass: organizationalPerson\n"
    
    for key, value in attributes.items():
        if value:  # Only add non-empty values
            ldif += f"{key}: {value}\n"
    
    return ldif

def generate_ldif_modify(user_dn, attributes):
    """Generate LDIF entry for modifying an existing user."""
    ldif = f"dn: {user_dn}\n"
    ldif += "changetype: modify\n"
    
    for key, value in attributes.items():
        if value:  # Only add non-empty values
            ldif += f"replace: {key}\n"
            ldif += f"{key}: {value}\n"
            ldif += "-\n"
    
    return ldif

print(f"Connecting to AD domain {domain} using current Windows credentials...")

try:
    # Initialize pyad with the domain
    pyad.set_defaults(ldap_server=domain)
    
    # Test user data
    test_users = [
        {
            "username": "testuser1",
            "givenName": "Test",
            "sn": "User1",
            "displayName": "Test User1",
            "userPrincipalName": "testuser1@mlb.dev",
            "mail": "testuser1@mlb.dev",
            "department": "IT",
            "title": "Test Engineer"
        },
        {
            "username": "testuser2",
            "givenName": "Test",
            "sn": "User2",
            "displayName": "Test User2",
            "userPrincipalName": "testuser2@mlb.dev",
            "mail": "testuser2@mlb.dev",
            "department": "HR",
            "title": "HR Specialist"
        }
    ]
    
    print("\nChecking users and generating LDIF entries...")
    
    # Create LDIF file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ldif_file = f"user_changes_{timestamp}.ldif"
    
    with open(ldif_file, 'w') as f:
        for user_data in test_users:
            username = user_data["username"]
            user_dn = f"CN={user_data['displayName']},CN=Users,DC=mlb,DC=dev"
            
            # Check if user exists
            q = adquery.ADQuery()
            q.execute_query(
                attributes=["distinguishedName"],
                where_clause=f"sAMAccountName = '{username}'",
                base_dn="DC=mlb,DC=dev"
            )
            
            results = q.get_results()
            
            if not results:
                # User doesn't exist, generate add LDIF
                print(f"\nGenerating LDIF for new user: {username}")
                ldif_entry = generate_ldif_add(user_dn, user_data)
                f.write(ldif_entry + "\n")
            else:
                # User exists, generate modify LDIF
                print(f"\nGenerating LDIF for existing user: {username}")
                ldif_entry = generate_ldif_modify(user_dn, user_data)
                f.write(ldif_entry + "\n")
    
    print(f"\nLDIF file generated: {ldif_file}")
    print("\nQuery completed successfully.")
    
except Exception as e:
    print("\nError occurred:", str(e))
    print("\nError type:", type(e).__name__)
    if hasattr(e, 'args'):
        print("Error args:", e.args)
    print("\nTroubleshooting tips:")
    print("1. Verify you are logged in with a domain account")
    print("2. Check if the domain is reachable (ping mlb.dev)")
    print("3. Verify domain name:", domain)
    print("\nConnection details used:")
    print(f"Domain: {domain}")
    print("Authentication: Using current Windows credentials")
    sys.exit(1) 