# MLB Active Directory Schema Automation

**Automates the process of analyzing MLB statistical data and creating appropriate AD schema extensions and auxiliary classes.**  

This project **lays the foundation** for a broader **Active Directory (AD) Inventory Federation**, enabling **multi-forest asset synchronization** into a central **inventory forest** (`inventoryad.local`).  
The MLB dataset serves as a **test case** to prove out the **schema extension process**, paving the way for real-world IT inventory.

---

## 📌 Purpose

This toolset automatically analyzes **CSV files containing MLB statistics** and:

1. **Determines optimal AD attribute types**.
2. **Creates auxiliary classes** for different MLB entities (**Players, Teams, Stats**).
3. **Generates LDIF files** for schema extension and data import.
4. **Handles the import process** into Active Directory.

Once tested on MLB data, this process can be **scaled** to real **enterprise-wide Active Directory inventory federation**.

---

## 🔧 Prerequisites

- **Windows Server** with **Active Directory Domain Services (AD DS)**.
- **PowerShell 5.1 or higher**.
- **Schema Admin rights** in AD (**required for schema modifications**).
- **CSV files** containing MLB data (from [Lahman Baseball Database](http://www.seanlahman.com/baseball-archive/statistics/)).
- **LDIFDE.exe utility** (included with Windows Server).

⚠️ **Important**: Schema extensions are **permanent**. Test in a lab environment first.

---

## 📁 Project Structure

| File                        | Description                                           |
|-----------------------------|-------------------------------------------------------|
| `Build-1stDC.ps1`           | Builds the **first domain controller**.              |
| `Get-CsvSchemaAnalysis.ps1` | **Analyzes CSV files** to determine schema.          |
| `setupdc_2k5.ps1`           | **Initial DC setup and configuration.**              |
| `New-ADSchemaCSV.ps1`       | **Generates schema definitions in CSV format.**      |
| `New-LDIFSchema.ps1`        | **Creates an LDIF file for schema extension.**       |
| `New-LDIFUsers.ps1`         | **Generates an LDIF file for importing users.**      |
| `Import-LDIF.ps1`           | **Executes `ldifde` to apply schema changes.**       |

---

## 📂 Schema Directory Structure

The `.\schema` directory contains all schema-related files:

| File                      | Description                                           |
|--------------------------|-------------------------------------------------------|
| `mlb_schema.ldf`         | **Active Directory schema extensions** ready for LDIFDE import |
| `mlb_schema_analysis.csv`| **Detailed attribute analysis** with inferred types   |

This centralized location ensures:
- **Clean organization** of schema artifacts
- **Easy tracking** of schema versions
- **Simple cleanup** of old schema files
- **Clear separation** from source data

---

## 🎯 Type Inference Rules

The schema analysis employs sophisticated type inference:

### **Pattern Recognition**
- **Numbers**:
  - Integers: `-123`, `456`
  - Decimals: `0.123`, `-45.67`
  - Statistics: `.345`, `.123`
- **Dates**:
  - ISO Format: `YYYY-MM-DD`
  - Short Format: `MM/DD/YYYY`
  - Year Only: `YYYY`
- **Booleans**:
  - Binary: `0/1`
  - Text: `Y/N`, `True/False`
  - Empty/Filled: `""/Value`
- **MultiValue**:
  - Comma Lists: `value1,value2`
  - Semi-colon Lists: `value1;value2`
  - Space Separated: `value1 value2`

### **Special Cases**
- **Baseball Statistics**:
  - Batting Averages: `.200` - `.400`
  - ERA: `0.00` - `99.99`
  - Win-Loss: `W`, `L`
- **Empty Values**:
  - Nulls: `NULL`, `null`
  - Blanks: `""`, `''`
  - Special: `N/A`, `None`

---

## 🚀 Quick Start

### **1️⃣ Setup Your Domain Controller**
```powershell
.\setupdc_2k5.ps1
.\Build-1stDC.ps1 -FQDN "mlb.local"
```

### **2️⃣ Analyze Your CSV Files**
```powershell
Get-CsvSchema -FolderPath "C:\data\mlb\baseballdatabank" -OutputPath "C:\data\mlb\schema_analysis.csv"
```

### **3️⃣ Generate and Import LDIF**
```powershell
# Generate schema LDIF
.\New-LDIFSchema.ps1 -SchemaCSV "C:\data\mlb\schema_analysis.csv" -LDIFFile "C:\data\mlb\mlb_schema.ldf"

# Import schema using LDIFDE
.\Import-LDIF.ps1 -SchemaLDIF "C:\data\mlb\mlb_schema.ldf" -Domain "mlb.local"
```

---

## 🔬 Schema Analysis

The `Get-CsvSchemaAnalysis.ps1` script:
- **Analyzes CSV files** to determine attribute types.
- **Creates appropriate auxiliary class names**.
- **Handles MLB-specific data patterns**.
- **Generates a comprehensive schema analysis**.

### **Data Types**
- **Integer** (years, counts, statistics)
- **DateTime** (dates, debuts, games)
- **Boolean** (status flags)
- **MultiValue** (comma-separated values)
- **String** (default type)

### **Auxiliary Class**
All attributes are assigned to a **single auxiliary class**:  
- `auxMLB`

### **Special Mappings**
Handles specific MLB data files:
- `People.csv` → **auxMLB**
- `Batting.csv` → **auxMLB**
- `Pitching.csv` → **auxMLB**
- `Teams.csv` → **auxMLB**
- `Managers.csv` → **auxMLB**

---

## 🛡️ LDAP Security & Best Practices

### **1️⃣ LDIFDE Operations**
- **Import Mode**: `-i -f schema.ldf`
- **Export Mode**: `-f export.ldf -s server`
- **Secure Import**: `-i -k` (ignore errors)
- **SSL/TLS**: `-t 636` (LDAPS port)

### **2️⃣ Security Measures**
- Use **LDAPS (636)** instead of LDAP (389)
- Enable **Extended Protection** for LDAP
- Set **minimum authentication** to `Negotiate Signing`
- Configure **LDAP Signing Requirements**

### **3️⃣ Network Security**
- **Required Ports**:
  - TCP/UDP 636 (LDAPS) between domains
  - TCP/UDP 389 (LDAP) if needed
  - TCP 3268/3269 (Global Catalog)
- **Firewall Rules**:
  - Allow only trusted domain controllers
  - Restrict by IP/subnet
  - Monitor LDAP traffic

### **4️⃣ Service Accounts**
- Create **dedicated service accounts**
- Grant **minimum required permissions**
- Use **managed service accounts** (MSAs)
- Enable **Kerberos authentication**

---

## ⚠️ Limitations & Troubleshooting

### **Schema Limits**
- Attribute names: **64 chars max**
- SAM account names: **20 chars max**
- DN path length: **255 chars max**

### **Common Issues**
1. **LDIFDE Errors**:
   ```powershell
   # Check syntax
   ldifde -i -f schema.ldf -v
   # Force import
   ldifde -i -f schema.ldf -k
   ```

2. **Permission Issues**:
   ```powershell
   # Verify Schema Admin
   Get-ADGroupMember "Schema Admins"
   # Register schema DLL
   regsvr32 schmmgmt.dll
   ```

3. **Replication**:
   ```powershell
   # Force replication
   repadmin /syncall /AdeP
   # Check status
   repadmin /showrepl
   ```

---

## 🛠 Active Directory Federation

### **Core Components**
1. **Schema Extensions**:
   - `auxMLB` for MLB data
   - `auxInventory` for IT assets

2. **Sync Process**:
   ```powershell
   # Export from source
   ldifde -f export.ldf -s sourcedc.domain
   # Import to inventory
   ldifde -i -f export.ldf -s inventorydc.local
   ```

3. **Security**:
   - **TLS 1.2/1.3** required
   - **Mutual authentication**
   - **Channel binding**
   - **LDAP signing**

### **Real-World IT Example**
Consider a global company with **multiple AD forests**:
```plaintext
CompanyA.com
├── Users: 50,000
├── Computers: 75,000
└── Service Accounts: 1,000

CompanyB.com
├── Users: 25,000
├── Computers: 30,000
└── Service Accounts: 500
```

Using AD Federation, all assets sync to `inventoryad.local`:
- **Real-time inventory** of all AD objects
- **Instant search** across all forests
- **Security monitoring** for compromised accounts
- **Compliance reporting** across domains

---

## 🔥 Next Steps: From MLB to Full IT Inventory

Once the MLB schema automation is proven:
1. **Corporate IT Assets**
   - Users, Computers, Groups
   - Printers, Service Accounts
   - Group Policies, DNS Records

2. **Multi-Forest Integration**
   - Schema mapping between forests
   - Secure LDAPS synchronization
   - Real-time inventory updates

3. **Enterprise Features**
   - Security & compliance auditing
   - Help desk integration
   - Asset lifecycle tracking

The MLB dataset proves the concept—next stop: **full enterprise IT inventory federation**!

---

## 📜 License
**MIT License** – See `LICENSE` file for details.