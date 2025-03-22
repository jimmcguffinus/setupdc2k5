Here's a **README.md** for your **Build-1stDc** project. This document explains the purpose, prerequisites, and usage of your script.  

---

## **Build-1stDc**

### **📌 Overview**
The **Build-1stDc** script automates the process of **demoting** a **Domain Controller (DC)** and optionally **restoring** the local Administrator profile. It is designed to:
- **Demote a DC** while preserving key configurations.
- **Create a local administrator account** before demotion.
- **Backup and restore the Administrator profile** to avoid login issues.
- **Prepare the server for re-promotion** as a DC.

This script is **ideal** for **testing lab environments** where you need to flip between domain roles **without losing configurations**.

---

### **📋 Prerequisites**
- **Windows Server 2016/2019/2022**
- **PowerShell 7.0+**
- **Active Directory Domain Services (AD DS) Installed**
- **Administrator Privileges**
- **Ensure no FSMO roles exist on this DC before demotion (unless it's the last DC in the forest).**  
  _(Check FSMO roles: `netdom query fsmo`)_

---

### **🚀 Usage**
#### **1️⃣ Run the script to demote the DC**
```powershell
.\Build-1stDc.ps1 -Demote
```
This will:
- **Backup the Administrator profile & SID**  
- **Create a backup local administrator account (`AdminBackup`)**  
- **Demote the DC using `Uninstall-ADDSDomainController`**  
- **Restart the system after completion**  

> **⚠️ WARNING:** This **will force a reboot** after demotion!

---

#### **2️⃣ Run the script to restore Administrator profile**
After demotion, to **restore the original Administrator profile**:
```powershell
.\Build-1stDc.ps1
```
This will:
- **Reapply the Administrator profile registry backup**
- **Fix permissions for `C:\Users\Administrator`**
- **Restore profile ownership & permissions (`takeown`, `icacls`)**
- **Ensure seamless login post-demotion**

---

### **🔄 Re-Promotion as a DC**
If you want to **re-promote the server back as a DC**, run:
```powershell
Install-ADDSForest -DomainName "mlb.dev"
```
> **Note:** You may need to **import back your schema extensions** if they were modified.

---

### **🔧 Additional Commands**
#### **Check Current Edition & Days Left**
```powershell
slmgr /dlv
```
#### **Extend Evaluation License (if applicable)**
```powershell
slmgr /rearm
Restart-Computer
```
> **This may reset the trial period** (works up to 5 times on some eval editions).

#### **Check If System is a DC**
```powershell
(Get-WmiObject Win32_ComputerSystem).DomainRole
```
- `0-3` = Workgroup  
- `4-5` = Domain Controller  

---

### **📌 Notes**
- If the **old DC still exists**, ensure proper **metadata cleanup** (`ntdsutil`).
- If **rejoining the same domain**, make sure to reset the computer account in **Active Directory Users & Computers**.
- **Never run `sysprep /generalize /oobe` on a DC!** It will break AD DS.

---

### **📜 License**
This script is provided **as-is**, with **no warranties**. Use at your own risk.  
For any improvements or issues, feel free to contribute!

---

### **💬 Author**
**Jim McGuffin**  
Flint, MI | `mlb.dev`  

🚀 _“Because sometimes you just gotta flip the DC down and up like a champ.”_  

---

Let me know if you want any refinements! 🎯