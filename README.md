# Process Ghosting - PoC

This repository contains a proof-of-concept (PoC) implementation of **Process Ghosting**, a Windows technique used to execute malicious code while bypassing traditional on-disk detection mechanisms.

## 📌 Description

**Process Ghosting** is a technique that abuses how Windows handles process creation and image section mapping. It allows an attacker to create a process from a file that has already been deleted (or overwritten), effectively executing code that no longer exists on disk.

This PoC demonstrates the core steps involved in:

- Creating a delete-pending file
- Writing a malicious payload to it
- Mapping the payload into memory
- Executing the process without leaving a readable artifact on disk

> ⚠️ For educational and research purposes only.

## 🛠️ Requirements

- Windows 10 (x64)
- Visual Studio or Mingw for compilation
- Administrator privileges

## 🔧 Build
- check cmake config