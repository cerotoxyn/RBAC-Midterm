# Secure RBAC Encryption Project
Required video to demonstrate how the script works: https://drive.google.com/file/d/19Y1vZY83hbvX9mQynveqyyjrdo1-d08O/view?usp=sharing

## CIA Triad Explanation

This project protects **confidentiality** by encrypting messages with AES so other people cannot read them. It also limits certain features based on user role, which helps keep sensitive information private.

It protects **integrity** by using SHA-256 hashing. The program checks whether the message stayed the same by comparing the original hash to the hash after decryption. The digital signature also helps prove the message was not altered.

It supports **availability** by making the system accessible to authorized users through login. Users with the correct permissions can use the program when needed, while the system blocks unauthorized actions.

## Overview
This project is a simple Python application that demonstrates user login, role-based access control, hashing, encryption, decryption, and integrity verification. It was created to show basic cybersecurity concepts in action, including confidentiality, integrity, availability, entropy, and digital signatures.

## Features
- User login with predefined accounts
- Role-based access control
- SHA-256 hashing for integrity checking
- AES encryption for confidentiality
- AES decryption for authorized users
- Hash comparison to verify integrity
- Digital signature demonstration using public/private keys
- Simple substitution cipher example

## Requirements
- Python 3.10 or newer
- Required packages listed in `requirements.txt`

## Installation
1. Open the project folder in a terminal.
2. Install the required package:

```bash
pip install -r requirements.txt
