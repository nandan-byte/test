"""
SCA Category Mapper

Intelligently maps Trivy SCA vulnerabilities to appropriate security categories
based on CVE description, CWE ID, package name, and vulnerability characteristics.

This mapper ensures each SCA vulnerability is assigned to the correct category
(Injection, Cryptography, DoS, etc.) instead of defaulting to "Infrastructure Security".
"""

import re
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class SCACategoryMapper:
    """Maps SCA vulnerabilities to security categories based on vulnerability characteristics."""
    
    def __init__(self):
        """Initialize category mapping rules."""
        # CWE to Category mapping (Common Weakness Enumeration)
        # Source: https://cwe.mitre.org/ and SANS/CWE Top 25
        # Comprehensive mapping covering all major vulnerability categories
        self.cwe_mappings = {
            # ============================================================
            # INJECTION VULNERABILITIES (SANS Top 25: #2, #3, #5, #16)
            # ============================================================
            'CWE-79': 'Injection',    # XSS - Cross-site Scripting (SANS #2)
            'CWE-89': 'Injection',    # SQL Injection (SANS #3)
            'CWE-78': 'Injection',    # OS Command Injection (SANS #5)
            'CWE-77': 'Injection',    # Command Injection (SANS #16)
            'CWE-91': 'Injection',    # XML Injection
            'CWE-94': 'Injection',    # Code Injection
            'CWE-95': 'Injection',    # PHP Code Injection
            'CWE-917': 'Injection',   # Expression Language Injection
            'CWE-90': 'Injection',    # LDAP Injection
            'CWE-943': 'Injection',   # NoSQL Injection
            'CWE-184': 'Injection',   # Incomplete List of Disallowed Inputs
            'CWE-1321': 'Injection',  # Prototype Pollution
            'CWE-74': 'Injection',    # Improper Neutralization of Special Elements
            'CWE-75': 'Injection',    # Failure to Sanitize Special Elements into a Different Plane
            'CWE-76': 'Injection',    # Improper Neutralization of Equivalent Special Elements
            'CWE-80': 'Injection',    # Improper Neutralization of Script-Related HTML Tags
            'CWE-81': 'Injection',    # Improper Neutralization of Script in Error Message
            'CWE-82': 'Injection',    # Improper Neutralization of Script in Attributes
            'CWE-83': 'Injection',    # Improper Neutralization of Script in Attributes in Web Page
            'CWE-84': 'Injection',    # Improper Neutralization of Encoded URI Schemes
            'CWE-85': 'Injection',    # Doubled Character XSS
            'CWE-86': 'Injection',    # Improper Neutralization of Invalid Characters in Identifiers
            'CWE-87': 'Injection',    # Improper Neutralization of Alternate XSS Syntax
            'CWE-88': 'Injection',    # Improper Neutralization of Argument Delimiters
            'CWE-93': 'Injection',    # Improper Neutralization of CRLF Sequences
            'CWE-96': 'Injection',    # Improper Neutralization of Directives in Statically Saved Code
            'CWE-97': 'Injection',    # Improper Neutralization of Server-Side Includes
            'CWE-98': 'Injection',    # Improper Control of Filename for Include/Require Statement
            'CWE-99': 'Injection',    # Improper Control of Resource Identifiers
            
            # ============================================================
            # AUTHENTICATION & SESSION MANAGEMENT (SANS Top 25: #13)
            # ============================================================
            'CWE-287': 'Authentication & Session Management',  # Improper Authentication (SANS #13)
            'CWE-306': 'Authentication & Session Management',  # Missing Authentication for Critical Function
            'CWE-307': 'Authentication & Session Management',  # Improper Restriction of Excessive Authentication Attempts
            'CWE-384': 'Authentication & Session Management',  # Session Fixation
            'CWE-613': 'Authentication & Session Management',  # Insufficient Session Expiration
            'CWE-798': 'Authentication & Session Management',  # Use of Hard-coded Credentials (SANS #24)
            'CWE-620': 'Authentication & Session Management',  # Unverified Password Change
            'CWE-640': 'Authentication & Session Management',  # Weak Password Recovery Mechanism
            'CWE-521': 'Authentication & Session Management',  # Weak Password Requirements
            'CWE-522': 'Authentication & Session Management',  # Insufficiently Protected Credentials
            'CWE-523': 'Authentication & Session Management',  # Unprotected Transport of Credentials
            'CWE-549': 'Authentication & Session Management',  # Missing Password Field Masking
            'CWE-555': 'Authentication & Session Management',  # J2EE Misconfiguration: Plaintext Password in Configuration File
            'CWE-556': 'Authentication & Session Management',  # ASP.NET Misconfiguration: Use of Identity Impersonation
            'CWE-620': 'Authentication & Session Management',  # Unverified Password Change
            'CWE-640': 'Authentication & Session Management',  # Weak Password Recovery Mechanism for Forgotten Password
            'CWE-645': 'Authentication & Session Management',  # Overly Restrictive Account Lockout Mechanism
            'CWE-836': 'Authentication & Session Management',  # Use of Password Hash Instead of Password for Authentication
            'CWE-916': 'Authentication & Session Management',  # Use of Password Hash With Insufficient Computational Effort
            
            # ============================================================
            # AUTHORIZATION & ACCESS CONTROL (SANS Top 25: #11, #17, #18, #19, #21, #23)
            # ============================================================
            'CWE-862': 'API Security',  # Missing Authorization (SANS #11)
            'CWE-863': 'API Security',  # Incorrect Authorization (SANS #17)
            'CWE-639': 'API Security',  # Authorization Bypass Through User-Controlled Key (SANS #18)
            'CWE-269': 'API Security',  # Improper Privilege Management (SANS #19)
            'CWE-284': 'API Security',  # Improper Access Control (SANS #21)
            'CWE-276': 'API Security',  # Incorrect Default Permissions (SANS #23)
            'CWE-285': 'API Security',  # Improper Authorization
            'CWE-352': 'API Security',  # CSRF - Cross-Site Request Forgery (SANS #9)
            'CWE-918': 'API Security',  # SSRF - Server-Side Request Forgery (SANS #19)
            'CWE-601': 'API Security',  # URL Redirection to Untrusted Site (Open Redirect)
            'CWE-266': 'API Security',  # Incorrect Privilege Assignment
            'CWE-267': 'API Security',  # Privilege Defined With Unsafe Actions
            'CWE-268': 'API Security',  # Privilege Chaining
            'CWE-270': 'API Security',  # Privilege Context Switching Error
            'CWE-271': 'API Security',  # Privilege Dropping / Lowering Errors
            'CWE-272': 'API Security',  # Least Privilege Violation
            'CWE-273': 'API Security',  # Improper Check for Dropped Privileges
            'CWE-274': 'API Security',  # Improper Handling of Insufficient Privileges
            'CWE-275': 'API Security',  # Permission Issues
            'CWE-277': 'API Security',  # Insecure Inherited Permissions
            'CWE-278': 'API Security',  # Insecure Preserved Inherited Permissions
            'CWE-279': 'API Security',  # Incorrect Execution-Assigned Permissions
            'CWE-280': 'API Security',  # Improper Handling of Insufficient Permissions
            'CWE-281': 'API Security',  # Improper Preservation of Permissions
            'CWE-282': 'API Security',  # Improper Ownership Management
            'CWE-283': 'API Security',  # Unverified Ownership
            
            # ============================================================
            # CRYPTOGRAPHY (SANS Top 25: #24)
            # ============================================================
            'CWE-327': 'Cryptography',  # Use of a Broken or Risky Cryptographic Algorithm
            'CWE-328': 'Cryptography',  # Use of Weak Hash
            'CWE-329': 'Cryptography',  # Generation of Predictable IV with CBC Mode
            'CWE-330': 'Cryptography',  # Use of Insufficiently Random Values
            'CWE-326': 'Cryptography',  # Inadequate Encryption Strength
            'CWE-321': 'Cryptography',  # Use of Hard-coded Cryptographic Key
            'CWE-322': 'Cryptography',  # Key Exchange without Entity Authentication
            'CWE-323': 'Cryptography',  # Reusing a Nonce, Key Pair in Encryption
            'CWE-338': 'Cryptography',  # Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
            'CWE-310': 'Cryptography',  # Cryptographic Issues
            'CWE-311': 'Cryptography',  # Missing Encryption of Sensitive Data
            'CWE-313': 'Cryptography',  # Cleartext Storage in a File or on Disk
            'CWE-314': 'Cryptography',  # Cleartext Storage in the Registry
            'CWE-315': 'Cryptography',  # Cleartext Storage of Sensitive Information in a Cookie
            'CWE-316': 'Cryptography',  # Cleartext Storage of Sensitive Information in Memory
            'CWE-317': 'Cryptography',  # Cleartext Storage of Sensitive Information in GUI
            'CWE-318': 'Cryptography',  # Cleartext Storage of Sensitive Information in Executable
            'CWE-324': 'Cryptography',  # Use of a Key Past its Expiration Date
            'CWE-325': 'Cryptography',  # Missing Cryptographic Step
            'CWE-331': 'Cryptography',  # Insufficient Entropy
            'CWE-332': 'Cryptography',  # Insufficient Entropy in PRNG
            'CWE-333': 'Cryptography',  # Improper Handling of Insufficient Entropy in TRNG
            'CWE-334': 'Cryptography',  # Small Space of Random Values
            'CWE-335': 'Cryptography',  # Incorrect Usage of Seeds in Pseudo-Random Number Generator
            'CWE-336': 'Cryptography',  # Same Seed in Pseudo-Random Number Generator
            'CWE-337': 'Cryptography',  # Predictable Seed in Pseudo-Random Number Generator
            'CWE-339': 'Cryptography',  # Small Seed Space in PRNG
            'CWE-340': 'Cryptography',  # Generation of Predictable Numbers or Identifiers
            'CWE-341': 'Cryptography',  # Predictable from Observable State
            'CWE-342': 'Cryptography',  # Predictable Exact Value from Previous Values
            'CWE-343': 'Cryptography',  # Predictable Value Range from Previous Values
            'CWE-344': 'Cryptography',  # Use of Invariant Value in Dynamically Changing Context
            'CWE-345': 'Cryptography',  # Insufficient Verification of Data Authenticity
            'CWE-346': 'Cryptography',  # Origin Validation Error
            'CWE-347': 'Cryptography',  # Improper Verification of Cryptographic Signature
            'CWE-348': 'Cryptography',  # Use of Less Trusted Source
            'CWE-349': 'Cryptography',  # Acceptance of Extraneous Untrusted Data With Trusted Data
            'CWE-350': 'Cryptography',  # Reliance on Reverse DNS Resolution for a Security-Critical Action
            'CWE-351': 'Cryptography',  # Insufficient Type Distinction
            
            # ============================================================
            # DENIAL OF SERVICE (SANS Top 25: #20, #25)
            # ============================================================
            'CWE-400': 'Denial of Service (DoS)',  # Uncontrolled Resource Consumption (SANS #20)
            'CWE-770': 'Denial of Service (DoS)',  # Allocation of Resources Without Limits or Throttling
            'CWE-835': 'Denial of Service (DoS)',  # Loop with Unreachable Exit Condition (Infinite Loop) (SANS #25)
            'CWE-1333': 'Denial of Service (DoS)', # Inefficient Regular Expression Complexity (ReDoS)
            'CWE-674': 'Denial of Service (DoS)',  # Uncontrolled Recursion
            'CWE-405': 'Denial of Service (DoS)',  # Asymmetric Resource Consumption (Amplification)
            'CWE-410': 'Denial of Service (DoS)',  # Insufficient Resource Pool
            'CWE-665': 'Denial of Service (DoS)',  # Improper Initialization
            'CWE-730': 'Denial of Service (DoS)',  # OWASP Top Ten 2004 Category A9 - Denial of Service
            'CWE-834': 'Denial of Service (DoS)',  # Excessive Iteration
            'CWE-1050': 'Denial of Service (DoS)', # Excessive Platform Resource Consumption within a Loop
            'CWE-1073': 'Denial of Service (DoS)', # Non-SQL Invokable Control Element with Excessive Volume of Commented-out Code
            'CWE-1088': 'Denial of Service (DoS)', # Synchronous Access of Remote Resource without Timeout
            'CWE-1176': 'Denial of Service (DoS)', # Inefficient CPU Computation
            
            # ============================================================
            # INPUT VALIDATION (SANS Top 25: #1, #4, #6, #7, #8, #10, #14, #15)
            # ============================================================
            'CWE-787': 'Input Validation',  # Out-of-bounds Write (SANS #1)
            'CWE-416': 'Input Validation',  # Use After Free (SANS #4)
            'CWE-20': 'Input Validation',   # Improper Input Validation (SANS #6)
            'CWE-125': 'Input Validation',  # Out-of-bounds Read (SANS #7)
            'CWE-22': 'Input Validation',   # Path Traversal (SANS #8)
            'CWE-434': 'Input Validation',  # Unrestricted Upload of File with Dangerous Type (SANS #10)
            'CWE-190': 'Input Validation',  # Integer Overflow or Wraparound (SANS #14)
            'CWE-502': 'Input Validation',  # Deserialization of Untrusted Data (SANS #15)
            'CWE-129': 'Input Validation',  # Improper Validation of Array Index
            'CWE-611': 'Input Validation',  # Improper Restriction of XML External Entity Reference (XXE)
            'CWE-120': 'Input Validation',  # Buffer Copy without Checking Size of Input (Classic Buffer Overflow)
            'CWE-241': 'Input Validation',  # Improper Handling of Unexpected Data Type
            'CWE-119': 'Input Validation',  # Improper Restriction of Operations within the Bounds of a Memory Buffer
            'CWE-121': 'Input Validation',  # Stack-based Buffer Overflow
            'CWE-122': 'Input Validation',  # Heap-based Buffer Overflow
            'CWE-123': 'Input Validation',  # Write-what-where Condition
            'CWE-124': 'Input Validation',  # Buffer Underwrite
            'CWE-126': 'Input Validation',  # Buffer Over-read
            'CWE-127': 'Input Validation',  # Buffer Under-read
            'CWE-128': 'Input Validation',  # Wrap-around Error
            'CWE-130': 'Input Validation',  # Improper Handling of Length Parameter Inconsistency
            'CWE-131': 'Input Validation',  # Incorrect Calculation of Buffer Size
            'CWE-134': 'Input Validation',  # Use of Externally-Controlled Format String
            'CWE-135': 'Input Validation',  # Incorrect Calculation of Multi-Byte String Length
            'CWE-170': 'Input Validation',  # Improper Null Termination
            'CWE-172': 'Input Validation',  # Encoding Error
            'CWE-173': 'Input Validation',  # Improper Handling of Alternate Encoding
            'CWE-174': 'Input Validation',  # Double Decoding of the Same Data
            'CWE-175': 'Input Validation',  # Improper Handling of Mixed Encoding
            'CWE-176': 'Input Validation',  # Improper Handling of Unicode Encoding
            'CWE-177': 'Input Validation',  # Improper Handling of URL Encoding (Hex Encoding)
            'CWE-178': 'Input Validation',  # Improper Handling of Case Sensitivity
            'CWE-179': 'Input Validation',  # Incorrect Behavior Order: Early Validation
            'CWE-180': 'Input Validation',  # Incorrect Behavior Order: Validate Before Canonicalize
            'CWE-181': 'Input Validation',  # Incorrect Behavior Order: Validate Before Filter
            'CWE-182': 'Input Validation',  # Collapse of Data into Unsafe Value
            'CWE-183': 'Input Validation',  # Permissive List of Allowed Inputs
            'CWE-185': 'Input Validation',  # Incorrect Regular Expression
            'CWE-186': 'Input Validation',  # Overly Restrictive Regular Expression
            'CWE-187': 'Input Validation',  # Partial String Comparison
            'CWE-188': 'Input Validation',  # Reliance on Data/Memory Layout
            'CWE-189': 'Input Validation',  # Numeric Errors
            'CWE-191': 'Input Validation',  # Integer Underflow (Wrap or Wraparound)
            'CWE-192': 'Input Validation',  # Integer Coercion Error
            'CWE-193': 'Input Validation',  # Off-by-one Error
            'CWE-194': 'Input Validation',  # Unexpected Sign Extension
            'CWE-195': 'Input Validation',  # Signed to Unsigned Conversion Error
            'CWE-196': 'Input Validation',  # Unsigned to Signed Conversion Error
            'CWE-197': 'Input Validation',  # Numeric Truncation Error
            'CWE-198': 'Input Validation',  # Use of Incorrect Byte Ordering
            'CWE-242': 'Input Validation',  # Use of Inherently Dangerous Function
            'CWE-243': 'Input Validation',  # Creation of chroot Jail Without Changing Working Directory
            'CWE-244': 'Input Validation',  # Improper Clearing of Heap Memory Before Release
            'CWE-252': 'Input Validation',  # Unchecked Return Value
            'CWE-253': 'Input Validation',  # Incorrect Check of Function Return Value
            'CWE-354': 'Input Validation',  # Improper Validation of Integrity Check Value
            'CWE-426': 'Input Validation',  # Untrusted Search Path
            'CWE-427': 'Input Validation',  # Uncontrolled Search Path Element
            'CWE-428': 'Input Validation',  # Unquoted Search Path or Element
            'CWE-456': 'Input Validation',  # Missing Initialization of a Variable
            'CWE-457': 'Input Validation',  # Use of Uninitialized Variable
            'CWE-458': 'Input Validation',  # DEPRECATED: Incorrect Initialization
            'CWE-459': 'Input Validation',  # Incomplete Cleanup
            'CWE-460': 'Input Validation',  # Improper Cleanup on Thrown Exception
            'CWE-463': 'Input Validation',  # Deletion of Data Structure Sentinel
            'CWE-464': 'Input Validation',  # Addition of Data Structure Sentinel
            'CWE-466': 'Input Validation',  # Return of Pointer Value Outside of Expected Range
            'CWE-467': 'Input Validation',  # Use of sizeof() on a Pointer Type
            'CWE-468': 'Input Validation',  # Incorrect Pointer Scaling
            'CWE-469': 'Input Validation',  # Use of Pointer Subtraction to Determine Size
            'CWE-470': 'Input Validation',  # Use of Externally-Controlled Input to Select Classes or Code
            'CWE-471': 'Input Validation',  # Modification of Assumed-Immutable Data (MAID)
            'CWE-472': 'Input Validation',  # External Control of Assumed-Immutable Web Parameter
            'CWE-473': 'Input Validation',  # PHP External Variable Modification
            'CWE-474': 'Input Validation',  # Use of Function with Inconsistent Implementations
            'CWE-475': 'Input Validation',  # Undefined Behavior for Input to API
            'CWE-476': 'Input Validation',  # NULL Pointer Dereference (SANS #12)
            'CWE-477': 'Input Validation',  # Use of Obsolete Function
            'CWE-478': 'Input Validation',  # Missing Default Case in Multiple Condition Expression
            'CWE-479': 'Input Validation',  # Signal Handler Use of a Non-reentrant Function
            'CWE-480': 'Input Validation',  # Use of Incorrect Operator
            'CWE-481': 'Input Validation',  # Assigning instead of Comparing
            'CWE-482': 'Input Validation',  # Comparing instead of Assigning
            'CWE-483': 'Input Validation',  # Incorrect Block Delimitation
            'CWE-484': 'Input Validation',  # Omitted Break Statement in Switch
            'CWE-606': 'Input Validation',  # Unchecked Input for Loop Condition
            'CWE-607': 'Input Validation',  # Public Static Final Field References Mutable Object
            'CWE-608': 'Input Validation',  # Struts: Non-private Field in ActionForm Class
            
            # ============================================================
            # DATA PROTECTION & PRIVACY (SANS Top 25: #22)
            # ============================================================
            'CWE-200': 'Data Protection & Privacy',  # Exposure of Sensitive Information to an Unauthorized Actor
            'CWE-209': 'Data Protection & Privacy',  # Generation of Error Message Containing Sensitive Information
            'CWE-532': 'Data Protection & Privacy',  # Insertion of Sensitive Information into Log File
            'CWE-312': 'Data Protection & Privacy',  # Cleartext Storage of Sensitive Information
            'CWE-319': 'Data Protection & Privacy',  # Cleartext Transmission of Sensitive Information (SANS #22)
            'CWE-201': 'Data Protection & Privacy',  # Insertion of Sensitive Information Into Sent Data
            'CWE-202': 'Data Protection & Privacy',  # Exposure of Sensitive Information Through Data Queries
            'CWE-203': 'Data Protection & Privacy',  # Observable Discrepancy
            'CWE-204': 'Data Protection & Privacy',  # Observable Response Discrepancy
            'CWE-205': 'Data Protection & Privacy',  # Observable Behavioral Discrepancy
            'CWE-206': 'Data Protection & Privacy',  # Observable Internal Behavioral Discrepancy
            'CWE-207': 'Data Protection & Privacy',  # Observable Behavioral Discrepancy With Equivalent Products
            'CWE-208': 'Data Protection & Privacy',  # Observable Timing Discrepancy
            'CWE-210': 'Data Protection & Privacy',  # Self-generated Error Message Containing Sensitive Information
            'CWE-211': 'Data Protection & Privacy',  # Externally-Generated Error Message Containing Sensitive Information
            'CWE-212': 'Data Protection & Privacy',  # Improper Removal of Sensitive Information Before Storage or Transfer
            'CWE-213': 'Data Protection & Privacy',  # Exposure of Sensitive Information Due to Incompatible Policies
            'CWE-214': 'Data Protection & Privacy',  # Invocation of Process Using Visible Sensitive Information
            'CWE-215': 'Data Protection & Privacy',  # Insertion of Sensitive Information Into Debugging Code
            'CWE-359': 'Data Protection & Privacy',  # Exposure of Private Personal Information to an Unauthorized Actor
            'CWE-497': 'Data Protection & Privacy',  # Exposure of Sensitive System Information to an Unauthorized Control Sphere
            'CWE-498': 'Data Protection & Privacy',  # Cloneable Class Containing Sensitive Information
            'CWE-499': 'Data Protection & Privacy',  # Serializable Class Containing Sensitive Data
            'CWE-524': 'Data Protection & Privacy',  # Use of Cache Containing Sensitive Information
            'CWE-525': 'Data Protection & Privacy',  # Use of Web Browser Cache Containing Sensitive Information
            'CWE-526': 'Data Protection & Privacy',  # Exposure of Sensitive Information Through Environmental Variables
            'CWE-527': 'Data Protection & Privacy',  # Exposure of Version-Control Repository to an Unauthorized Control Sphere
            'CWE-528': 'Data Protection & Privacy',  # Exposure of Core Dump File to an Unauthorized Control Sphere
            'CWE-529': 'Data Protection & Privacy',  # Exposure of Access Control List Files to an Unauthorized Control Sphere
            'CWE-530': 'Data Protection & Privacy',  # Exposure of Backup File to an Unauthorized Control Sphere
            'CWE-531': 'Data Protection & Privacy',  # Inclusion of Sensitive Information in Test Code
            'CWE-533': 'Data Protection & Privacy',  # DEPRECATED: Information Exposure Through Server Log Files
            'CWE-534': 'Data Protection & Privacy',  # DEPRECATED: Information Exposure Through Debug Log Files
            'CWE-535': 'Data Protection & Privacy',  # Exposure of Information Through Shell Error Message
            'CWE-536': 'Data Protection & Privacy',  # Servlet Runtime Error Message Containing Sensitive Information
            'CWE-537': 'Data Protection & Privacy',  # Java Runtime Error Message Containing Sensitive Information
            'CWE-538': 'Data Protection & Privacy',  # Insertion of Sensitive Information into Externally-Accessible File or Directory
            'CWE-539': 'Data Protection & Privacy',  # Use of Persistent Cookies Containing Sensitive Information
            'CWE-540': 'Data Protection & Privacy',  # Inclusion of Sensitive Information in Source Code
            'CWE-541': 'Data Protection & Privacy',  # Inclusion of Sensitive Information in an Include File
            'CWE-542': 'Data Protection & Privacy',  # DEPRECATED: Information Exposure Through Cleanup Log Files
            'CWE-543': 'Data Protection & Privacy',  # Use of Singleton Pattern Without Synchronization in a Multithreaded Context
            'CWE-544': 'Data Protection & Privacy',  # Missing Standardized Error Handling Mechanism
            'CWE-545': 'Data Protection & Privacy',  # DEPRECATED: Use of Dynamic Class Loading
            'CWE-546': 'Data Protection & Privacy',  # Suspicious Comment
            'CWE-547': 'Data Protection & Privacy',  # Use of Hard-coded, Security-relevant Constants
            'CWE-548': 'Data Protection & Privacy',  # Exposure of Information Through Directory Listing
            'CWE-550': 'Data Protection & Privacy',  # Server-generated Error Message Containing Sensitive Information
            'CWE-551': 'Data Protection & Privacy',  # Incorrect Behavior Order: Authorization Before Parsing and Canonicalization
            'CWE-552': 'Data Protection & Privacy',  # Files or Directories Accessible to External Parties
            'CWE-553': 'Data Protection & Privacy',  # Command Shell in Externally Accessible Directory
            'CWE-554': 'Data Protection & Privacy',  # ASP.NET Misconfiguration: Not Using Input Validation Framework
            
            # ============================================================
            # TRANSPORT SECURITY
            # ============================================================
            'CWE-295': 'Transport Security',  # Improper Certificate Validation
            'CWE-297': 'Transport Security',  # Improper Validation of Certificate with Host Mismatch
            'CWE-296': 'Transport Security',  # Improper Following of a Certificate's Chain of Trust
            'CWE-298': 'Transport Security',  # Improper Validation of Certificate Expiration
            'CWE-299': 'Transport Security',  # Improper Check for Certificate Revocation
            'CWE-300': 'Transport Security',  # Channel Accessible by Non-Endpoint
            'CWE-301': 'Transport Security',  # Reflection Attack in an Authentication Protocol
            'CWE-302': 'Transport Security',  # Authentication Bypass by Assumed-Immutable Data
            'CWE-303': 'Transport Security',  # Incorrect Implementation of Authentication Algorithm
            'CWE-304': 'Transport Security',  # Missing Critical Step in Authentication
            'CWE-305': 'Transport Security',  # Authentication Bypass by Primary Weakness
            'CWE-308': 'Transport Security',  # Use of Single-factor Authentication
            'CWE-309': 'Transport Security',  # Use of Password System for Primary Authentication
            'CWE-320': 'Transport Security',  # Key Management Errors
            'CWE-757': 'Transport Security',  # Selection of Less-Secure Algorithm During Negotiation
            'CWE-759': 'Transport Security',  # Use of a One-Way Hash without a Salt
            'CWE-760': 'Transport Security',  # Use of a One-Way Hash with a Predictable Salt
            'CWE-780': 'Transport Security',  # Use of RSA Algorithm without OAEP
            'CWE-924': 'Transport Security',  # Improper Enforcement of Message Integrity During Transmission in a Communication Channel
            'CWE-925': 'Transport Security',  # Improper Verification of Intent by Broadcast Receiver
            'CWE-926': 'Transport Security',  # Improper Export of Android Application Components
            'CWE-927': 'Transport Security',  # Use of Implicit Intent for Sensitive Communication
            
            # ============================================================
            # BUSINESS LOGIC & RACE CONDITIONS (SANS Top 25: #22)
            # ============================================================
            'CWE-362': 'Business Logic Vulnerabilities',  # Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition) (SANS #22)
            'CWE-363': 'Business Logic Vulnerabilities',  # Race Condition Enabling Link Following
            'CWE-364': 'Business Logic Vulnerabilities',  # Signal Handler Race Condition
            'CWE-365': 'Business Logic Vulnerabilities',  # DEPRECATED: Race Condition in Switch
            'CWE-366': 'Business Logic Vulnerabilities',  # Race Condition within a Thread
            'CWE-367': 'Business Logic Vulnerabilities',  # Time-of-check Time-of-use (TOCTOU) Race Condition
            'CWE-368': 'Business Logic Vulnerabilities',  # Context Switching Race Condition
            'CWE-369': 'Business Logic Vulnerabilities',  # Divide By Zero
            'CWE-370': 'Business Logic Vulnerabilities',  # Missing Check for Certificate Revocation after Initial Check
            'CWE-371': 'Business Logic Vulnerabilities',  # State Issues
            'CWE-372': 'Business Logic Vulnerabilities',  # Incomplete Internal State Distinction
            'CWE-373': 'Business Logic Vulnerabilities',  # DEPRECATED: State Synchronization Error
            'CWE-374': 'Business Logic Vulnerabilities',  # Passing Mutable Objects to an Untrusted Method
            'CWE-375': 'Business Logic Vulnerabilities',  # Returning a Mutable Object to an Untrusted Caller
            'CWE-377': 'Business Logic Vulnerabilities',  # Insecure Temporary File
            'CWE-378': 'Business Logic Vulnerabilities',  # Creation of Temporary File With Insecure Permissions
            'CWE-379': 'Business Logic Vulnerabilities',  # Creation of Temporary File in Directory with Insecure Permissions
            'CWE-382': 'Business Logic Vulnerabilities',  # J2EE Bad Practices: Use of System.exit()
            'CWE-383': 'Business Logic Vulnerabilities',  # J2EE Bad Practices: Direct Use of Threads
            'CWE-385': 'Business Logic Vulnerabilities',  # Covert Timing Channel
            'CWE-386': 'Business Logic Vulnerabilities',  # Symbolic Name not Mapping to Correct Object
            'CWE-390': 'Business Logic Vulnerabilities',  # Detection of Error Condition Without Action
            'CWE-391': 'Business Logic Vulnerabilities',  # Unchecked Error Condition
            'CWE-392': 'Business Logic Vulnerabilities',  # Missing Report of Error Condition
            'CWE-393': 'Business Logic Vulnerabilities',  # Return of Wrong Status Code
            'CWE-394': 'Business Logic Vulnerabilities',  # Unexpected Status Code or Return Value
            'CWE-395': 'Business Logic Vulnerabilities',  # Use of NullPointerException Catch to Detect NULL Pointer Dereference
            'CWE-396': 'Business Logic Vulnerabilities',  # Declaration of Catch for Generic Exception
            'CWE-397': 'Business Logic Vulnerabilities',  # Declaration of Throws for Generic Exception
            'CWE-404': 'Business Logic Vulnerabilities',  # Improper Resource Shutdown or Release
            'CWE-406': 'Business Logic Vulnerabilities',  # Insufficient Control of Network Message Volume
            'CWE-407': 'Business Logic Vulnerabilities',  # Inefficient Algorithmic Complexity
            'CWE-408': 'Business Logic Vulnerabilities',  # Incorrect Behavior Order: Early Amplification
            'CWE-409': 'Business Logic Vulnerabilities',  # Improper Handling of Highly Compressed Data (Data Amplification)
            'CWE-662': 'Business Logic Vulnerabilities',  # Improper Synchronization
            'CWE-663': 'Business Logic Vulnerabilities',  # Use of a Non-reentrant Function in a Concurrent Context
            'CWE-664': 'Business Logic Vulnerabilities',  # Improper Control of a Resource Through its Lifetime
            'CWE-666': 'Business Logic Vulnerabilities',  # Operation on Resource in Wrong Phase of Lifetime
            'CWE-667': 'Business Logic Vulnerabilities',  # Improper Locking
            'CWE-668': 'Business Logic Vulnerabilities',  # Exposure of Resource to Wrong Sphere
            'CWE-669': 'Business Logic Vulnerabilities',  # Incorrect Resource Transfer Between Spheres
            'CWE-670': 'Business Logic Vulnerabilities',  # Always-Incorrect Control Flow Implementation
            'CWE-671': 'Business Logic Vulnerabilities',  # Lack of Administrator Control over Security
            'CWE-672': 'Business Logic Vulnerabilities',  # Operation on a Resource after Expiration or Release
            'CWE-673': 'Business Logic Vulnerabilities',  # External Influence of Sphere Definition
            'CWE-675': 'Business Logic Vulnerabilities',  # Multiple Operations on Resource in Single-Operation Context
            'CWE-676': 'Business Logic Vulnerabilities',  # Use of Potentially Dangerous Function
            'CWE-681': 'Business Logic Vulnerabilities',  # Incorrect Conversion between Numeric Types
            'CWE-682': 'Business Logic Vulnerabilities',  # Incorrect Calculation
            'CWE-683': 'Business Logic Vulnerabilities',  # Function Call With Incorrect Order of Arguments
            'CWE-684': 'Business Logic Vulnerabilities',  # Incorrect Provision of Specified Functionality
            'CWE-685': 'Business Logic Vulnerabilities',  # Function Call With Incorrect Number of Arguments
            'CWE-686': 'Business Logic Vulnerabilities',  # Function Call With Incorrect Argument Type
            'CWE-687': 'Business Logic Vulnerabilities',  # Function Call With Incorrectly Specified Argument Value
            'CWE-688': 'Business Logic Vulnerabilities',  # Function Call With Incorrect Variable or Reference as Argument
            'CWE-689': 'Business Logic Vulnerabilities',  # Permission Race Condition During Resource Copy
            'CWE-690': 'Business Logic Vulnerabilities',  # Unchecked Return Value to NULL Pointer Dereference
            'CWE-691': 'Business Logic Vulnerabilities',  # Insufficient Control Flow Management
            'CWE-692': 'Business Logic Vulnerabilities',  # Incomplete Denylist to Cross-Site Scripting
            'CWE-693': 'Business Logic Vulnerabilities',  # Protection Mechanism Failure
            'CWE-694': 'Business Logic Vulnerabilities',  # Use of Multiple Resources with Duplicate Identifier
            'CWE-695': 'Business Logic Vulnerabilities',  # Use of Low-Level Functionality
            'CWE-696': 'Business Logic Vulnerabilities',  # Incorrect Behavior Order
            'CWE-697': 'Business Logic Vulnerabilities',  # Incorrect Comparison
            'CWE-698': 'Business Logic Vulnerabilities',  # Execution After Redirect (EAR)
            'CWE-703': 'Business Logic Vulnerabilities',  # Improper Check or Handling of Exceptional Conditions
            'CWE-704': 'Business Logic Vulnerabilities',  # Incorrect Type Conversion or Cast
            'CWE-705': 'Business Logic Vulnerabilities',  # Incorrect Control Flow Scoping
            'CWE-706': 'Business Logic Vulnerabilities',  # Use of Incorrectly-Resolved Name or Reference
            'CWE-707': 'Business Logic Vulnerabilities',  # Improper Neutralization
            'CWE-708': 'Business Logic Vulnerabilities',  # Incorrect Ownership Assignment
            'CWE-710': 'Business Logic Vulnerabilities',  # Improper Adherence to Coding Standards
            
            # ============================================================
            # SUPPLY CHAIN SECURITY
            # ============================================================
            'CWE-1104': 'Supply Chain Security',  # Use of Unmaintained Third Party Components
            'CWE-1329': 'Supply Chain Security',  # Reliance on Component That is Not Updateable
            'CWE-829': 'Supply Chain Security',   # Inclusion of Functionality from Untrusted Control Sphere
            'CWE-830': 'Supply Chain Security',   # Inclusion of Web Functionality from an Untrusted Source
            'CWE-494': 'Supply Chain Security',   # Download of Code Without Integrity Check
            'CWE-495': 'Supply Chain Security',   # Private Data Structure Returned From A Public Method
            'CWE-496': 'Supply Chain Security',   # Public Data Assigned to Private Array-Typed Field
            'CWE-506': 'Supply Chain Security',   # Embedded Malicious Code
            'CWE-507': 'Supply Chain Security',   # Trojan Horse
            'CWE-508': 'Supply Chain Security',   # Non-Replicating Malicious Code
            'CWE-509': 'Supply Chain Security',   # Replicating Malicious Code (Virus or Worm)
            'CWE-510': 'Supply Chain Security',   # Trapdoor
            'CWE-912': 'Supply Chain Security',   # Hidden Functionality
            'CWE-913': 'Supply Chain Security',   # Improper Control of Dynamically-Managed Code Resources
        }
        
        # Keyword patterns for description-based mapping
        # These patterns are based on standard security terminology
        self.description_patterns = {
            'Injection': [
                r'\bxss\b', r'cross.?site.?script', r'cross-site.?script',  # Added hyphenated version
                r'sql.?inject', r'command.?inject', r'code.?inject', r'ldap.?inject',
                r'xml.?inject', r'nosql.?inject', r'template.?inject',
                r'script.?inject', r'html.?inject', r'os.?command',
                r'untrusted.?code', r'executes.?untrusted', r'improper.?neutralization',  # Added for CVEs like 43799
                r'arbitrary.?code', r'prototype.?pollution', r'header.?manipulation'  # Added for babel, lodash, on-headers
            ],
            'Denial of Service (DoS)': [
                r'denial.?of.?service', r'\bdos\b', r'ddos', r'resource.?exhaust',
                r'regex.?dos', r'redos', r'infinite.?loop', r'memory.?exhaust',
                r'cpu.?exhaust', r'algorithmic.?complexity', r'uncontrolled.?resource',
                r'resource.?consumption', r'hang', r'freeze', r'crash', r'service.?crash'
            ],
            'Cryptography': [
                r'crypto', r'encrypt', r'decrypt', r'hash', r'cipher',
                r'weak.?algorithm', r'\bmd5\b', r'sha1\b', r'\bdes\b', r'\brc4\b',
                r'hard.?coded.?(password|credential|key|secret)',
                r'insecure.?random', r'predictable.?random', r'weak.?key',
                r'broken.?crypto', r'insufficient.?entropy'
            ],
            'Authentication & Session Management': [
                r'authentication', r'authorization', r'session', r'\bjwt\b',
                r'token', r'cookie', r'login', r'password', r'credential',
                r'auth.?bypass', r'privilege.?escalation', r'access.?control',
                r'session.?fixation', r'session.?hijack', r'brute.?force'
            ],
            'Transport Security': [
                r'\btls\b', r'\bssl\b', r'https', r'certificate', r'man.?in.?the.?middle',
                r'\bmitm\b', r'cleartext', r'unencrypted.?transmission',
                r'insecure.?protocol', r'cert.?validation', r'cert.?verify'
            ],
            'API Security': [
                r'\bcsrf\b', r'cross.?site.?request', r'\bssrf\b', r'server.?side.?request',
                r'\bcors\b', r'\bapi\b', r'\brest\b', r'graphql', r'rate.?limit',
                r'mass.?assignment', r'open.?redirect', r'unvalidated.?redirect'
            ],
            'Input Validation': [
                r'input.?validation', r'buffer.?overflow', r'integer.?overflow',
                r'path.?traversal', r'directory.?traversal', r'file.?inclusion',
                r'\bxxe\b', r'xml.?external.?entity', r'deserialization',
                r'out.?of.?bounds', r'array.?index', r'format.?string'
            ],
            'Data Protection & Privacy': [
                r'information.?disclosure', r'data.?leak', r'sensitive.?data',
                r'\bpii\b', r'privacy', r'gdpr', r'personal.?information',
                r'exposure', r'information.?exposure', r'cleartext.?storage',
                r'sensitive.?info', r'confidential'
            ],
            'Supply Chain Security': [
                r'supply.?chain', r'malicious.?package', r'typosquat',
                r'dependency.?confusion', r'compromised.?package',
                r'backdoor', r'trojan', r'malware', r'vulnerable.?dependency'
            ],
            'Business Logic Vulnerabilities': [
                r'race.?condition', r'toctou', r'business.?logic',
                r'workflow', r'state.?manipulation', r'price.?manipulation',
                r'logic.?flaw', r'business.?flow'
            ]
        }
        
        # Package name patterns
        # These help identify the purpose of the package
        self.package_patterns = {
            'Cryptography': [
                r'crypto', r'cipher', r'hash', r'encrypt', r'\bjwt\b',
                r'bcrypt', r'scrypt', r'argon', r'aes', r'rsa'
            ],
            'Authentication & Session Management': [
                r'auth', r'passport', r'session', r'\bjwt\b', r'oauth',
                r'saml', r'openid', r'login', r'credential'
            ],
            'Transport Security': [
                r'\btls\b', r'\bssl\b', r'https', r'certificate', r'x509'
            ],
            'API Security': [
                r'express', r'koa', r'fastify', r'axios', r'fetch',
                r'request', r'graphql', r'\brest\b', r'\bapi\b'
            ]
        }
    
    def map_vulnerability_to_category(self, vuln: Dict[str, Any]) -> str:
        """
        Map a Trivy vulnerability to the most appropriate security category.
        
        Args:
            vuln: Normalized vulnerability dictionary
            
        Returns:
            Category name string
        """
        # 1. Try CWE-based mapping (most reliable)
        cwe_id = self._extract_cwe_id(vuln)
        if cwe_id:
            category = self.cwe_mappings.get(cwe_id)
            if category:
                logger.debug(f"Mapped to '{category}' based on {cwe_id}")
                return category
        
        # 2. Try description-based mapping
        description = vuln.get('description', '').lower()
        title = vuln.get('title', '').lower()
        combined_text = f"{title} {description}"
        
        category_scores = {}
        for category, patterns in self.description_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    score += 1
            if score > 0:
                category_scores[category] = score
        
        if category_scores:
            # Return category with highest score
            best_category = max(category_scores, key=category_scores.get)
            logger.debug(f"Mapped to '{best_category}' based on description keywords")
            return best_category
        
        # 3. Try package name-based mapping
        package_name = vuln.get('package_name', '').lower()
        for category, patterns in self.package_patterns.items():
            for pattern in patterns:
                if re.search(pattern, package_name, re.IGNORECASE):
                    logger.debug(f"Mapped to '{category}' based on package name '{package_name}'")
                    return category
        
        # 4. Try severity-based heuristic for high-severity vulnerabilities
        severity = vuln.get('severity', '').upper()
        if severity in ['CRITICAL', 'HIGH']:
            # High severity vulnerabilities without clear category
            if 'remote' in combined_text or 'rce' in combined_text or 'execute' in combined_text:
                logger.debug(f"Mapped to 'Injection' based on high severity and remote execution keywords")
                return 'Injection'
            elif 'leak' in combined_text or 'disclosure' in combined_text:
                logger.debug(f"Mapped to 'Data Protection & Privacy' based on high severity and disclosure keywords")
                return 'Data Protection & Privacy'
        
        # 5. Default fallback - more specific than "Infrastructure Security"
        logger.debug(f"Mapped to 'Supply Chain Security' as default for SCA vulnerability")
        return 'Supply Chain Security'
    
    def _extract_cwe_id(self, vuln: Dict[str, Any]) -> Optional[str]:
        """Extract CWE ID from vulnerability data."""
        # Check direct CWE field
        cwe_id = vuln.get('cwe_id')
        if cwe_id:
            # Normalize to CWE-XXX format
            if isinstance(cwe_id, list) and len(cwe_id) > 0:
                cwe_id = cwe_id[0]
            if isinstance(cwe_id, str):
                if not cwe_id.startswith('CWE-'):
                    cwe_id = f"CWE-{cwe_id}"
                return cwe_id
        
        # Try to extract from raw_data if available
        raw_data = vuln.get('raw_data', {})
        if raw_data:
            # Trivy sometimes stores CWE in different fields
            cwe_field = raw_data.get('CweIDs') or raw_data.get('CWE') or raw_data.get('cwe')
            if cwe_field:
                if isinstance(cwe_field, list) and len(cwe_field) > 0:
                    cwe_id = cwe_field[0]
                else:
                    cwe_id = cwe_field
                
                if isinstance(cwe_id, str):
                    if not cwe_id.startswith('CWE-'):
                        cwe_id = f"CWE-{cwe_id}"
                    return cwe_id
        
        # Try to extract from description or references
        description = vuln.get('description', '')
        title = vuln.get('title', '')
        combined = f"{title} {description}"
        
        # Look for CWE-XXX pattern
        match = re.search(r'CWE-(\d+)', combined, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        
        return None
    
    def get_category_justification(self, vuln: Dict[str, Any], category: str) -> str:
        """
        Generate a justification for why this vulnerability was mapped to this category.
        
        Args:
            vuln: Vulnerability dictionary
            category: Assigned category
            
        Returns:
            Justification string
        """
        cwe_id = self._extract_cwe_id(vuln)
        if cwe_id and cwe_id in self.cwe_mappings:
            return f"Mapped to {category} based on {cwe_id}"
        
        description = vuln.get('description', '').lower()
        title = vuln.get('title', '').lower()
        combined = f"{title} {description}"
        
        # Find which pattern matched
        if category in self.description_patterns:
            for pattern in self.description_patterns[category]:
                match = re.search(pattern, combined, re.IGNORECASE)
                if match:
                    matched_text = match.group(0)
                    return f"Mapped to {category} based on vulnerability description containing '{matched_text}'"
        
        package_name = vuln.get('package_name', '')
        if category in self.package_patterns:
            for pattern in self.package_patterns[category]:
                if re.search(pattern, package_name, re.IGNORECASE):
                    return f"Mapped to {category} based on package name '{package_name}'"
        
        return f"Mapped to {category} as default category for supply chain vulnerabilities"


# Example usage and testing
if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(level=logging.DEBUG)
    
    mapper = SCACategoryMapper()
    
    # Test cases
    test_vulns = [
        {
            "title": "Cross-Site Scripting (XSS) in sanitize-html",
            "description": "Improper neutralization of input allows XSS attacks",
            "package_name": "sanitize-html",
            "severity": "HIGH",
            "cwe_id": "CWE-79"
        },
        {
            "title": "Regular Expression Denial of Service in word-wrap",
            "description": "ReDoS vulnerability causes CPU exhaustion",
            "package_name": "word-wrap",
            "severity": "HIGH",
            "cwe_id": "CWE-1333"
        },
        {
            "title": "Weak cryptographic algorithm in crypto-js",
            "description": "Uses deprecated MD5 hashing algorithm",
            "package_name": "crypto-js",
            "severity": "MEDIUM"
        },
        {
            "title": "SQL Injection in sequelize",
            "description": "Improper input sanitization allows SQL injection",
            "package_name": "sequelize",
            "severity": "CRITICAL",
            "cwe_id": "CWE-89"
        },
        {
            "title": "Authentication bypass in jsonwebtoken",
            "description": "JWT signature verification can be bypassed",
            "package_name": "jsonwebtoken",
            "severity": "CRITICAL",
            "cwe_id": "CWE-287"
        }
    ]
    
    print("=" * 80)
    print("Testing SCA Category Mapper")
    print("=" * 80)
    
    for i, vuln in enumerate(test_vulns, 1):
        print(f"\n{i}. Vulnerability: {vuln['title']}")
        print(f"   Package: {vuln['package_name']}")
        print(f"   Severity: {vuln['severity']}")
        
        category = mapper.map_vulnerability_to_category(vuln)
        justification = mapper.get_category_justification(vuln, category)
        
        print(f"   → Category: {category}")
        print(f"   → Justification: {justification}")
        print("-" * 80)
    
    print("\n✅ Testing complete!")
