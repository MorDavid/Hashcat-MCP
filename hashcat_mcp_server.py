from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
import os
import logging
import subprocess
import json
import re
from typing import Dict, List, Optional, Any, Tuple
import tempfile
import asyncio
import csv
import hashlib
import time
from dataclasses import dataclass
from functools import lru_cache
import sqlite3
from pathlib import Path
import shlex
import string

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Environment variables with defaults
HASHCAT_PATH = os.getenv("HASHCAT_PATH")
HASHCAT_DIR = os.path.dirname(HASHCAT_PATH) if HASHCAT_PATH else ""

# Configuration from environment variables
SESSION_DB_PATH = os.getenv("HASHCAT_SESSION_DB", "hashcat_sessions.db")
PRESETS_FILE_PATH = os.getenv("HASHCAT_PRESETS_FILE", "attack_presets.json")
HASH_MODES_CSV_PATH = os.getenv("HASHCAT_MODES_CSV", "hashcat_modes.csv")

# Security settings from environment
RATE_LIMIT = int(os.getenv("HASHCAT_RATE_LIMIT", "10"))  # requests per minute
RATE_WINDOW = int(os.getenv("HASHCAT_RATE_WINDOW", "60"))  # seconds
MAX_RUNTIME = int(os.getenv("HASHCAT_MAX_RUNTIME", "86400"))  # 24 hours default
MAX_OUTPUT_SIZE = int(os.getenv("HASHCAT_MAX_OUTPUT_SIZE", "100000"))  # 100KB default

# Timeout settings from environment
HASHCAT_TIMEOUT = int(os.getenv("HASHCAT_TIMEOUT", "300"))  # 5 minutes default for main operations
HASHCAT_QUICK_TIMEOUT = int(os.getenv("HASHCAT_QUICK_TIMEOUT", "30"))  # 30 seconds for quick operations
HASHCAT_BENCHMARK_TIMEOUT = int(os.getenv("HASHCAT_BENCHMARK_TIMEOUT", "120"))  # 2 minutes for benchmarks

# Input validation limits from environment
MAX_HASH_LENGTH = int(os.getenv("HASHCAT_MAX_HASH_LENGTH", "1024"))  # Maximum hash input length
MAX_PATH_LENGTH = int(os.getenv("HASHCAT_MAX_PATH_LENGTH", "500"))  # Maximum file path length
MAX_PLAINTEXT_LENGTH = int(os.getenv("HASHCAT_MAX_PLAINTEXT_LENGTH", "500"))  # Maximum plaintext output length
DEFAULT_TIME_LIMIT_PER_HASH = int(os.getenv("HASHCAT_DEFAULT_TIME_LIMIT_PER_HASH", "900"))  # 15 minutes default
MAX_MASK_LENGTH = int(os.getenv("HASHCAT_MAX_MASK_LENGTH", "100"))  # Maximum mask pattern length
MAX_CHARSET_LENGTH = int(os.getenv("HASHCAT_MAX_CHARSET_LENGTH", "100"))  # Maximum custom charset length
MAX_HASH_TYPE = int(os.getenv("HASHCAT_MAX_HASH_TYPE", "30000"))  # Maximum allowed hash type number
MAX_OUTPUT_LINES = int(os.getenv("HASHCAT_MAX_OUTPUT_LINES", "1000"))  # Maximum output lines to process
MAX_LINE_LENGTH = int(os.getenv("HASHCAT_MAX_LINE_LENGTH", "1000"))  # Maximum line length to process

# Safe directories from environment (comma-separated)
SAFE_DIRECTORIES_ENV = os.getenv("HASHCAT_SAFE_DIRS", "")
SAFE_DIRECTORIES = [d.strip() for d in SAFE_DIRECTORIES_ENV.split(",") if d.strip()] if SAFE_DIRECTORIES_ENV else []

# Default wordlists and rules from environment
DEFAULT_WORDLISTS_ENV = os.getenv("HASHCAT_DEFAULT_WORDLISTS", "")
DEFAULT_WORDLISTS = [w.strip() for w in DEFAULT_WORDLISTS_ENV.split(",") if w.strip()] if DEFAULT_WORDLISTS_ENV else []

DEFAULT_RULES_ENV = os.getenv("HASHCAT_DEFAULT_RULES", "")
DEFAULT_RULES = [r.strip() for r in DEFAULT_RULES_ENV.split(",") if r.strip()] if DEFAULT_RULES_ENV else []

# Logging level from environment
LOG_LEVEL = os.getenv("HASHCAT_LOG_LEVEL", "DEBUG")

# Reconfigure logging with environment variable
logging.getLogger().setLevel(getattr(logging, LOG_LEVEL.upper(), logging.DEBUG))

# Custom exceptions
class HashcatError(Exception):
    """Custom hashcat error with detailed context"""
    pass

class HashcatTimeoutError(HashcatError):
    """Hashcat operation timed out"""
    pass

class HashcatNotFoundError(HashcatError):
    """Hashcat executable not found"""
    pass

@dataclass
class HashcatConfig:
    """Configuration for hashcat operations"""
    hashcat_path: str
    default_wordlists: List[str]
    default_rules: List[str]
    max_runtime: int = 3600
    auto_optimize: bool = True
    session_db_path: str = "hashcat_sessions.db"

# Create FastMCP server
mcp = FastMCP("Hashcat MCP Server")

# Global configuration
config = HashcatConfig(
    hashcat_path=HASHCAT_PATH,
    default_wordlists=DEFAULT_WORDLISTS,
    default_rules=DEFAULT_RULES,
    session_db_path=SESSION_DB_PATH
)

# Session management
active_sessions = {}

# Initialize session database
def init_session_db():
    """Initialize SQLite database for session tracking"""
    conn = sqlite3.connect(SESSION_DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            hash_value TEXT,
            hash_type INTEGER,
            attack_mode INTEGER,
            status TEXT,
            created_at TIMESTAMP,
            completed_at TIMESTAMP,
            result TEXT,
            progress REAL
        )
    ''')
    conn.commit()
    conn.close()

init_session_db()

# Hash pattern detection
HASH_PATTERNS = {
    32: [
        (r'^[a-f0-9]{32}$', [0, 1000], ['MD5', 'NTLM']),  # MD5 or NTLM
        (r'^[A-F0-9]{32}$', [0, 1000], ['MD5', 'NTLM']),  # Uppercase
    ],
    40: [
        (r'^[a-f0-9]{40}$', [100], ['SHA1']),
        (r'^[A-F0-9]{40}$', [100], ['SHA1']),
    ],
    64: [
        (r'^[a-f0-9]{64}$', [1400], ['SHA2-256']),
        (r'^[A-F0-9]{64}$', [1400], ['SHA2-256']),
    ],
    128: [
        (r'^[a-f0-9]{128}$', [1700], ['SHA2-512']),
        (r'^[A-F0-9]{128}$', [1700], ['SHA2-512']),
    ]
}

# Load hash types from CSV database
def load_hash_types() -> Dict[int, Dict[str, str]]:
    """Load hash types from CSV database"""
    hash_types = {}
    csv_path = HASH_MODES_CSV_PATH
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                mode = int(row['mode'])
                hash_types[mode] = {
                    'name': row['name'],
                    'category': row['category']
                }
    except FileNotFoundError:
        logger.warning(f"Hash types CSV not found at {csv_path}, using fallback data")
        # Fallback to basic hash types
        hash_types = {
            0: {'name': 'MD5', 'category': 'Raw Hash'},
            100: {'name': 'SHA1', 'category': 'Raw Hash'},
            1400: {'name': 'SHA2-256', 'category': 'Raw Hash'},
            1700: {'name': 'SHA2-512', 'category': 'Raw Hash'},
            1000: {'name': 'NTLM', 'category': 'Operating System'},
            3200: {'name': 'bcrypt', 'category': 'Operating System'},
            1800: {'name': 'sha512crypt', 'category': 'Operating System'},
            7400: {'name': 'sha256crypt', 'category': 'Operating System'},
            500: {'name': 'md5crypt', 'category': 'Operating System'},
            22000: {'name': 'WPA-PBKDF2-PMKID+EAPOL', 'category': 'Network Protocol'},
            2500: {'name': 'WPA-EAPOL-PBKDF2', 'category': 'Network Protocol'},
            16800: {'name': 'WPA-PMKID-PBKDF2', 'category': 'Network Protocol'}
        }
    except Exception as e:
        logger.error(f"Error loading hash types: {e}")
        hash_types = {}
    
    return hash_types

# Load hash types database
HASH_TYPES = load_hash_types()

ATTACK_MODES = {
    0: "Straight",
    1: "Combination", 
    3: "Brute-force",
    6: "Hybrid Wordlist + Mask",
    7: "Hybrid Mask + Wordlist",
    9: "Association"
}

# Security validation functions
def validate_hash_input(hash_value: str) -> bool:
    """Validate hash input to prevent injection attacks"""
    if not hash_value or len(hash_value) > MAX_HASH_LENGTH:  # Configurable length limit
        return False
    
    # Check for obvious injection attempts
    dangerous_patterns = [
        ';', '|', '&', '`', '$(',  # Command injection
        '../', '..\\',             # Directory traversal
        '\n', '\r',               # Newline injection
        '\x00',                   # Null byte injection
    ]
    
    for pattern in dangerous_patterns:
        if pattern in hash_value:
            return False
    
    # Allow only hexadecimal characters, colons (for salted hashes), dollar signs (for formatted hashes)
    # and some special characters for specific hash formats
    allowed_chars = set(string.hexdigits + ':${}*')
    
    # For bcrypt and other formatted hashes, allow additional characters
    if hash_value.startswith(('$1$', '$2', '$5$', '$6$', '$7$')):
        allowed_chars.update('./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
    
    return all(c in allowed_chars for c in hash_value)

def validate_file_path(file_path: str) -> bool:
    """Validate file path to prevent directory traversal and injection"""
    if not file_path or len(file_path) > MAX_PATH_LENGTH:  # Configurable length limit
        return False
    
    # Check for injection attempts
    dangerous_patterns = [
        ';', '|', '&', '`', '$(',  # Command injection
        '\n', '\r',               # Newline injection
        '\x00',                   # Null byte injection
    ]
    
    for pattern in dangerous_patterns:
        if pattern in file_path:
            return False
    
    try:
        # Convert to Path object for validation
        path = Path(file_path)
        
        # Check for directory traversal attempts
        if '..' in path.parts:
            return False
        
        # Check for absolute paths that might be dangerous
        if path.is_absolute():
            # Use environment-configured safe directories with fallback defaults
            default_safe_dirs = [
                HASHCAT_DIR,
                "./wordlists",
                "./rules"
            ]
            
            # Combine environment and default safe directories
            all_safe_dirs = SAFE_DIRECTORIES + default_safe_dirs
            
            if not any(str(path).startswith(str(safe_dir)) for safe_dir in all_safe_dirs):
                return False
        
        # Check file extension for wordlists and rules
        allowed_extensions = ('.txt', '.lst', '.dict', '.rule', '.rules')
        if not file_path.lower().endswith(allowed_extensions):
            return False
        
        return True
        
    except Exception:
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent injection"""
    if not filename:
        return "default"
    
    # Remove dangerous characters
    safe_chars = set(string.ascii_letters + string.digits + '._-')
    sanitized = ''.join(c for c in filename if c in safe_chars)
    
    # Ensure it's not empty and not too long
    if not sanitized:
        sanitized = "default"
    
    return sanitized[:50]  # Limit length

def validate_mask_pattern(mask: str) -> bool:
    """Validate mask pattern for brute force attacks"""
    if not mask or len(mask) > MAX_MASK_LENGTH:  # Reasonable length limit
        return False
    
    # Check for injection attempts
    dangerous_chars = [';', '|', '&', '`', '$', '\n', '\r', '\x00']
    if any(char in mask for char in dangerous_chars):
        return False
    
    # Allow only valid hashcat mask characters
    valid_chars = set('?ludsa?LUDSA0123456789')
    return all(c in valid_chars for c in mask)

def create_secure_temp_file(prefix: str, content: str) -> str:
    """Create a secure temporary file with validated content"""
    # Sanitize prefix
    safe_prefix = sanitize_filename(prefix)
    
    # Create unique filename with timestamp
    timestamp = int(time.time())
    safe_filename = f"{safe_prefix}_{timestamp}_{os.getpid()}.txt"
    
    # Full path
    file_path = os.path.join(HASHCAT_DIR, safe_filename)
    
    # Write content securely
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content.strip())
    
    return safe_filename

# Rate limiting (simple implementation)
request_counts = {}

def check_rate_limit(client_id: str = "default") -> bool:
    """Simple rate limiting to prevent abuse"""
    current_time = time.time()
    
    # Clean old entries
    request_counts[client_id] = [
        req_time for req_time in request_counts.get(client_id, [])
        if current_time - req_time < RATE_WINDOW
    ]
    
    # Check if under limit
    if len(request_counts.get(client_id, [])) >= RATE_LIMIT:
        return False
    
    # Add current request
    if client_id not in request_counts:
        request_counts[client_id] = []
    request_counts[client_id].append(current_time)
    
    return True

@mcp.tool()
async def identify_hash(hash_value: str) -> Dict[str, Any]:
    """Identify hash type using hashcat's --identify feature"""
    try:
        # 🛡️ Security validation
        if not validate_hash_input(hash_value):
            return {"success": False, "error": "Invalid hash format - potential security risk"}
        
        # Create secure hash file with sanitized name
        safe_filename = create_secure_temp_file("identify", hash_value)
        
        try:
            result = subprocess.run([
                "hashcat.exe", "--identify", safe_filename, "--machine-readable"
            ], capture_output=True, text=True, timeout=HASHCAT_QUICK_TIMEOUT, cwd=HASHCAT_DIR, shell=False)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Identification timed out"}
        except Exception as e:
            return {"success": False, "error": f"Execution error: {str(e)}"}
        finally:
            # Clean up hash file
            try:
                os.unlink(safe_filename)
            except Exception:
                logger.warning(f"Could not delete temporary hash file: {safe_filename}")
        
        if result.returncode == 0:
            return {
                "success": True,
                "hash": hash_value,
                "identification": result.stdout.strip(),
                "possible_types": _parse_identification_output(result.stdout)
            }
        else:
            return {
                "success": False,
                "error": result.stderr.strip() or "Hash identification failed"
            }
    except Exception as e:
        logger.error(f"Error in identify_hash: {e}")
        return {"success": False, "error": str(e)}

@mcp.tool()
async def crack_hash(
    hash_value: str,
    hash_type: int = 0,
    attack_mode: int = 0,
    wordlist: Optional[str] = None,
    mask: Optional[str] = None,
    rules_file: Optional[str] = None,
    custom_charset1: Optional[str] = None,
    custom_charset2: Optional[str] = None,
    runtime: Optional[int] = None,
    workload_profile: int = 2
) -> Dict[str, Any]:
    """Crack a hash using hashcat with various attack modes"""
    try:
        # 🛡️ Rate limiting
        if not check_rate_limit("crack_hash"):
            return {"success": False, "error": "Rate limit exceeded. Please wait before making more requests."}
        
        # 🛡️ Security validation
        if not validate_hash_input(hash_value):
            return {"success": False, "error": "Invalid hash format - potential security risk"}
        
        if wordlist and not validate_file_path(wordlist):
            return {"success": False, "error": "Invalid wordlist path - potential security risk"}
        
        if rules_file and not validate_file_path(rules_file):
            return {"success": False, "error": "Invalid rules file path - potential security risk"}
        
        if mask and not validate_mask_pattern(mask):
            return {"success": False, "error": "Invalid mask pattern - potential security risk"}
        
        # Validate numeric parameters
        if not (0 <= hash_type <= MAX_HASH_TYPE):
            return {"success": False, "error": "Invalid hash type"}
        
        if not (0 <= attack_mode <= 9):
            return {"success": False, "error": "Invalid attack mode"}
        
        if not (1 <= workload_profile <= 4):
            return {"success": False, "error": "Invalid workload profile"}
        
        if runtime and (runtime < 1 or runtime > MAX_RUNTIME):  # Max 24 hours
            return {"success": False, "error": "Invalid runtime (1-86400 seconds)"}
        
        # Create secure hash file
        safe_filename = create_secure_temp_file("hash", hash_value)
        
        # Build command with validated parameters
        cmd = [
            HASHCAT_PATH,
            "-m", str(hash_type),
            "-a", str(attack_mode),
            "-w", str(workload_profile),
            "--force"
        ]
        
        # Add runtime limit if specified
        if runtime:
            cmd.extend(["--runtime", str(runtime)])
        
        # Add custom charsets (validate them)
        if custom_charset1:
            if len(custom_charset1) > MAX_CHARSET_LENGTH or not all(c.isprintable() for c in custom_charset1):
                return {"success": False, "error": "Invalid custom charset 1"}
            cmd.extend(["-1", custom_charset1])
            
        if custom_charset2:
            if len(custom_charset2) > MAX_CHARSET_LENGTH or not all(c.isprintable() for c in custom_charset2):
                return {"success": False, "error": "Invalid custom charset 2"}
            cmd.extend(["-2", custom_charset2])
        
        # Add rules file (already validated)
        if rules_file:
            cmd.extend(["-r", rules_file])
        
        cmd.append(safe_filename)  # Use safe filename
        
        # Add wordlist or mask based on attack mode (already validated)
        if attack_mode in [0, 1, 6, 7, 9] and wordlist:
            cmd.append(wordlist)
        elif attack_mode == 3 and mask:
            cmd.append(mask)
        elif attack_mode == 6 and wordlist and mask:
            cmd.extend([wordlist, mask])
        elif attack_mode == 7 and mask and wordlist:
            cmd.extend([mask, wordlist])
        
        # Execute with timeout and proper error handling
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=HASHCAT_TIMEOUT,  # 5 minute timeout
                cwd=HASHCAT_DIR,
                env={"PATH": os.environ.get("PATH", "")},  # Minimal environment
                shell=False  # 🛡️ Never use shell=True!
            )
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": f"Execution error: {str(e)}"}
        
        # If hash was already cracked, try to show it
        if "All hashes found in potfile" in result.stdout or "Use --show to display them" in result.stdout:
            show_cmd = cmd.copy()
            show_cmd.append("--show")
            try:
                show_result = subprocess.run(
                    show_cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=HASHCAT_QUICK_TIMEOUT, 
                    cwd=HASHCAT_DIR,
                    shell=False
                )
                if show_result.returncode == 0:
                    result = show_result
            except Exception:
                pass  # Continue with original result
        
        # Clean up hash file
        try:
            os.unlink(os.path.join(HASHCAT_DIR, safe_filename))
        except Exception:
            logger.warning(f"Could not delete temporary hash file: {safe_filename}")
        
        cracked = _parse_crack_output(result.stdout, result.stderr)
        
        return {
            "success": True,
            "hash": hash_value,
            "hash_type": hash_type,
            "hash_type_name": HASH_TYPES.get(hash_type, {}).get('name', 'Unknown'),
            "attack_mode": attack_mode,
            "attack_mode_name": ATTACK_MODES.get(attack_mode, 'Unknown'),
            "cracked": cracked["found"],
            "plaintext": cracked["plaintext"],
            "status": cracked["status"],
            "output": result.stdout,
            "errors": result.stderr
        }
    except Exception as e:
        logger.error(f"Error in crack_hash: {e}")
        return {"success": False, "error": str(e)}

@mcp.tool()
async def benchmark_hashcat(hash_types: Optional[List[int]] = None) -> Dict[str, Any]:
    """Run hashcat benchmark for specified hash types or all types"""
    try:
        cmd = [HASHCAT_PATH, "-b"]
        
        if hash_types:
            for ht in hash_types:
                cmd.extend(["-m", str(ht)])
        else:
            cmd.append("--benchmark-all")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=HASHCAT_BENCHMARK_TIMEOUT)
        
        benchmarks = _parse_benchmark_output(result.stdout)
        
        return {
            "success": True,
            "benchmarks": benchmarks,
            "raw_output": result.stdout
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def get_hash_info(hash_type: Optional[int] = None) -> Dict[str, Any]:
    """Get information about hash types"""
    try:
        if hash_type is not None:
            # Get specific hash type info from our database
            if hash_type in HASH_TYPES:
                return {
                    "success": True,
                    "hash_type": hash_type,
                    "name": HASH_TYPES[hash_type]['name'],
                    "category": HASH_TYPES[hash_type]['category'],
                    "database_info": HASH_TYPES[hash_type]
                }
            else:
                return {
                    "success": False,
                    "error": f"Hash type {hash_type} not found in database"
                }
        else:
            # Return all hash types
            return {
                "success": True,
                "total_hash_types": len(HASH_TYPES),
                "hash_types": HASH_TYPES,
                "categories": list(set(ht['category'] for ht in HASH_TYPES.values()))
            }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def search_hash_types(
    search_term: str,
    category: Optional[str] = None
) -> Dict[str, Any]:
    """Search hash types by name or category"""
    try:
        results = []
        search_lower = search_term.lower()
        
        for mode, info in HASH_TYPES.items():
            name_match = search_lower in info['name'].lower()
            category_match = category is None or info['category'].lower() == category.lower()
            
            if name_match and category_match:
                results.append({
                    "mode": mode,
                    "name": info['name'],
                    "category": info['category']
                })
        
        return {
            "success": True,
            "search_term": search_term,
            "category_filter": category,
            "results": results,
            "count": len(results)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def get_hash_categories() -> Dict[str, Any]:
    """Get all available hash categories"""
    try:
        categories = {}
        for mode, info in HASH_TYPES.items():
            category = info['category']
            if category not in categories:
                categories[category] = []
            categories[category].append({
                "mode": mode,
                "name": info['name']
            })
        
        return {
            "success": True,
            "categories": categories,
            "category_count": len(categories),
            "total_hash_types": len(HASH_TYPES)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def generate_mask_attack(
    charset: str = "?a",
    min_length: int = 1,
    max_length: int = 8,
    increment: bool = True
) -> Dict[str, Any]:
    """Generate mask attack patterns for brute force"""
    try:
        masks = []
        if increment:
            for length in range(min_length, max_length + 1):
                masks.append(charset * length)
        else:
            masks.append(charset * max_length)
        
        return {
            "success": True,
            "masks": masks,
            "charset": charset,
            "min_length": min_length,
            "max_length": max_length,
            "increment": increment
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def show_cracked_hashes(potfile_path: Optional[str] = None) -> Dict[str, Any]:
    """Show previously cracked hashes from potfile"""
    try:
        cmd = [HASHCAT_PATH, "--show"]
        if potfile_path:
            cmd.extend(["--potfile-path", potfile_path])
        
        # Need a dummy hash file for --show to work
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
            f.write("dummy")
            hash_file = f.name
        
        cmd.append(hash_file)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=HASHCAT_QUICK_TIMEOUT)
        
        os.unlink(hash_file)
        
        cracked_hashes = _parse_show_output(result.stdout)
        
        return {
            "success": True,
            "cracked_hashes": cracked_hashes,
            "count": len(cracked_hashes)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def get_backend_info() -> Dict[str, Any]:
    """Get system/environment/backend API info"""
    try:
        result = subprocess.run([HASHCAT_PATH, "-I"], capture_output=True, text=True, timeout=HASHCAT_QUICK_TIMEOUT)
        
        return {
            "success": True,
            "backend_info": result.stdout.strip(),
            "parsed_info": _parse_backend_info(result.stdout)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def create_wordlist_rules(
    base_word: str,
    rule_functions: List[str] = ["c", "u", "l", "r", "$1", "$2", "$3"]
) -> Dict[str, Any]:
    """Generate wordlist variations using hashcat rules"""
    try:
        variations = []
        
        # Apply basic rule transformations
        for rule in rule_functions:
            if rule == "c":  # Capitalize first letter
                variations.append(base_word.capitalize())
            elif rule == "u":  # Uppercase all
                variations.append(base_word.upper())
            elif rule == "l":  # Lowercase all
                variations.append(base_word.lower())
            elif rule == "r":  # Reverse
                variations.append(base_word[::-1])
            elif rule.startswith("$"):  # Append character
                char = rule[1] if len(rule) > 1 else ""
                variations.append(base_word + char)
            elif rule.startswith("^"):  # Prepend character
                char = rule[1] if len(rule) > 1 else ""
                variations.append(char + base_word)
        
        return {
            "success": True,
            "base_word": base_word,
            "variations": list(set(variations)),  # Remove duplicates
            "rules_applied": rule_functions
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def estimate_keyspace(
    attack_mode: int = 3,
    mask: Optional[str] = None,
    wordlist: Optional[str] = None,
    increment_min: Optional[int] = None,
    increment_max: Optional[int] = None
) -> Dict[str, Any]:
    """Estimate keyspace size for an attack"""
    try:
        cmd = [HASHCAT_PATH, "-a", str(attack_mode), "--keyspace"]
        
        if increment_min:
            cmd.extend(["--increment-min", str(increment_min)])
        if increment_max:
            cmd.extend(["--increment-max", str(increment_max)])
        
        # Add dummy hash
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
            f.write("5d41402abc4b2a76b9719d911017c592")  # MD5 of "hello"
            hash_file = f.name
        
        cmd.extend(["-m", "0", hash_file])  # MD5 mode
        
        if mask:
            cmd.append(mask)
        elif wordlist:
            cmd.append(wordlist)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=HASHCAT_QUICK_TIMEOUT)
        
        os.unlink(hash_file)
        
        keyspace = _parse_keyspace_output(result.stdout)
        
        return {
            "success": True,
            "attack_mode": attack_mode,
            "keyspace": keyspace,
            "raw_output": result.stdout
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def smart_identify_hash(hash_value: str) -> Dict[str, Any]:
    """Enhanced hash identification with pattern matching and confidence scoring"""
    try:
        # 🛡️ Security validation
        if not validate_hash_input(hash_value):
            return {"success": False, "error": "Invalid hash format - potential security risk"}
        
        hash_clean = hash_value.strip()
        hash_length = len(hash_clean)
        candidates = []
        
        # Pattern-based detection
        if hash_length in HASH_PATTERNS:
            for pattern, modes, names in HASH_PATTERNS[hash_length]:
                if re.match(pattern, hash_clean):
                    for i, mode in enumerate(modes):
                        confidence = 0.9 - (i * 0.1)  # First match gets higher confidence
                        candidates.append({
                            "mode": mode,
                            "name": names[i] if i < len(names) else HASH_TYPES.get(mode, {}).get('name', 'Unknown'),
                            "confidence": confidence,
                            "category": HASH_TYPES.get(mode, {}).get('category', 'Unknown'),
                            "detection_method": "pattern_matching"
                        })
        
        # Enhanced detection for specific formats
        if hash_length == 32:
            # Check for common NTLM vs MD5 indicators
            if hash_clean.isupper():
                # NTLM hashes are often uppercase in dumps
                for candidate in candidates:
                    if candidate["mode"] == 1000:
                        candidate["confidence"] += 0.1
            
            # Check for salt indicators
            if ':' in hash_clean:
                candidates.append({
                    "mode": 10,  # md5($pass.$salt)
                    "name": "MD5 with salt",
                    "confidence": 0.8,
                    "category": "Raw Hash salted",
                    "detection_method": "salt_detected"
                })
        
        # Sort by confidence
        candidates.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Get recommended attack strategies
        recommendations = []
        if candidates:
            top_candidate = candidates[0]
            recommendations = _get_attack_recommendations(top_candidate["mode"])
        
        return {
            "success": True,
            "hash": hash_clean,
            "length": hash_length,
            "candidates": candidates[:5],  # Top 5 candidates
            "best_guess": candidates[0] if candidates else None,
            "attack_recommendations": recommendations
        }
    except Exception as e:
        logger.error(f"Error in smart_identify_hash: {e}")
        return {"success": False, "error": str(e)}

@mcp.tool()
async def create_session(
    hash_value: str,
    hash_type: int,
    attack_mode: int = 0,
    session_name: Optional[str] = None
) -> Dict[str, Any]:
    """Create a new hashcat session for tracking"""
    try:
        session_id = session_name or f"session_{int(time.time())}"
        
        # Store in database
        conn = sqlite3.connect(SESSION_DB_PATH)
        conn.execute('''
            INSERT INTO sessions (id, hash_value, hash_type, attack_mode, status, created_at, progress)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, hash_value, hash_type, attack_mode, "created", time.time(), 0.0))
        conn.commit()
        conn.close()
        
        # Store in memory for active tracking
        active_sessions[session_id] = {
            "hash_value": hash_value,
            "hash_type": hash_type,
            "attack_mode": attack_mode,
            "status": "created",
            "created_at": time.time(),
            "progress": 0.0,
            "process": None
        }
        
        return {
            "success": True,
            "session_id": session_id,
            "status": "created"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def get_session_status(session_id: str) -> Dict[str, Any]:
    """Get real-time status of hashcat session"""
    try:
        if session_id not in active_sessions:
            # Try to load from database
            conn = sqlite3.connect(SESSION_DB_PATH)
            cursor = conn.execute('SELECT * FROM sessions WHERE id = ?', (session_id,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return {"success": False, "error": "Session not found"}
            
            return {
                "success": True,
                "session_id": session_id,
                "status": row[4],  # status column
                "progress": row[8] or 0.0,  # progress column
                "from_database": True
            }
        
        session = active_sessions[session_id]
        
        # Check if process is still running
        if session.get("process"):
            if session["process"].poll() is None:
                session["status"] = "running"
            else:
                session["status"] = "completed"
                session["process"] = None
        
        return {
            "success": True,
            "session_id": session_id,
            "status": session["status"],
            "progress": session.get("progress", 0.0),
            "hash_type": session["hash_type"],
            "attack_mode": session["attack_mode"],
            "runtime": time.time() - session["created_at"] if session["status"] == "running" else None
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def auto_attack_strategy(
    hash_value: str,
    time_limit: int = 3600,
    wordlists: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Automatically choose and execute best attack strategy"""
    try:
        # First, identify the hash
        identification = await smart_identify_hash(hash_value)
        if not identification["success"] or not identification["best_guess"]:
            return {"success": False, "error": "Could not identify hash type"}
        
        best_guess = identification["best_guess"]
        hash_type = best_guess["mode"]
        
        # Create session
        session_result = await create_session(hash_value, hash_type, 0, f"auto_{int(time.time())}")
        if not session_result["success"]:
            return {"success": False, "error": "Could not create session"}
        
        session_id = session_result["session_id"]
        
        # Use provided wordlists or defaults
        attack_wordlists = wordlists or config.default_wordlists
        
        # Strategy sequence: wordlist -> wordlist+rules -> hybrid -> brute force
        strategies = [
            {"mode": 0, "wordlist": attack_wordlists[0], "description": "Straight wordlist attack"},
            {"mode": 0, "wordlist": attack_wordlists[0], "rules": "best64.rule", "description": "Wordlist with rules"},
            {"mode": 6, "wordlist": attack_wordlists[0], "mask": "?d?d?d?d", "description": "Hybrid wordlist + digits"},
            {"mode": 3, "mask": "?l?l?l?l?l?l?l?l", "description": "Brute force lowercase 8 chars"}
        ]
        
        results = []
        total_time = 0
        time_per_strategy = time_limit // len(strategies)
        
        for i, strategy in enumerate(strategies):
            if total_time >= time_limit:
                break
                
            logger.info(f"Executing strategy {i+1}: {strategy['description']}")
            
            # Execute attack with time limit
            attack_result = await crack_hash(
                hash_value=hash_value,
                hash_type=hash_type,
                attack_mode=strategy["mode"],
                wordlist=strategy.get("wordlist"),
                mask=strategy.get("mask"),
                rules_file=strategy.get("rules"),
                runtime=time_per_strategy
            )
            
            results.append({
                "strategy": strategy["description"],
                "result": attack_result,
                "strategy_number": i + 1
            })
            
            # If cracked, stop
            if attack_result.get("cracked"):
                return {
                    "success": True,
                    "session_id": session_id,
                    "hash_identified_as": best_guess,
                    "cracked": True,
                    "plaintext": attack_result["plaintext"],
                    "successful_strategy": strategy["description"],
                    "strategies_tried": results,
                    "total_time": total_time
                }
            
            total_time += time_per_strategy
        
        return {
            "success": True,
            "session_id": session_id,
            "hash_identified_as": best_guess,
            "cracked": False,
            "strategies_tried": results,
            "total_time": total_time,
            "recommendation": "Try longer runtime or additional wordlists"
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def get_gpu_status() -> Dict[str, Any]:
    """Get real-time GPU status and performance metrics"""
    try:
        # Get backend info first
        result = subprocess.run([HASHCAT_PATH, "-I"], capture_output=True, text=True, timeout=HASHCAT_QUICK_TIMEOUT)
        
        gpu_info = []
        current_device = {}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if 'Device #' in line:
                if current_device:
                    gpu_info.append(current_device)
                current_device = {"device": line}
            elif current_device and line:
                if 'Temperature' in line:
                    current_device["temperature"] = line
                elif 'Utilization' in line:
                    current_device["utilization"] = line
                elif 'Memory' in line:
                    current_device["memory"] = line
        
        if current_device:
            gpu_info.append(current_device)
        
        return {
            "success": True,
            "gpu_devices": gpu_info,
            "timestamp": time.time()
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def analyze_cracked_passwords(potfile_path: Optional[str] = None) -> Dict[str, Any]:
    """Analyze patterns in cracked passwords"""
    try:
        # Get cracked hashes
        cracked_result = await show_cracked_hashes(potfile_path)
        if not cracked_result["success"]:
            return cracked_result
        
        passwords = [item["plaintext"] for item in cracked_result["cracked_hashes"]]
        
        if not passwords:
            return {"success": True, "message": "No cracked passwords to analyze"}
        
        # Analyze patterns
        analysis = {
            "total_passwords": len(passwords),
            "length_distribution": {},
            "character_sets": {"lowercase": 0, "uppercase": 0, "digits": 0, "special": 0},
            "common_patterns": {},
            "top_passwords": {},
            "complexity_stats": {"simple": 0, "medium": 0, "complex": 0}
        }
        
        # Length distribution
        for pwd in passwords:
            length = len(pwd)
            analysis["length_distribution"][length] = analysis["length_distribution"].get(length, 0) + 1
        
        # Character set analysis
        for pwd in passwords:
            if any(c.islower() for c in pwd):
                analysis["character_sets"]["lowercase"] += 1
            if any(c.isupper() for c in pwd):
                analysis["character_sets"]["uppercase"] += 1
            if any(c.isdigit() for c in pwd):
                analysis["character_sets"]["digits"] += 1
            if any(not c.isalnum() for c in pwd):
                analysis["character_sets"]["special"] += 1
        
        # Complexity scoring
        for pwd in passwords:
            score = 0
            if len(pwd) >= 8: score += 1
            if any(c.islower() for c in pwd): score += 1
            if any(c.isupper() for c in pwd): score += 1
            if any(c.isdigit() for c in pwd): score += 1
            if any(not c.isalnum() for c in pwd): score += 1
            
            if score <= 2:
                analysis["complexity_stats"]["simple"] += 1
            elif score <= 4:
                analysis["complexity_stats"]["medium"] += 1
            else:
                analysis["complexity_stats"]["complex"] += 1
        
        # Top passwords (frequency)
        from collections import Counter
        pwd_counter = Counter(passwords)
        analysis["top_passwords"] = dict(pwd_counter.most_common(10))
        
        return {
            "success": True,
            "analysis": analysis,
            "recommendations": _generate_password_recommendations(analysis)
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def crack_multiple_hashes(
    hash_list: List[str],
    auto_detect: bool = True,
    parallel: bool = True,
    time_limit_per_hash: int = DEFAULT_TIME_LIMIT_PER_HASH
) -> Dict[str, Any]:
    """Crack multiple hashes efficiently with auto-detection"""
    try:
        results = []
        total_cracked = 0
        
        for i, hash_value in enumerate(hash_list):
            logger.info(f"Processing hash {i+1}/{len(hash_list)}: {hash_value[:16]}...")
            
            if auto_detect:
                # Use smart identification
                identification = await smart_identify_hash(hash_value)
                if not identification["success"] or not identification["best_guess"]:
                    results.append({
                        "hash": hash_value,
                        "success": False,
                        "error": "Could not identify hash type"
                    })
                    continue
                
                hash_type = identification["best_guess"]["mode"]
            else:
                hash_type = 0  # Default to MD5
            
            # Try to crack with auto strategy
            crack_result = await auto_attack_strategy(
                hash_value=hash_value,
                time_limit=time_limit_per_hash
            )
            
            if crack_result.get("cracked"):
                total_cracked += 1
            
            results.append({
                "hash": hash_value,
                "hash_type": hash_type,
                "result": crack_result,
                "cracked": crack_result.get("cracked", False),
                "plaintext": crack_result.get("plaintext")
            })
        
        return {
            "success": True,
            "total_hashes": len(hash_list),
            "total_cracked": total_cracked,
            "success_rate": f"{(total_cracked/len(hash_list)*100):.1f}%",
            "results": results
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def generate_smart_masks(
    hash_type: int,
    known_patterns: Optional[List[str]] = None,
    target_length: Optional[int] = None
) -> Dict[str, Any]:
    """Generate intelligent mask patterns based on common password patterns"""
    try:
        masks = []
        
        # Common password patterns
        common_patterns = [
            # Word + digits
            "?l?l?l?l?l?l?d?d",  # 6 letters + 2 digits
            "?l?l?l?l?l?d?d?d",  # 5 letters + 3 digits
            "?u?l?l?l?l?l?d?d",  # Capital + 5 letters + 2 digits
            
            # Years
            "?l?l?l?l?l?l?d?d?d?d",  # word + year
            "?u?l?l?l?l?l?d?d?d?d",  # Word + year
            
            # Special chars
            "?l?l?l?l?l?l?s",      # word + special
            "?l?l?l?l?l?l?d?s",    # word + digit + special
            "?s?l?l?l?l?l?l?d?d",  # special + word + digits
            
            # All lowercase/uppercase
            "?l?l?l?l?l?l?l?l",    # 8 lowercase
            "?u?u?u?u?u?u?u?u",    # 8 uppercase
            
            # Mixed case
            "?u?l?l?l?l?l?l?l",    # Capital first
            "?l?l?l?l?u?l?l?l",    # Capital middle
        ]
        
        # Add length-specific patterns
        if target_length:
            length_patterns = []
            # Generate patterns for specific length
            for i in range(1, target_length):
                # Letters + digits
                letters = "?l" * i
                digits = "?d" * (target_length - i)
                length_patterns.append(letters + digits)
                
                # Uppercase first + letters + digits
                if i > 1:
                    pattern = "?u" + "?l" * (i-1) + "?d" * (target_length - i)
                    length_patterns.append(pattern)
            
            common_patterns.extend(length_patterns[:10])  # Limit to 10 additional
        
        # Add user-provided patterns
        if known_patterns:
            common_patterns.extend(known_patterns)
        
        # Score patterns based on hash type
        for pattern in common_patterns:
            score = _score_mask_pattern(pattern, hash_type)
            masks.append({
                "mask": pattern,
                "description": _describe_mask_pattern(pattern),
                "score": score,
                "estimated_keyspace": _estimate_mask_keyspace(pattern)
            })
        
        # Sort by score (higher is better)
        masks.sort(key=lambda x: x["score"], reverse=True)
        
        return {
            "success": True,
            "hash_type": hash_type,
            "target_length": target_length,
            "recommended_masks": masks[:15],  # Top 15 masks
            "total_generated": len(masks)
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def validate_hash_format(hash_value: str) -> Dict[str, Any]:
    """Validate hash format and detect potential issues"""
    try:
        issues = []
        warnings = []
        
        # Basic validation
        hash_clean = hash_value.strip()
        
        # Check for common issues
        if not hash_clean:
            issues.append("Hash is empty")
            return {"success": False, "issues": issues}
        
        # Check for whitespace
        if hash_value != hash_clean:
            warnings.append("Hash contains leading/trailing whitespace")
        
        # Check for valid characters
        if not re.match(r'^[a-fA-F0-9:$]+$', hash_clean):
            issues.append("Hash contains invalid characters")
        
        # Check length
        length = len(hash_clean)
        valid_lengths = [16, 32, 40, 56, 64, 96, 128]  # Common hash lengths
        
        if ':' in hash_clean:
            # Salted hash
            parts = hash_clean.split(':')
            if len(parts) == 2:
                hash_part, salt_part = parts
                if len(hash_part) not in valid_lengths:
                    warnings.append(f"Unusual hash length: {len(hash_part)}")
                if not salt_part:
                    warnings.append("Empty salt detected")
            else:
                warnings.append(f"Unusual salt format: {len(parts)} parts")
        else:
            # Unsalted hash
            if length not in valid_lengths:
                warnings.append(f"Unusual hash length: {length}")
        
        # Check for common formats
        format_detected = None
        if length == 32 and re.match(r'^[a-fA-F0-9]{32}$', hash_clean):
            format_detected = "MD5 or NTLM"
        elif length == 40 and re.match(r'^[a-fA-F0-9]{40}$', hash_clean):
            format_detected = "SHA1"
        elif length == 64 and re.match(r'^[a-fA-F0-9]{64}$', hash_clean):
            format_detected = "SHA256"
        elif length == 128 and re.match(r'^[a-fA-F0-9]{128}$', hash_clean):
            format_detected = "SHA512"
        elif '$' in hash_clean:
            if hash_clean.startswith('$1$'):
                format_detected = "MD5 crypt"
            elif hash_clean.startswith('$2'):
                format_detected = "bcrypt"
            elif hash_clean.startswith('$5$'):
                format_detected = "SHA256 crypt"
            elif hash_clean.startswith('$6$'):
                format_detected = "SHA512 crypt"
        
        return {
            "success": True,
            "hash": hash_clean,
            "original_hash": hash_value,
            "length": length,
            "format_detected": format_detected,
            "has_salt": ':' in hash_clean or '$' in hash_clean,
            "issues": issues,
            "warnings": warnings,
            "is_valid": len(issues) == 0
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def estimate_crack_time(
    hash_type: int,
    attack_mode: int,
    keyspace: Optional[int] = None,
    mask: Optional[str] = None
) -> Dict[str, Any]:
    """Estimate time to crack based on current hardware performance"""
    try:
        # Get benchmark for this hash type
        benchmark_result = await benchmark_hashcat([hash_type])
        if not benchmark_result["success"]:
            return {"success": False, "error": "Could not get benchmark data"}
        
        # Extract speed from benchmark
        speed_h_per_s = 0
        for bench in benchmark_result["benchmarks"]:
            if bench["mode"] == hash_type:
                speed_str = bench["speed"]
                # Parse speed (e.g., "1234.5 MH/s")
                speed_match = re.search(r'([\d.]+)\s*([KMGT]?)H/s', speed_str)
                if speed_match:
                    value = float(speed_match.group(1))
                    unit = speed_match.group(2)
                    
                    multipliers = {'': 1, 'K': 1000, 'M': 1000000, 'G': 1000000000, 'T': 1000000000000}
                    speed_h_per_s = value * multipliers.get(unit, 1)
                break
        
        if speed_h_per_s == 0:
            return {"success": False, "error": "Could not determine hash speed"}
        
        # Estimate keyspace if not provided
        if not keyspace:
            if mask:
                keyspace = _estimate_mask_keyspace(mask)
            else:
                # Default estimates based on attack mode
                if attack_mode == 3:  # Brute force
                    keyspace = 95 ** 8  # 8 character full ASCII
                else:
                    keyspace = 1000000  # Rough wordlist estimate
        
        # Calculate time estimates
        seconds_total = keyspace / speed_h_per_s
        seconds_average = seconds_total / 2  # On average, found at 50%
        
        def format_time(seconds):
            if seconds < 60:
                return f"{seconds:.1f} seconds"
            elif seconds < 3600:
                return f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                return f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                return f"{seconds/86400:.1f} days"
            else:
                return f"{seconds/31536000:.1f} years"
        
        return {
            "success": True,
            "hash_type": hash_type,
            "hash_speed": f"{speed_h_per_s:,.0f} H/s",
            "keyspace": keyspace,
            "time_estimates": {
                "worst_case": format_time(seconds_total),
                "average_case": format_time(seconds_average),
                "best_case": "Instant (if lucky)"
            },
            "raw_seconds": {
                "worst_case": seconds_total,
                "average_case": seconds_average
            },
            "feasibility": _assess_crack_feasibility(seconds_average)
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def save_attack_preset(
    name: str,
    config_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Save attack configuration as preset"""
    try:
        presets_file = PRESETS_FILE_PATH
        
        # Load existing presets
        presets = {}
        if os.path.exists(presets_file):
            with open(presets_file, 'r') as f:
                presets = json.load(f)
        
        # Add new preset
        presets[name] = {
            "config": config_data,
            "created_at": time.time(),
            "description": config_data.get("description", "")
        }
        
        # Save back to file
        with open(presets_file, 'w') as f:
            json.dump(presets, f, indent=2)
        
        return {
            "success": True,
            "preset_name": name,
            "saved_at": time.time()
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
async def load_attack_preset(name: str) -> Dict[str, Any]:
    """Load saved attack preset"""
    try:
        presets_file = PRESETS_FILE_PATH
        
        if not os.path.exists(presets_file):
            return {"success": False, "error": "No presets file found"}
        
        with open(presets_file, 'r') as f:
            presets = json.load(f)
        
        if name not in presets:
            available = list(presets.keys())
            return {
                "success": False, 
                "error": f"Preset '{name}' not found",
                "available_presets": available
            }
        
        return {
            "success": True,
            "preset_name": name,
            "config": presets[name]["config"],
            "created_at": presets[name]["created_at"],
            "description": presets[name].get("description", "")
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}

# Helper functions
def _parse_identification_output(output: str) -> List[Dict[str, Any]]:
    """Parse hashcat identification output"""
    types = []
    lines = output.split('\n')
    for line in lines:
        if 'Hash-Mode' in line and 'Hash-Name' in line:
            continue
        if line.strip() and not line.startswith('The following'):
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                mode = int(parts[0])
                name = " ".join(parts[1:])
                # Add category info from our database
                category = HASH_TYPES.get(mode, {}).get('category', 'Unknown')
                types.append({
                    "mode": mode,
                    "name": name,
                    "category": category
                })
    return types

def _parse_crack_output(stdout: str, stderr: str) -> Dict[str, Any]:
    """Parse hashcat cracking output with security considerations"""
    found = False
    plaintext = None
    status = "Unknown"
    
    # Limit output size to prevent memory issues
    if len(stdout) > MAX_OUTPUT_SIZE:  # 100KB limit
        stdout = stdout[:MAX_OUTPUT_SIZE]
    if len(stderr) > MAX_OUTPUT_SIZE:
        stderr = stderr[:MAX_OUTPUT_SIZE]
    
    # Check if hash was already cracked (appears in output)
    for line in stdout.split('\n')[:MAX_OUTPUT_LINES]:  # Limit lines processed
        line = line.strip()
        if not line or len(line) > MAX_LINE_LENGTH:  # Skip very long lines
            continue
            
        if ':' in line and len(line.split(':')) == 2:
            hash_part, plain_part = line.split(':', 1)
            # Validate hash part looks reasonable
            if 16 <= len(hash_part) <= 128 and all(c in string.hexdigits for c in hash_part):
                found = True
                # Sanitize plaintext output
                plaintext = plain_part.strip()[:MAX_PLAINTEXT_LENGTH]  # Configurable plaintext length limit
                status = "Cracked"
                break
    
    if not found:
        # Check status indicators in output
        status_indicators = {
            "Cracked": "Cracked",
            "Status...........: Cracked": "Cracked", 
            "Exhausted": "Exhausted",
            "Aborted": "Aborted",
            "Quit": "Quit"
        }
        
        for indicator, status_value in status_indicators.items():
            if indicator in stdout:
                if status_value == "Cracked":
                    found = True
                status = status_value
                break
    
    return {
        "found": found,
        "plaintext": plaintext,
        "status": status
    }

def _parse_benchmark_output(output: str) -> List[Dict[str, Any]]:
    """Parse hashcat benchmark output"""
    benchmarks = []
    lines = output.split('\n')
    
    for line in lines:
        if 'H/s' in line and '|' in line:
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 3:
                try:
                    mode = int(parts[0])
                    name = parts[1]
                    speed = parts[2]
                    # Add category from our database
                    category = HASH_TYPES.get(mode, {}).get('category', 'Unknown')
                    benchmarks.append({
                        "mode": mode,
                        "name": name,
                        "speed": speed,
                        "category": category
                    })
                except ValueError:
                    continue
    
    return benchmarks

def _parse_hash_info(output: str) -> Dict[str, Any]:
    """Parse hash info output"""
    info = {}
    current_mode = None
    
    for line in output.split('\n'):
        if line.strip().startswith('Hash mode #'):
            current_mode = line.strip()
            info[current_mode] = []
        elif current_mode and line.strip():
            info[current_mode].append(line.strip())
    
    return info

def _parse_show_output(output: str) -> List[Dict[str, str]]:
    """Parse --show output for cracked hashes"""
    cracked = []
    for line in output.split('\n'):
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                cracked.append({
                    "hash": parts[0].strip(),
                    "plaintext": parts[1].strip()
                })
    return cracked

def _parse_backend_info(output: str) -> Dict[str, Any]:
    """Parse backend info output"""
    info = {"devices": [], "opencl": {}, "cuda": {}}
    
    lines = output.split('\n')
    current_section = None
    
    for line in lines:
        line = line.strip()
        if 'OpenCL Info' in line:
            current_section = "opencl"
        elif 'CUDA Info' in line:
            current_section = "cuda"
        elif 'Backend Device ID' in line:
            current_section = "devices"
        elif current_section and line:
            if current_section == "devices":
                info["devices"].append(line)
            else:
                info[current_section][len(info[current_section])] = line
    
    return info

def _parse_keyspace_output(output: str) -> Optional[int]:
    """Parse keyspace estimation output"""
    for line in output.split('\n'):
        if 'keyspace' in line.lower():
            numbers = re.findall(r'\d+', line)
            if numbers:
                return int(numbers[-1])
    return None

def _get_attack_recommendations(hash_type: int) -> List[Dict[str, Any]]:
    """Get recommended attack strategies for hash type"""
    recommendations = []
    
    if hash_type in [0, 1000]:  # MD5, NTLM - fast hashes
        recommendations = [
            {"mode": 0, "description": "Wordlist attack", "priority": 1, "estimated_time": "minutes"},
            {"mode": 0, "description": "Wordlist + rules", "priority": 2, "estimated_time": "hours"},
            {"mode": 3, "description": "Brute force", "priority": 3, "estimated_time": "days-weeks"}
        ]
    elif hash_type in [1400, 1700]:  # SHA256, SHA512 - medium speed
        recommendations = [
            {"mode": 0, "description": "Wordlist attack", "priority": 1, "estimated_time": "hours"},
            {"mode": 0, "description": "Wordlist + rules", "priority": 2, "estimated_time": "days"},
            {"mode": 6, "description": "Hybrid attacks", "priority": 3, "estimated_time": "weeks"}
        ]
    elif hash_type in [3200, 1800]:  # bcrypt, sha512crypt - slow hashes
        recommendations = [
            {"mode": 0, "description": "Targeted wordlist", "priority": 1, "estimated_time": "days"},
            {"mode": 0, "description": "Custom wordlist", "priority": 2, "estimated_time": "weeks"},
            {"mode": 6, "description": "Hybrid (if desperate)", "priority": 3, "estimated_time": "months"}
        ]
    else:
        recommendations = [
            {"mode": 0, "description": "Wordlist attack", "priority": 1, "estimated_time": "varies"},
            {"mode": 3, "description": "Brute force", "priority": 2, "estimated_time": "varies"}
        ]
    
    return recommendations

def _generate_password_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """Generate security recommendations based on password analysis"""
    recommendations = []
    
    total = analysis["total_passwords"]
    
    # Length recommendations
    short_passwords = sum(count for length, count in analysis["length_distribution"].items() if length < 8)
    if short_passwords > total * 0.3:
        recommendations.append(f"{short_passwords}/{total} passwords are under 8 characters - enforce minimum length")
    
    # Complexity recommendations
    simple_ratio = analysis["complexity_stats"]["simple"] / total
    if simple_ratio > 0.5:
        recommendations.append(f"{simple_ratio:.1%} passwords are too simple - enforce complexity requirements")
    
    # Character set recommendations
    if analysis["character_sets"]["special"] < total * 0.3:
        recommendations.append("Consider requiring special characters in passwords")
    
    if analysis["character_sets"]["uppercase"] < total * 0.5:
        recommendations.append("Consider requiring uppercase letters")
    
    # Common password warnings
    if analysis["top_passwords"]:
        most_common = max(analysis["top_passwords"].values())
        if most_common > 1:
            recommendations.append(f"Found {most_common} instances of the same password - check for password reuse")
    
    return recommendations

def _score_mask_pattern(pattern: str, hash_type: int) -> float:
    """Score mask pattern based on effectiveness for hash type"""
    score = 0.5  # Base score
    
    # Fast hashes (MD5, NTLM) can handle more complex patterns
    if hash_type in [0, 1000]:
        score += 0.3
    
    # Patterns with mixed case are generally good
    if '?u' in pattern and '?l' in pattern:
        score += 0.2
    
    # Patterns with digits are common
    if '?d' in pattern:
        score += 0.1
    
    # Reasonable length (6-12 chars)
    pattern_length = pattern.count('?')
    if 6 <= pattern_length <= 12:
        score += 0.2
    elif pattern_length > 12:
        score -= 0.3  # Too long, impractical
    
    return min(score, 1.0)

def _describe_mask_pattern(pattern: str) -> str:
    """Generate human-readable description of mask pattern"""
    descriptions = {
        '?l': 'lowercase letter',
        '?u': 'uppercase letter', 
        '?d': 'digit',
        '?s': 'special character',
        '?a': 'any character'
    }
    
    # Count each type
    counts = {}
    for mask_char in ['?l', '?u', '?d', '?s', '?a']:
        count = pattern.count(mask_char)
        if count > 0:
            counts[mask_char] = count
    
    # Build description
    parts = []
    for mask_char, count in counts.items():
        desc = descriptions[mask_char]
        if count == 1:
            parts.append(f"1 {desc}")
        else:
            parts.append(f"{count} {desc}s")
    
    return " + ".join(parts)

def _estimate_mask_keyspace(mask: str) -> int:
    """Estimate keyspace size for a mask"""
    charset_sizes = {
        '?l': 26,   # lowercase
        '?u': 26,   # uppercase  
        '?d': 10,   # digits
        '?s': 33,   # special chars
        '?a': 95    # all printable ASCII
    }
    
    keyspace = 1
    i = 0
    while i < len(mask):
        if i < len(mask) - 1 and mask[i:i+2] in charset_sizes:
            keyspace *= charset_sizes[mask[i:i+2]]
            i += 2
        else:
            keyspace *= 95  # Assume any character
            i += 1
    
    return keyspace

def _assess_crack_feasibility(average_seconds: float) -> str:
    """Assess if cracking is feasible based on time estimate"""
    if average_seconds < 3600:  # < 1 hour
        return "Very feasible"
    elif average_seconds < 86400:  # < 1 day
        return "Feasible"
    elif average_seconds < 604800:  # < 1 week
        return "Challenging but possible"
    elif average_seconds < 31536000:  # < 1 year
        return "Very challenging"
    else:
        return "Impractical with current hardware"

# Run the server
if __name__ == "__main__":
    logger.info("🚀 Starting Enhanced Hashcat MCP Server...")
    logger.info(f"📊 Loaded {len(HASH_TYPES)} hash types from database")
    logger.info(f"🔧 Hashcat path: {HASHCAT_PATH}")
    logger.info(f"💾 Session database: {SESSION_DB_PATH}")
    logger.info("🎯 Enhanced features enabled:")
    logger.info("   • Smart hash identification with confidence scoring")
    logger.info("   • Session management and tracking")
    logger.info("   • Auto attack strategies")
    logger.info("   • Batch hash processing")
    logger.info("   • GPU monitoring")
    logger.info("   • Password analysis")
    logger.info("   • Smart mask generation")
    logger.info("   • Attack presets")
    logger.info("   • Time estimation")
    logger.info("🔥 Ready to crack some hashes!")
    
    try:
        mcp.run(transport="stdio")
    except KeyboardInterrupt:
        logger.info("👋 Server shutdown requested")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
    finally:
        logger.info("🛑 Hashcat MCP Server stopped")