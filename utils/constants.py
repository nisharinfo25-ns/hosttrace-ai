"""
utils/constants.py
Shared CIDR databases, keyword lists, and lookup tables for HostTrace AI.
"""

# ── Cloudflare ──────────────────────────────────────────────────────────────
CLOUDFLARE_RANGES = [
    "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "104.16.0.0/13",  "104.24.0.0/14",  "108.162.192.0/18",
    "131.0.72.0/22",  "141.101.64.0/18","162.158.0.0/15",
    "172.64.0.0/13",  "173.245.48.0/20","188.114.96.0/20",
    "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
    "160.79.96.0/20",
]

# ── AWS ─────────────────────────────────────────────────────────────────────
AWS_RANGES = [
    "3.0.0.0/9","13.32.0.0/12","18.0.0.0/8",
    "52.0.0.0/8","54.0.0.0/8","99.77.0.0/16",
    "34.192.0.0/12","35.0.0.0/8",
]

# ── Google Cloud ─────────────────────────────────────────────────────────────
GCP_RANGES = [
    "8.34.208.0/20","8.35.192.0/20","23.236.48.0/20",
    "23.251.128.0/19","34.64.0.0/10","35.184.0.0/13",
    "35.192.0.0/14","35.196.0.0/15","35.199.0.0/16",
    "104.154.0.0/15","104.196.0.0/14","130.211.0.0/22",
    "142.250.0.0/15",
]

# ── Azure ────────────────────────────────────────────────────────────────────
AZURE_RANGES = [
    "13.64.0.0/11","20.0.0.0/8","40.64.0.0/10",
    "51.0.0.0/8","52.224.0.0/11","104.40.0.0/13",
    "137.116.0.0/14","168.61.0.0/16","191.232.0.0/13",
]

# ── Akamai ───────────────────────────────────────────────────────────────────
AKAMAI_RANGES = [
    "23.0.0.0/12","23.32.0.0/11","23.64.0.0/14",
    "96.6.0.0/15","104.64.0.0/10","216.206.0.0/17",
]

# ── Fastly ───────────────────────────────────────────────────────────────────
FASTLY_RANGES = [
    "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24",
    "103.245.222.0/23","151.101.0.0/16","157.52.192.0/18",
    "167.82.0.0/17","172.111.64.0/18","185.31.16.0/22",
]

# ── DigitalOcean ─────────────────────────────────────────────────────────────
DIGITALOCEAN_RANGES = [
    "104.131.0.0/16","162.243.0.0/16","178.62.0.0/16",
    "192.241.128.0/17","198.199.64.0/18","45.55.0.0/16",
    "159.203.0.0/16","167.99.0.0/16","174.138.0.0/16",
    "138.68.0.0/16","139.59.0.0/16","188.226.192.0/18",
]

# ── Linode / Akamai Cloud ─────────────────────────────────────────────────────
LINODE_RANGES = [
    "45.33.0.0/17","45.56.0.0/21","45.79.0.0/16",
    "66.175.208.0/20","72.14.176.0/20","97.107.128.0/17",
    "173.230.128.0/17","173.255.192.0/18",
]

# ── Vultr ─────────────────────────────────────────────────────────────────────
VULTR_RANGES = [
    "45.32.0.0/13","64.227.0.0/16","108.61.0.0/16",
    "149.28.0.0/16","207.246.0.0/16","209.250.224.0/19",
]

# ── Hetzner ───────────────────────────────────────────────────────────────────
HETZNER_RANGES = [
    "5.9.0.0/16","78.46.0.0/15","88.198.0.0/16",
    "144.76.0.0/16","188.40.0.0/15","213.239.192.0/18",
]

# ── OVH ───────────────────────────────────────────────────────────────────────
OVH_RANGES = [
    "51.38.0.0/16","51.68.0.0/16","51.75.0.0/16",
    "54.36.0.0/14","137.74.0.0/16","145.239.0.0/16",
]

# ── NS Patterns ──────────────────────────────────────────────────────────────
CF_NS_PATTERNS = ["cloudflare", "ns.cloudflare"]

HOSTING_NS_PATTERNS = {
    "AWS":          ["awsdns","amazonaws"],
    "Google Cloud": ["google","googledomains","cloud.google"],
    "Azure":        ["azure-dns","azure.com","msft.net"],
    "Akamai":       ["akamai","akam.net"],
    "Fastly":       ["fastly"],
    "DigitalOcean": ["digitalocean"],
    "Linode":       ["linode"],
    "Hetzner":      ["hetzner"],
    "OVH":          ["ovh.net","ovh.ca"],
    "Vultr":        ["vultr.com"],
    "Bluehost":     ["bluehost"],
    "GoDaddy":      ["godaddy"],
    "SiteGround":   ["siteground"],
}

# ── Flagged Regions ──────────────────────────────────────────────────────────
FLAGGED_REGIONS = {
    "RU": ("Russia",         True),
    "CN": ("China",          True),
    "KP": ("North Korea",    True),
    "IR": ("Iran",           True),
    "NG": ("Nigeria",        True),
    "BY": ("Belarus",        True),
    "UA": ("Ukraine",        False),
    "US": ("United States",  False),
    "DE": ("Germany",        False),
    "GB": ("United Kingdom", False),
    "FR": ("France",         False),
    "NL": ("Netherlands",    False),
    "SG": ("Singapore",      False),
    "JP": ("Japan",          False),
    "IN": ("India",          False),
    "BR": ("Brazil",         False),
    "CA": ("Canada",         False),
    "AU": ("Australia",      False),
}

# ── Suspicious TLDs ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",
    ".loan",".work",".date",".racing",".win",".stream",
    ".download",".gdn",".cam",".kim",".link",
]

# ── Phishing Keywords ─────────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "login","verify","secure","account","update","confirm",
    "banking","paypal","apple","microsoft","amazon","support",
    "password","credential","suspended","unusual","activity",
    "alert","warning","reset","validation","auth",
]

# ── Enterprise / Trusted Registrars ──────────────────────────────────────────
ENTERPRISE_REGISTRARS = [
    "markmonitor","verisign","cscglobal","safenames",
    "networksolutions","register.com","gandi",
]
TRUSTED_REGISTRARS = [
    "markmonitor","verisign","cscglobal","safenames","godaddy",
    "namecheap","cloudflare","google domains","gandi","hover",
]

# ── Known-Legit Patterns ──────────────────────────────────────────────────────
KNOWN_LEGIT_PATTERNS = [
    "google","amazon","microsoft","apple","meta","facebook",
    "twitter","x.com","github","cloudflare","anthropic","claude",
    "openai","notion","figma","stripe","shopify","discord",
    "netflix","spotify","linkedin","adobe","salesforce",
    "zoom","slack","dropbox","canva","atlassian","hubspot",
]

# ── ASN Provider Map (for quick lookup) ──────────────────────────────────────
ASN_PROVIDER_MAP = {
    "Cloudflare":    CLOUDFLARE_RANGES,
    "AWS":           AWS_RANGES,
    "Google Cloud":  GCP_RANGES,
    "Azure":         AZURE_RANGES,
    "Akamai":        AKAMAI_RANGES,
    "Fastly":        FASTLY_RANGES,
    "DigitalOcean":  DIGITALOCEAN_RANGES,
    "Linode":        LINODE_RANGES,
    "Vultr":         VULTR_RANGES,
    "Hetzner":       HETZNER_RANGES,
    "OVH":           OVH_RANGES,
}

# ── Subdomains to probe for origin leaks ─────────────────────────────────────
ORIGIN_SUBDOMAINS = [
    "mail","ftp","api","dev","origin","direct",
    "smtp","vpn","cpanel","webmail","admin","mx",
    "remote","ns1","ns2","shop","m","staging",
]

# ── Simulated threat DB ───────────────────────────────────────────────────────
FAKE_THREAT_DB = {
    "malware": {"virustotal_flags": 8,  "blacklist_hits": 4,  "abuse_ch": True,  "otx_pulses": 3},
    "phish":   {"virustotal_flags": 12, "blacklist_hits": 7,  "abuse_ch": True,  "otx_pulses": 5},
    "spam":    {"virustotal_flags": 3,  "blacklist_hits": 2,  "abuse_ch": False, "otx_pulses": 1},
    "free":    {"virustotal_flags": 1,  "blacklist_hits": 0,  "abuse_ch": False, "otx_pulses": 0},
    "default": {"virustotal_flags": 0,  "blacklist_hits": 0,  "abuse_ch": False, "otx_pulses": 0},
}

# ── Popular Cloudflare enterprise customers ───────────────────────────────────
POPULAR_CF = [
    "discord","shopify","cloudflare","medium","doordash",
    "canva","notion","claude","anthropic",
]
