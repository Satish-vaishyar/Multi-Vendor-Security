"""Run all OKF scrapers and report coverage."""
from .nist_oscal_scraper import scrape as nist
from .cis_scraper import scrape as cis
from .stig_scraper import scrape as stig
from .iso_scraper import scrape as iso

def run_all() -> dict:
    return {"NIST_OSCAL": nist(), "CIS": cis(), "STIG": stig(), "ISO27001": iso()}

if __name__ == "__main__":
    import json
    print(json.dumps(run_all(), indent=2))
