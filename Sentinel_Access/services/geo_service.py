"""Geo/IP lookup service.

Uses ipinfo.io when a token is configured (or even token-less, on a best-effort
basis, since ipinfo allows a small number of free unauthenticated requests).
Falls back to deterministic mock geolocation data for private/local IPs or
whenever the real lookup fails, so the app runs fully offline for demos.
"""

import hashlib
import math

import requests

PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.", "::1", "0.")


MOCK_LOCATIONS = [
    {"city": "New York", "region": "NY", "country": "US", "lat": 40.7128, "lon": -74.0060},
    {"city": "London", "region": "", "country": "GB", "lat": 51.5074, "lon": -0.1278},
    {"city": "Mumbai", "region": "MH", "country": "IN", "lat": 19.0760, "lon": 72.8777},
    {"city": "Sydney", "region": "NSW", "country": "AU", "lat": -33.8688, "lon": 151.2093},
    {"city": "Sao Paulo", "region": "SP", "country": "BR", "lat": -23.5505, "lon": -46.6333},
    {"city": "Tokyo", "region": "", "country": "JP", "lat": 35.6762, "lon": 139.6503},
    {"city": "Cape Town", "region": "", "country": "ZA", "lat": -33.9249, "lon": 18.4241},
    {"city": "Toronto", "region": "ON", "country": "CA", "lat": 43.6532, "lon": -79.3832},
    {"city": "Berlin", "region": "", "country": "DE", "lat": 52.5200, "lon": 13.4050},
    {"city": "Singapore", "region": "", "country": "SG", "lat": 1.3521, "lon": 103.8198},
]


def _is_private_ip(ip):
    if not ip:
        return True
    for prefix in ("172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                    "172.28.", "172.29.", "172.30.", "172.31."):
        if ip.startswith(prefix):
            return True
    return ip == "localhost" or ip.startswith(PRIVATE_PREFIXES)


def _mock_location(ip):
    idx = int(hashlib.sha256((ip or "unknown").encode()).hexdigest(), 16) % len(MOCK_LOCATIONS)
    loc = dict(MOCK_LOCATIONS[idx])
    loc["label"] = f"{loc['city']}, {loc['country']}"
    loc["source"] = "mock"
    return loc


def get_location(ip, token=None):
    """Return {city, region, country, lat, lon, label, source} for an IP address."""
    if not _is_private_ip(ip):
        try:
            params = {"token": token} if token else {}
            resp = requests.get(f"https://ipinfo.io/{ip}/json", params=params, timeout=2)
            if resp.ok:
                data = resp.json()
                loc_str = data.get("loc")  # "lat,lon"
                if loc_str:
                    lat_s, lon_s = loc_str.split(",")
                    return {
                        "city": data.get("city", ""),
                        "region": data.get("region", ""),
                        "country": data.get("country", ""),
                        "lat": float(lat_s),
                        "lon": float(lon_s),
                        "label": f"{data.get('city', '?')}, {data.get('country', '?')}",
                        "source": "ipinfo",
                    }
        except (requests.RequestException, ValueError, KeyError):
            pass  # fall through to mock

    return _mock_location(ip)


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two lat/lon points, in kilometers."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))
