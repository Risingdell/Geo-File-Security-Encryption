"""Access policy: who, where, when. Evaluated only by the LTA, never trusted from the client."""
import math
import os

from .util import b64e

EARTH_RADIUS_M = 6_371_008.8


class PolicyError(ValueError):
    pass


def circle_zone(lat: float, lon: float, radius_m: float) -> dict:
    return {"type": "circle", "lat": lat, "lon": lon, "radius_m": radius_m}


def polygon_zone(points: list[tuple[float, float]]) -> dict:
    return {"type": "polygon", "points": [[lat, lon] for lat, lon in points]}


def make_policy(*, recipient_sign_pk: str, zone: dict, not_before: int, not_after: int,
                max_accuracy_m: float = 25.0, beacon_pk: str | None = None,
                require_attestation: bool = False) -> dict:
    policy = {
        "v": 1,
        "id": b64e(os.urandom(12)),  # makes every policy (and so every file key) unique
        "recipient_sign_pk": recipient_sign_pk,
        "zone": zone,
        "not_before": int(not_before),
        "not_after": int(not_after),
        "max_accuracy_m": float(max_accuracy_m),
        "beacon_pk": beacon_pk,
        "require_attestation": bool(require_attestation),
    }
    validate_policy(policy)
    return policy


def validate_policy(p: dict) -> None:
    try:
        if p["v"] != 1:
            raise PolicyError("unsupported policy version")
        if not isinstance(p["recipient_sign_pk"], str):
            raise PolicyError("recipient_sign_pk missing")
        if p["not_after"] <= p["not_before"]:
            raise PolicyError("not_after must be later than not_before")
        if not 0 < p["max_accuracy_m"] <= 1000:
            raise PolicyError("max_accuracy_m must be in (0, 1000]")
        z = p["zone"]
        if z["type"] == "circle":
            _check_latlon(z["lat"], z["lon"])
            if not 1 <= z["radius_m"] <= 100_000:
                raise PolicyError("radius_m must be in [1, 100000]")
        elif z["type"] == "polygon":
            if len(z["points"]) < 3:
                raise PolicyError("polygon needs at least 3 points")
            for lat, lon in z["points"]:
                _check_latlon(lat, lon)
        else:
            raise PolicyError(f"unknown zone type {z['type']!r}")
    except (KeyError, TypeError, ValueError) as e:
        if isinstance(e, PolicyError):
            raise
        raise PolicyError(f"malformed policy: {e}") from None


def _check_latlon(lat: float, lon: float) -> None:
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise PolicyError("latitude/longitude out of range")


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(math.sqrt(a))


def _in_polygon(points: list[list[float]], lat: float, lon: float) -> bool:
    """Ray casting. Fine for site-sized polygons that don't cross the antimeridian."""
    inside = False
    n = len(points)
    for i in range(n):
        y1, x1 = points[i]
        y2, x2 = points[(i + 1) % n]
        if (y1 > lat) != (y2 > lat):
            x_cross = x1 + (lat - y1) * (x2 - x1) / (y2 - y1)
            if lon < x_cross:
                inside = not inside
    return inside


def in_zone(zone: dict, lat: float, lon: float) -> bool:
    if zone["type"] == "circle":
        return haversine_m(zone["lat"], zone["lon"], lat, lon) <= zone["radius_m"]
    return _in_polygon(zone["points"], lat, lon)


def describe_zone(zone: dict) -> str:
    if zone["type"] == "circle":
        return f"circle r={zone['radius_m']:g} m around ({zone['lat']:.6f}, {zone['lon']:.6f})"
    return f"polygon with {len(zone['points'])} vertices"
