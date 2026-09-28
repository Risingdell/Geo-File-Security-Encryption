"""Capture the device's current location from the OS location service.

Windows: System.Device GeoCoordinateWatcher (GPS if present, else Wi-Fi/cell positioning).
Needs Settings > Privacy & security > Location turned on for desktop apps.
"""
import subprocess
import sys

from .container import Location

_PS_SCRIPT = r"""
Add-Type -AssemblyName System.Device
$w = New-Object System.Device.Location.GeoCoordinateWatcher([System.Device.Location.GeoPositionAccuracy]::High)
[void]$w.TryStart($false, [TimeSpan]::FromSeconds(%(timeout)d))
$deadline = (Get-Date).AddSeconds(%(timeout)d)
while ($w.Status -ne 'Ready' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
$c = $w.Position.Location
if ($w.Permission -ne 'Granted') { Write-Output "ERR permission=$($w.Permission)"; exit 2 }
if ($c.IsUnknown) { Write-Output "ERR status=$($w.Status)"; exit 3 }
Write-Output ("OK {0} {1} {2}" -f $c.Latitude.ToString([cultureinfo]::InvariantCulture),
    $c.Longitude.ToString([cultureinfo]::InvariantCulture),
    $c.HorizontalAccuracy.ToString([cultureinfo]::InvariantCulture))
$w.Stop()
"""


class LocationError(Exception):
    pass


def current_location(timeout_s: int = 20) -> Location:
    if sys.platform != "win32":
        raise LocationError("automatic location is only implemented on Windows; pass --lat/--lon/--accuracy")
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT % {"timeout": timeout_s}],
            capture_output=True, text=True, timeout=timeout_s + 20,
        ).stdout.strip().splitlines()
    except (OSError, subprocess.TimeoutExpired) as e:
        raise LocationError(f"location service unavailable: {e}") from None
    last = out[-1] if out else "ERR no output"
    if not last.startswith("OK "):
        raise LocationError(f"could not get a location fix ({last[4:]}). "
                            "Turn on Windows location services for desktop apps.")
    lat, lon, acc = (float(x) for x in last[3:].split())
    return Location(lat, lon, acc)
