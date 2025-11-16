import numpy as np, pandas as pd
from geopy.distance import geodesic
import pytz

def to_local(ts_series, tz_name):
    tz = pytz.timezone(tz_name)
    s = pd.to_datetime(ts_series, utc=True, errors="coerce")
    return s.dt.tz_convert(tz)

def _parse_lat(v):
    if isinstance(v, dict): return v.get("lat")
    if isinstance(v, str) and "," in v:
        try: return float(v.split(",")[0].strip())
        except: return np.nan
    return np.nan

def _parse_lon(v):
    if isinstance(v, dict): return v.get("lon")
    if isinstance(v, str) and "," in v:
        try: return float(v.split(",")[1].strip())
        except: return np.nan
    return np.nan

def _dist_km(a_lat, a_lon, b_lat, b_lon):
    vals = (a_lat, a_lon, b_lat, b_lon)
    if any(v is None for v in vals): return np.nan
    try:
        if any(isinstance(v, float) and (np.isnan(v) or np.isinf(v)) for v in vals): return np.nan
        return geodesic((a_lat, a_lon), (b_lat, b_lon)).km
    except: return np.nan

def featurize(raw_docs, tz_name="Asia/Kolkata", work_start=8, work_end=20,
              dist_clip_km=10000, fail_window_events=200):
    df = pd.json_normalize(raw_docs)
    if df.empty: return df, df

    df["@ts"] = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
    df["ts_local"] = to_local(df["@ts"], tz_name)
    df["hour"] = df["ts_local"].dt.hour.astype("Int16").fillna(0).astype("int16")
    df["weekday"] = df["ts_local"].dt.weekday.astype("Int16").fillna(0).astype("int16")
    df["off_hours"] = ~(df["hour"].between(work_start, work_end))

    df["user"] = df.get("user.name").fillna("unknown")
    df["asn"] = df.get("source.as.number")
    df["country"] = df.get("source.geo.country_iso_code").fillna("UNK")

    loc = df.get("source.geo.location")
    df["lat"] = loc.apply(_parse_lat) if isinstance(loc, pd.Series) else np.nan
    df["lon"] = loc.apply(_parse_lon) if isinstance(loc, pd.Series) else np.nan

    df = df.sort_values("@ts").reset_index(drop=True)

    frames = []
    for user, g in df.groupby("user", sort=False):
        g = g.copy()
        ip_series = g.get("source.ip").fillna("UNK")
        counts, seen = [], {}
        for ip in ip_series:
            seen[ip] = seen.get(ip, 0) + 1
            counts.append(seen[ip])
        denom = np.maximum(1, np.arange(1, len(g)+1))
        g["ip_rarity"] = 1.0 - (np.array(counts) / denom)

        is_fail = (g.get("event.outcome") == "failure").astype(float).fillna(0.0)
        g["fail_ratio_7d"] = is_fail.rolling(int(fail_window_events), min_periods=5).mean().fillna(0.0)

        g["asn_changed"] = g["asn"].ne(g["asn"].shift(1)).fillna(False)
        g["country_changed"] = g["country"].ne(g["country"].shift(1)).fillna(False)
        plat = g["lat"].shift(1); plon = g["lon"].shift(1)
        g["distance_km"] = [
            _dist_km(a,b,c,d) for a,b,c,d in zip(g["lat"], g["lon"], plat, plon)
        ]
        g["distance_km"] = g["distance_km"].fillna(0.0).clip(0, dist_clip_km)
        frames.append(g)

    df = pd.concat(frames, ignore_index=True)

    df["off_hours"] = df["off_hours"].astype(int)
    df["asn_changed"] = df["asn_changed"].astype(int)
    df["country_changed"] = df["country_changed"].astype(int)
    df["ip_rarity"] = df["ip_rarity"].clip(0,1)

    feats = df[[
        "hour","weekday","off_hours","ip_rarity","fail_ratio_7d",
        "asn_changed","country_changed","distance_km"
    ]].astype(float)

    return df, feats
