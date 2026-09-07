import os
import logging
import geoip2.database
import ipaddress

logger = logging.getLogger(__name__)

# Paths to the MaxMind GeoLite2 databases
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "GeoLite2-Country.mmdb"
)
ASN_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "GeoLite2-ASN.mmdb"
)
# City edition adds lat/lon (Country only ever gave ISO code) — needed for
# anything that plots an attacker's location rather than just naming their
# country, e.g. the Threat Globe view.
CITY_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "GeoLite2-City.mmdb"
)


class GeoIPManager:
    def __init__(self):
        self.reader = None
        self.asn_reader = None
        self.city_reader = None
        self._load_db()

    def _load_db(self):
        # 1. Load Country DB
        if not os.path.exists(DB_PATH):
            logger.warning(
                f"GeoIP Country database not found at {DB_PATH}. Geolocation lookups will be disabled."
            )
        else:
            try:
                self.reader = geoip2.database.Reader(DB_PATH)
                logger.info("Successfully loaded MaxMind GeoLite2-Country database.")
            except Exception as e:
                logger.error(f"Failed to load GeoIP Country database: {e}")

        # 2. Load ASN DB
        if not os.path.exists(ASN_DB_PATH):
            logger.warning(
                f"GeoIP ASN database not found at {ASN_DB_PATH}. ASN lookups will be disabled."
            )
        else:
            try:
                self.asn_reader = geoip2.database.Reader(ASN_DB_PATH)
                logger.info("Successfully loaded MaxMind GeoLite2-ASN database.")
            except Exception as e:
                logger.error(f"Failed to load GeoIP ASN database: {e}")

        # 3. Load City DB (optional — features that don't need lat/lon keep
        # working fine without it; get_city_location() just returns None)
        if not os.path.exists(CITY_DB_PATH):
            logger.warning(
                f"GeoIP City database not found at {CITY_DB_PATH}. Lat/lon lookups will be disabled."
            )
        else:
            try:
                self.city_reader = geoip2.database.Reader(CITY_DB_PATH)
                logger.info("Successfully loaded MaxMind GeoLite2-City database.")
            except Exception as e:
                logger.error(f"Failed to load GeoIP City database: {e}")

    def get_country_code(self, ip_address: str) -> str:
        """
        Returns the ISO 3166-1 alpha-2 country code (e.g., 'US', 'CN', 'BR') for the given IP.
        Returns empty string if lookup fails or DB is unavailable.
        """
        if not ip_address:
            return ""

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return "Internal"
        except ValueError:
            pass

        if not self.reader:
            return ""

        try:
            response = self.reader.country(ip_address)
            return response.country.iso_code or ""
        except geoip2.errors.AddressNotFoundError:
            return ""
        except Exception as e:
            logger.debug(f"GeoIP country lookup failed for {ip_address}: {e}")
            return ""

    def get_asn_org(self, ip_address: str) -> str:
        """
        Returns the ASN and ISP/Organization name for the given IP.
        Returns 'Internal' for private/loopback, 'Unknown (ASN DB Missing)' if DB not loaded,
        or 'Unknown' if not found.
        """
        if not ip_address:
            return ""

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return "Internal"
        except ValueError:
            pass

        if not self.asn_reader:
            return "Unknown (ASN DB Missing)"

        try:
            response = self.asn_reader.asn(ip_address)
            asn_num = response.autonomous_system_number
            asn_org = response.autonomous_system_organization
            if asn_num and asn_org:
                return f"AS{asn_num} {asn_org}"
            elif asn_num:
                return f"AS{asn_num}"
            return "Unknown"
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            logger.debug(f"GeoIP ASN lookup failed for {ip_address}: {e}")
            return "Unknown"

    def get_city_location(self, ip_address: str) -> dict:
        """
        Returns {"lat": float, "lon": float, "city": str} for the given IP,
        or None if the address is private/loopback, the City DB isn't
        loaded, or MaxMind has no record for it (common for IPs it can
        only place at a country-level accuracy). Deliberately returns None
        rather than a fabricated fallback point (e.g. a country centroid)
        — a caller that needs a real point on a map should skip the event
        rather than plot an attacker somewhere they weren't.
        """
        if not ip_address:
            return None

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return None
        except ValueError:
            return None

        if not self.city_reader:
            return None

        try:
            response = self.city_reader.city(ip_address)
            lat = response.location.latitude
            lon = response.location.longitude
            if lat is None or lon is None:
                return None
            return {"lat": lat, "lon": lon, "city": response.city.name or ""}
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            logger.debug(f"GeoIP City lookup failed for {ip_address}: {e}")
            return None

    def __del__(self):
        if self.reader:
            try:
                self.reader.close()
            except Exception:
                pass
        if self.asn_reader:
            try:
                self.asn_reader.close()
            except Exception:
                pass
        if self.city_reader:
            try:
                self.city_reader.close()
            except Exception:
                pass


# Singleton instance
geoip_manager = GeoIPManager()
